use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use log::{error, info, warn, debug};
use prost::Message;

// Import your custom fabric client structures and protobuf definitions
use dzta::fabric_client::FabricClient;
use dzta::config::UserContext;
use fabric_sdk::identity::IdentityBuilder;

// Generated Fabric Gateway Protobuf Types
use fabric_sdk::fabric::gateway::{
    ChaincodeEventsRequest, 
    SignedChaincodeEventsRequest, 
    ChaincodeEventsResponse
};

/// Payload structure emitted by the Layer 1a "RevokeCredential" smart contract action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEventPayload {
    pub credential_id: String,
    pub revoked_at: i64,
    pub reason: String,
}

pub struct FabricRevocationListener {
    fabric_client: FabricClient,
    user_context: UserContext,
    revocation_cache: Arc<RwLock<HashSet<String>>>,
    envoy_admin_url: String,
}

impl FabricRevocationListener {
    pub fn new(
        fabric_client: FabricClient,
        user_context: UserContext,
        revocation_cache: Arc<RwLock<HashSet<String>>>,
        envoy_admin_url: String,
    ) -> Self {
        Self {
            fabric_client,
            user_context,
            revocation_cache,
            envoy_admin_url,
        }
    }

    /// Execution loop: Seeds initial status, then listens for live chaincode events.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("[Layer 4 Daemon] Initializing Fabric Gateway Chaincode Event Listener...");

        let mut retry_backoff = Duration::from_secs(1);
        loop {
            info!("[Layer 4 Daemon] Connecting to Fabric Gateway streaming endpoint...");

            match self.stream_chaincode_events().await {
                Ok(_) => {
                    info!("[Layer 4 Daemon] Event stream ended gracefully. Reconnecting...");
                    retry_backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    error!(
                        "[Layer 4 Daemon] Chaincode event stream error: {:?}. Retrying in {}s...",
                        e,
                        retry_backoff.as_secs()
                    );
                    tokio::time::sleep(retry_backoff).await;
                    retry_backoff = std::cmp::min(retry_backoff * 2, Duration::from_secs(30));
                }
            }
        }
    }

    /// Establishes the gRPC server-streaming connection via `GatewayClient::chaincode_events`.
    async fn stream_chaincode_events(&self) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Build TLS Gateway Client
        let mut gateway_client = self
            .fabric_client
            .build_tls_gateway_client(&self.user_context)
            .await?;

        // 2. Prepare SDK Identity to sign the gRPC request
        let cert_pem = self.user_context.get_cert_pem();
        let private_key_pem = self.user_context.get_key_pem();

        let loaded_cert = if cert_pem.contains("-----BEGIN CERTIFICATE-----") {
            cert_pem.as_bytes().to_vec()
        } else {
            std::fs::read(cert_pem)?
        };

        let loaded_key = if private_key_pem.contains("-----BEGIN PRIVATE KEY-----") {
            private_key_pem.to_string()
        } else {
            std::fs::read_to_string(private_key_pem)?
        };

        let sdk_identity = IdentityBuilder::from_pem(&loaded_cert)?
            .with_msp(self.fabric_client.get_org_mspid())?
            .with_private_key(loaded_key)?
            .build()?;

        // 3. Assemble the raw ChaincodeEventsRequest payload
        let raw_request = ChaincodeEventsRequest {
            channel_id: self.fabric_client.get_channel_name().to_string(),
            chaincode_id: self.fabric_client.get_chaincode_name().to_string(),
            identity: loaded_cert.clone(), // Standardized identity bytes
            start_position: None, // Seek from current head block
            after_transaction_id: String::new(),
        };

        // Serialize request to binary bytes for signing
        let mut request_bytes = Vec::new();
        raw_request.encode(&mut request_bytes)?;

        // Sign request payload with identity private key
        let signature = sdk_identity.sign_message(&request_bytes);

        // Package into the final gRPC envelope expected by `chaincode_events`
        let signed_request = SignedChaincodeEventsRequest {
            request: request_bytes,
            signature,
        };

        // 4. Open gRPC Server-Streaming Pipe
        let mut response_stream = gateway_client
            .chaincode_events(signed_request)
            .await?
            .into_inner();

        info!("[Layer 4 Daemon] Subscribed to ChaincodeEvents stream for channel '{}' and chaincode '{}'", 
            self.fabric_client.get_channel_name(),
            self.fabric_client.get_chaincode_name()
        );

        // 5. Stream processing loop
        while let Some(events_response) = response_stream.message().await? {
            self.process_chaincode_events_response(events_response).await;
        }

        Ok(())
    }

    /// Handles a single `ChaincodeEventsResponse` emitted for a committed block.
    async fn process_chaincode_events_response(&self, response: ChaincodeEventsResponse) {
        let block_num = response.block_number;

        for cc_event in response.events {
            debug!(
                "[Layer 4 Daemon] Event received [Block #{} | TxID: {} | Event: {}]",
                block_num, cc_event.tx_id, cc_event.event_name
            );

            // Filter for Revocation Events
            if cc_event.event_name == "RevokeCredential" || cc_event.event_name == "CredentialRevoked" {
                if let Ok(payload) = serde_json::from_slice::<RevocationEventPayload>(&cc_event.payload) {
                    info!(
                        "[Layer 4 Daemon]  REVOCATION EVENT DETECTED in Block #{}: Credential ID = {}",
                        block_num, payload.credential_id
                    );

                    // A. Lock and update internal thread-safe cache
                    let mut cache = self.revocation_cache.write().await;
                    cache.insert(payload.credential_id.clone());

                    // B. Inject update into local Envoy Proxy shared runtime memory
                    self.sync_to_envoy_memory(&payload.credential_id).await;
                } else if let Ok(cred_id_str) = String::from_utf8(cc_event.payload.clone()) {
                    // Fallback if payload is plain raw credential_id string
                    info!(
                        "[Layer 4 Daemon]  REVOCATION EVENT DETECTED (Plain String) in Block #{}: Credential ID = {}",
                        block_num, cred_id_str
                    );

                    let mut cache = self.revocation_cache.write().await;
                    cache.insert(cred_id_str.clone());

                    self.sync_to_envoy_memory(&cred_id_str).await;
                }
            }
        }
    }

    /// Pushes the revoked ID to Envoy's local runtime admin memory endpoint.
    async fn sync_to_envoy_memory(&self, credential_id: &str) {
        let url = format!(
            "{}/runtime_modify?key=revoked.{}&val=true",
            self.envoy_admin_url, credential_id
        );

        let client = reqwest::Client::new();
        match client.post(&url).timeout(Duration::from_millis(200)).send().await {
            Ok(res) if res.status().is_success() => {
                info!(
                    "[Layer 4 Daemon] Successfully injected revocation [{}] into Envoy Wasm runtime cache.",
                    credential_id
                );
            }
            Ok(res) => {
                warn!(
                    "[Layer 4 Daemon] Envoy runtime update request returned HTTP status: {}",
                    res.status()
                );
            }
            Err(e) => {
                error!(
                    "[Layer 4 Daemon] Failed to reach Envoy Admin API at {}: {:?}",
                    url, e
                );
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Starting dZTA Layer 4 Fabric Revocation Sync Daemon...");

    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config/connection-profile.yaml".to_string());
    let channel_name = std::env::var("FABRIC_CHANNEL").unwrap_or_else(|_| "dzta".to_string());
    let chaincode_name = std::env::var("FABRIC_CHAINCODE").unwrap_or_else(|_| "dztac".to_string());
    let org_name = std::env::var("FABRIC_ORG").unwrap_or_else(|_| "Org1MSP".to_string());
    let peer_name = std::env::var("FABRIC_PEER").unwrap_or_else(|_| "org1-peer1".to_string());
    let envoy_admin_url = std::env::var("ENVOY_ADMIN_URL").unwrap_or_else(|_| "http://127.0.0.1:9901".to_string());

    let fabric_client = FabricClient::new(
        &config_path,
        &channel_name,
        &chaincode_name,
        &org_name,
        &peer_name,
    )
    .await?;

    let user_context = {
        let config_guard = fabric_client.config.read().await;
        config_guard.get_user_context().map_err(|e| {
            format!("Failed to load user context from config: {:?}", e)
        })?
    };

    let revocation_cache = Arc::new(RwLock::new(HashSet::new()));

    let listener = FabricRevocationListener::new(
        fabric_client,
        user_context,
        revocation_cache,
        envoy_admin_url,
    );

    listener.run().await?;

    Ok(())
}