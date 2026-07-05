async fn store_credential_in_askar(
        &self,
        credential_id: &str,
        credential_data: &Value,
    ) -> WalletResult<()> {
        debug!("Storing credential in Askar: {}", credential_id);

        let store_lock = self.askar_store.read().await;
        let store = store_lock.as_ref()
            .ok_or_else(|| WalletError::StorageError("Askar store not initialized".to_string()))?;

        let credential_json = credential_data.to_string();

        let mut session = store.session(None)
            .await
            .map_err(|e| {
                error!("Failed to create Askar session: {:?}", e);
                WalletError::StorageError(format!("Session creation failed: {}", e))
            })?;

        // Use the mutable session reference directly to insert
        session.insert(
            "credentials",  
            credential_id,  
            credential_json.as_bytes(), // Converted to byte slice
            Some(&json!({
                "stored_at": chrono::Utc::now().to_rfc3339(),
                "revoked": false
            }).to_string()),  
            None,
        )
        .await
        .map_err(|e| {
            error!("Failed to store credential in Askar: {:?}", e);
            WalletError::StorageError(format!("Credential storage failed: {}", e))
        })?;

        debug!("Credential stored successfully in Askar: {}", credential_id);
        Ok(())
    }

    async fn retrieve_credential_from_askar(
        &self,
        credential_id: &str,
    ) -> WalletResult<Value> {
        debug!("Retrieving credential from Askar: {}", credential_id);

        let store_lock = self.askar_store.read().await;
        let store = store_lock.as_ref()
            .ok_or_else(|| WalletError::StorageError("Askar store not initialized".to_string()))?;

        let mut session = store.session(None)
            .await
            .map_err(|e| {
                error!("Failed to create Askar session: {:?}", e);
                WalletError::StorageError(format!("Session creation failed: {}", e))
            })?;

        let entry = session.fetch(
            "credentials",  
            credential_id,  
            false,  
        )
        .await
        .map_err(|e| {
            error!("Failed to retrieve credential from Askar: {:?}", e);
            WalletError::StorageError(format!("Credential retrieval failed: {}", e))
        })?
        .ok_or_else(|| {
            error!("Credential not found in Askar: {}", credential_id);
            WalletError::StorageError(format!("Credential not found: {}", credential_id))
        })?;

        // entry.as_ref() gives access to the underlying slice
        let credential_data: Value = serde_json::from_slice(entry.as_ref())
            .map_err(|e| {
                error!("Failed to deserialize credential: {:?}", e);
                WalletError::StorageError(format!("Credential deserialization failed: {}", e))
            })?;

        debug!("Credential retrieved successfully from Askar: {}", credential_id);
        Ok(credential_data)
    }

    async fn mark_credential_revoked_in_askar(
        &self,
        credential_id: &str,
    ) -> WalletResult<()> {
        debug!("Marking credential as revoked in Askar: {}", credential_id);

        let store_lock = self.askar_store.read().await;
        let store = store_lock.as_ref()
            .ok_or_else(|| WalletError::StorageError("Askar store not initialized".to_string()))?;

        let mut session = store.session(None)
            .await
            .map_err(|e| {
                error!("Failed to create Askar session: {:?}", e);
                WalletError::StorageError(format!("Session creation failed: {}", e))
            })?;

        let entry = session.fetch(
            "credentials",
            credential_id,
            false,
        )
        .await
        .map_err(|e| {
            error!("Failed to fetch credential for revocation: {:?}", e);
            WalletError::StorageError(format!("Fetch failed: {}", e))
        })?
        .ok_or_else(|| {
            error!("Credential not found for revocation: {}", credential_id);
            WalletError::StorageError(format!("Credential not found: {}", credential_id))
        })?;

        let updated_metadata = json!({
            "revoked": true,
            "revoked_at": chrono::Utc::now().to_rfc3339()
        }).to_string();

        // Use session.replace here instead of insert because the key already exists
        session.replace(
            "credentials",
            credential_id,
            entry.as_ref(), // Keep original payload bytes
            Some(&updated_metadata),
            None,
        )
        .await
        .map_err(|e| {
            error!("Failed to update revocation status in Askar: {:?}", e);
            WalletError::StorageError(format!("Revocation update failed: {}", e))
        })?;

        debug!("Credential marked as revoked in Askar: {}", credential_id);
        Ok(())
    }


use aries_askar::EntryTag;

        // Convert your tags into the format Askar expects
        let tags = vec![
            EntryTag::Plain("stored_at".to_string(), chrono::Utc::now().to_rfc3339()),
            EntryTag::Plain("revoked".to_string(), "false".to_string()),
        ];

        // Store the credential with metadata
        session.insert(
            "credentials",  // category
            credential_id,  // name/key
            credential_json.as_bytes(),  // value
            Some(&tags),    // fixed: passing &[EntryTag]
            None,           // no expiry
        )

/// Initialize the Askar store (must be called before credential operations)
    pub async fn initialize_askar_store(
        &self,
        pass_key: &str,
    ) -> WalletResult<()> {
        info!("Initializing Askar store at: {}", self.askar_store_path);

        // Standard Askar Store::open parameters:
        // 1. db_url: &str
        // 2. key_method: Option<StoreKeyMethod>
        // 3. pass_key: PassKey<'_>
        // 4. profile: Option<String>
        let store = Store::open(
            &format!("sqlite://{}", self.askar_store_path),
            Some(StoreKeyMethod::DeriveKey(Default::default())), // Use Argon2i KDF
            pass_key.to_string().into(),                        // Construct PassKey using From<String>
            None,                                                // Default Profile
        )
        .await
        .map_err(|e| {
            error!("Failed to open Askar store: {:?}", e);
            WalletError::StorageError(format!("Askar store initialization failed: {}", e))
        })?;

        let mut store_lock = self.askar_store.write().await;
        *store_lock = Some(store);

        info!("Askar store initialized successfully");
        Ok(())
    }

// Re-store with updated tags
        session.replace(
            "credentials",
            credential_id,
            &entry.value,  
            Some(&updated_tags),
            None,
        )
        .await
        .map_err(|e| {
            error!("Failed to update revocation status in Askar: {:?}", e);
            WalletError::StorageError(format!("Revocation update failed: {}", e))
        })?;

        // Add this back to finalize the atomic transaction!
        session.commit()
            .await
            .map_err(|e| {
                error!("Failed to commit revocation session: {:?}", e);
                WalletError::StorageError(format!("Session commit failed: {}", e))
            })?;

        debug!("Credential marked as revoked in Askar: {}", credential_id);
        Ok(())

// src/fabric_client.rs
use crate::errors::{WalletError, WalletResult};
use crate::config::ConnectionConfig;
use crate::models::*;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, debug, error};

pub struct FabricClient {
    config: Option<Arc<RwLock<ConnectionConfig>>>,
    channel_name: String,
    chaincode_name: String,
    org_mspid: String,
    peer_url: String,
    is_mock: bool,
}

impl FabricClient {
    /// Initialize Fabric client using a connection profile configuration
    pub async fn new(
        config_path: &str,
        channel_name: &str,
        chaincode_name: &str,
        org_name: &str,
        peer_name: &str,
    ) -> WalletResult<Self> {
        let config = ConnectionConfig::from_file(config_path)?;
        let org_mspid = config.get_org_mspid(org_name)?;
        let peer_url = config.get_peer_url(peer_name)?;

        info!("Initialized Fabric client: {} on {}", chaincode_name, peer_url);

        Ok(FabricClient {
            config: Some(Arc::new(RwLock::new(config))),
            channel_name: channel_name.to_string(),
            chaincode_name: chaincode_name.to_string(),
            org_mspid,
            peer_url,
            is_mock: false,
        })
    }

    /// Explicitly initialize a Mock Fabric Client for testing cycles
    pub fn new_mock() -> Self {
        FabricClient {
            config: None,
            channel_name: "test-channel".to_string(),
            chaincode_name: "test-chaincode".to_string(),
            org_mspid: "TestMSP".to_string(),
            peer_url: "localhost:7051".to_string(),
            is_mock: true,
        }
    }

    /// Register DID on Fabric ledger
    pub async fn register_did(
        &self,
        did: &str,
        issuer_did: &str,
        public_key: &str,
    ) -> WalletResult<String> {
        let invocation = ChaincodeInvocation {
            function: "RegisterDID".to_string(),
            args: vec![
                did.to_string(),
                issuer_did.to_string(),
                public_key.to_string(),
            ],
        };

        self.invoke_chaincode(&invocation).await
    }

    /// Resolve DID from Fabric ledger
    pub async fn resolve_did(&self, did: &str) -> WalletResult<DIDDocument> {
        let invocation = ChaincodeInvocation {
            function: "ResolveDID".to_string(),
            args: vec![did.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let did_doc: DIDDocument = serde_json::from_slice(&response)
            .map_err(|e| WalletError::SerializationError(e))?;

        Ok(did_doc)
    }

    /// Record credential metadata on Fabric ledger
    pub async fn record_credential_metadata(
        &self,
        credential_id: &str,
        schema_id: &str,
        issuer_did: &str,
        subject_did: &str,
        expires_at: i64,
    ) -> WalletResult<String> {
        let invocation = ChaincodeInvocation {
            function: "RecordCredentialMetadata".to_string(),
            args: vec![
                credential_id.to_string(),
                schema_id.to_string(),
                issuer_did.to_string(),
                subject_did.to_string(),
                expires_at.to_string(),
            ],
        };

        self.invoke_chaincode(&invocation).await
    }

    /// Get credential metadata from Fabric ledger
    pub async fn get_credential_metadata(
        &self,
        credential_id: &str,
    ) -> WalletResult<CredentialMetadata> {
        let invocation = ChaincodeInvocation {
            function: "GetCredentialMetadata".to_string(),
            args: vec![credential_id.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let metadata: CredentialMetadata = serde_json::from_slice(&response)
            .map_err(|e| WalletError::SerializationError(e))?;

        Ok(metadata)
    }

    /// Check if credential is revoked on Fabric ledger
    pub async fn is_credential_revoked(&self, credential_id: &str) -> WalletResult<bool> {
        let invocation = ChaincodeInvocation {
            function: "IsCredentialRevoked".to_string(),
            args: vec![credential_id.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let revoked: bool = serde_json::from_slice(&response)
            .map_err(|e| WalletError::SerializationError(e))?;

        Ok(revoked)
    }

    /// Revoke credential on Fabric ledger
    pub async fn revoke_credential(&self, credential_id: &str) -> WalletResult<String> {
        let invocation = ChaincodeInvocation {
            function: "RevokeCredential".to_string(),
            args: vec![credential_id.to_string()],
        };

        self.invoke_chaincode(&invocation).await
    }

    /// Register credential schema on Fabric ledger
    pub async fn register_schema(
        &self,
        schema_id: &str,
        issuer_did: &str,
        name: &str,
        version: &str,
        attributes: &[SchemaAttribute],
    ) -> WalletResult<String> {
        let attributes_json = serde_json::to_string(attributes)
            .map_err(|e| WalletError::SerializationError(e))?;

        let invocation = ChaincodeInvocation {
            function: "RegisterSchema".to_string(),
            args: vec![
                schema_id.to_string(),
                issuer_did.to_string(),
                name.to_string(),
                version.to_string(),
                attributes_json,
            ],
        };

        self.invoke_chaincode(&invocation).await
    }

    /// Get credential schema from Fabric ledger
    pub async fn get_schema(&self, schema_id: &str) -> WalletResult<CredentialSchema> {
        let invocation = ChaincodeInvocation {
            function: "GetSchema".to_string(),
            args: vec![schema_id.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let schema: CredentialSchema = serde_json::from_slice(&response)
            .map_err(|e| WalletError::SerializationError(e))?;

        Ok(schema)
    }

    /// Query DIDs by issuer
    pub async fn query_dids_by_issuer(
        &self,
        issuer_did: &str,
    ) -> WalletResult<Vec<DIDDocument>> {
        let invocation = ChaincodeInvocation {
            function: "QueryDIDsByIssuer".to_string(),
            args: vec![issuer_did.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let dids: Vec<DIDDocument> = serde_json::from_slice(&response)
            .map_err(|e| WalletError::SerializationError(e))?;

        Ok(dids)
    }

    /// Invoke chaincode (write/modify ledger state)
    async fn invoke_chaincode(&self, invocation: &ChaincodeInvocation) -> WalletResult<String> {
        debug!(
            "Invoking chaincode function: {} with args: {:?}",
            invocation.function, invocation.args
        );

        if self.is_mock {
            info!("Mock Chaincode invocation submitted: {}", invocation.function);
            return Ok(format!("Mock Transaction submitted: {}", invocation.function));
        }

        // TODO: Production integration hooks:
        // 1. Get identity certificate/private key reference from self.config
        // 2. Build gRPC Proposal via fabric_sdk_rs
        // 3. Request endorsements, aggregate responses, and forward payload to orderer
        
        info!("Chaincode invocation submitted: {}", invocation.function);
        Ok(format!("Transaction submitted: {}", invocation.function))
    }

    /// Query chaincode (read ledger state - no consensus required)
    async fn query_chaincode(&self, invocation: &ChaincodeInvocation) -> WalletResult<Vec<u8>> {
        debug!(
            "Querying chaincode function: {} with args: {:?}",
            invocation.function, invocation.args
        );

        if self.is_mock {
            info!("Mock Chaincode query executed: {}", invocation.function);
            
            // Build meaningful structural mock JSON payloads so serialization doesn't crash tests
            let mock_json = match invocation.function.as_str() {
                "GetCredentialMetadata" => {
                    let cred_id = invocation.args.first().cloned().unwrap_or_default();
                    json!({
                        "credential_id": cred_id,
                        "schema_id": "mock-schema-id",
                        "issuer_did": "did:example:issuer",
                        "subject_did": "did:example:subject",
                        "issued_at": chrono::Utc::now().timestamp(),
                        "expires_at": chrono::Utc::now().timestamp() + 3600
                    })
                },
                "IsCredentialRevoked" => json!(false),
                "GetSchema" => {
                    let schema_id = invocation.args.first().cloned().unwrap_or_default();
                    json!({
                        "schema_id": schema_id,
                        "issuer_did": "did:example:issuer",
                        "name": "TestSchema",
                        "version": "1.0.0",
                        "attributes": []
                    })
                },
                "ResolveDID" => json!({
                    "id": invocation.args.first().cloned().unwrap_or_default(),
                    "public_key": "placeholder_pubkey",
                    "authentication": ["key-1"]
                }),
                _ => json!({})
            };

            return serde_json::to_vec(&mock_json)
                .map_err(|e| WalletError::SerializationError(e));
        }

        // TODO: Connect fabric_sdk_rs query engine to evaluation endpoint
        Ok(serde_json::to_vec(&json!({})).unwrap())
    }

    // Accessors
    pub fn get_channel_name(&self) -> &str { &self.channel_name }
    pub fn get_chaincode_name(&self) -> &str { &self.chaincode_name }
    pub fn get_org_mspid(&self) -> &str { &self.org_mspid }
    pub fn get_peer_url(&self) -> &str { &self.peer_url }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_query_mechanisms() {
        let client = FabricClient::new_mock();
        let status = client.is_credential_revoked("test-id").await.unwrap();
        assert!(!status);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStoreConfig {
    pub path: String,
    // Change this from Option<String> to Option<CryptoStoreConfig>
    #[serde(rename = "cryptoStore")]
    pub crypto_store: Option<CryptoStoreConfig>,
}

// Add this new struct to map the nested path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoStoreConfig {
    pub path: String,
}

// --- Step 1: Register Credential Schema ---
    // ... your existing code ...

    // --- Step 1.5: Unlock the Secure Askar Vault ---
    info!("Unlocking Askar secure store...");
    let pass_key = "your_secret_passphrase_here"; // In production, load this from an env var or vault
    credential_manager.initialize_askar_store(pass_key).await?;
    info!("✓ Askar secure store unlocked");

    // --- Step 2: Create Credential ---
    // Now you can call create_credential safely!