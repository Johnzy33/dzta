//dzta-attestation-broker/src/lib.rs

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{ Client};
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2_10::Sha256 as RsaSha256;

use std::{time::Duration};

use shared::vault_client::build_vault_client;
use shared::{BrokerError, BrokerResult, VaultSeed, VaultDecryptor, VaultEncryptor};

use zeroize::{ Zeroizing};


pub mod routes;

// Re-export core route utilities for integration tests and main binaries
pub use routes::{
    create_router,
    datakey::{
        ProvisionDatakeyRequest, UnwrapDatakeyRequest, UnwrapDatakeyResponse,
    },
    AppState, ErrorResponse,
};


/// Secrets are returned encrypted to the enclave public key. Providers must
/// never return plaintext wallet keys to the host process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedEnclaveSecrets {
    pub encrypted_wallet_key: String,
    pub encrypted_master_seed: String,
    pub key_encryption_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedEnclave {
    pub quote: Vec<u8>,
    pub report_data: Vec<u8>,
    pub enclave_public_key: String,
    pub mrenclave: String,
    pub mrsigner: String,
}

#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn release_for_verified_enclave(
        &self,
        enclave: &VerifiedEnclave,
        credential_key_id: &str,
        wallet_ciphertext: &str,
        seed_ciphertext: &str,
    ) -> Result<WrappedEnclaveSecrets, BrokerError>;
}

/// HashiCorp Vault Transit adapter. Transit unwraps a server-side encrypted
/// secret envelope; the returned value must be re-wrapped to the enclave key
/// by the broker before it crosses the broker boundary.
pub struct VaultTransitProvider {
    client: Client,
    address: String,
    token: String,
    transit_key: String,
}

impl VaultTransitProvider {

   pub fn new(
        address: impl Into<String>,
        token: impl Into<String>,
        transit_key: impl Into<String>,
    ) -> Result<Self, BrokerError> {
        let client = build_vault_client()?;

        Ok(Self {
            client,
            address: address.into().trim_end_matches('/').to_string(),
            token: token.into(),
            transit_key: transit_key.into(),
        })
    }

    async fn decrypt_envelope(&self, ciphertext: &str) -> Result<Vec<u8>, BrokerError> {
        let url = format!("{}/v1/transit/decrypt/{}", self.address, self.transit_key);
        let response = self
            .client
            .post(url)
            .header("X-Vault-Token", &self.token)
            .json(&serde_json::json!({ "ciphertext": ciphertext }))
            .send()
            .await?;
        let status = response.status();
        let body: VaultDecryptResponse = response.json().await.map_err(BrokerError::Request)?;
        if !status.is_success() {
            return Err(BrokerError::Provider {
                status,
                body: body.errors.join(", "),
            });
        }
        let plaintext = body
            .data
            .plaintext
            .ok_or_else(|| BrokerError::Response("Vault returned no plaintext".to_string()))?;
        BASE64
            .decode(plaintext)
            .map_err(|e| BrokerError::Response(format!("invalid Vault plaintext: {e}")))
    }
}

#[derive(Debug, Deserialize)]
struct VaultDecryptResponse {
    #[serde(default)]
    data: VaultDecryptData,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultDecryptData {
    plaintext: Option<String>,
}

/// The broker decrypts Vault Transit ciphertexts per request.
/// `release_for_verified_enclave` is deliberately left as the broker's boundary method:
/// it uses an enclave-held public key encryption implementation, never sending
/// `wallet_key` or `master_seed` to the client in plaintext.
pub struct VaultSecretRelease {
    pub provider: VaultTransitProvider,
}

#[async_trait]
impl SecretProvider for VaultSecretRelease {
    async fn release_for_verified_enclave(
        &self,
        enclave: &VerifiedEnclave,
        credential_key_id: &str,
        wallet_ciphertext: &str,
        seed_ciphertext: &str,
    ) -> Result<WrappedEnclaveSecrets, BrokerError> {
        if enclave.quote.is_empty()
            || enclave.report_data.is_empty()
            || enclave.enclave_public_key.is_empty()
        {
            return Err(BrokerError::Configuration(
                "verified enclave identity is incomplete".to_string(),
            ));
        }

        let wallet_key = self.provider.decrypt_envelope(wallet_ciphertext).await?;
        let master_seed = self.provider.decrypt_envelope(seed_ciphertext).await?;

        let public_key = RsaPublicKey::from_public_key_pem(&enclave.enclave_public_key)
            .map_err(|e| BrokerError::Response(format!("invalid enclave public key: {e}")))?;

        let mut rng = rand::thread_rng();
        let encrypted_wallet_key = public_key
            .encrypt(&mut rng, Oaep::new::<RsaSha256>(), &wallet_key)
            .map_err(|e| BrokerError::Response(format!("failed to wrap wallet key: {e}")))?;
        let encrypted_master_seed = public_key
            .encrypt(&mut rng, Oaep::new::<RsaSha256>(), &master_seed)
            .map_err(|e| BrokerError::Response(format!("failed to wrap master seed: {e}")))?;

        Ok(WrappedEnclaveSecrets {
            encrypted_wallet_key: BASE64.encode(encrypted_wallet_key),
            encrypted_master_seed: BASE64.encode(encrypted_master_seed),
            key_encryption_algorithm: format!("RSA-OAEP-SHA256:{credential_key_id}"),
        })
    }
}

/// Generic HTTPS KMS adapter. The endpoint is expected to verify the DCAP
/// result or trust the broker's verified request, then return secrets already
/// encrypted to `enclave_public_key`.
pub struct HttpsKmsProvider {
    client: Client,
    endpoint: String,
    bearer_token: Option<String>,
}

impl HttpsKmsProvider {
    pub fn new(
        endpoint: impl Into<String>,
        bearer_token: Option<String>,
    ) -> Result<Self, BrokerError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(BrokerError::Request)?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
            bearer_token,
        })
    }
}

#[derive(Serialize)]
struct KmsReleaseRequest<'a> {
    quote: &'a [u8],
    report_data: &'a [u8],
    enclave_public_key: &'a str,
    mrenclave: &'a str,
    mrsigner: &'a str,
    credential_key_id: &'a str,
    wallet_ciphertext: &'a str,
    seed_ciphertext: &'a str,
}

#[async_trait]
impl SecretProvider for HttpsKmsProvider {
    async fn release_for_verified_enclave(
        &self,
        enclave: &VerifiedEnclave,
        credential_key_id: &str,
        wallet_ciphertext: &str,
        seed_ciphertext: &str,
    ) -> Result<WrappedEnclaveSecrets, BrokerError> {
        let mut request = self.client.post(&self.endpoint).json(&KmsReleaseRequest {
            quote: &enclave.quote,
            report_data: &enclave.report_data,
            enclave_public_key: &enclave.enclave_public_key,
            mrenclave: &enclave.mrenclave,
            mrsigner: &enclave.mrsigner,
            credential_key_id,
            wallet_ciphertext,
            seed_ciphertext,
        });
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(BrokerError::Provider {
                status,
                body: response.text().await?,
            });
        }
        response.json().await.map_err(BrokerError::Request)
    }
}

// ----------------------------------------------------------------------------
// OPTION A: Vault Datakey Engine Implementation
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningDataKeyResponse {
    /// Ciphertext for the wallet DEK saved to user's local disk
    pub wallet_ciphertext: String,
    /// Wallet DEK wrapped for the enclave public key
    pub encrypted_wallet_key_for_enclave: String,
    /// Ciphertext for the ZKP master seed saved to user's local disk
    pub seed_ciphertext: String,
    /// ZKP Master seed wrapped for the enclave public key
    pub encrypted_master_seed_for_enclave: String,
}
#[derive(Debug, Deserialize)]
struct VaultDatakeyResponse {
    #[serde(default)]
    data: DatakeyPayload,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DatakeyPayload {
    plaintext: String,
    ciphertext: String,
}

pub struct VaultDatakeyEngine {
    pub vault_addr: String,
    pub vault_token: String,
    pub secret_key_name: String,
    pub client: Client,
}

#[derive(Debug, Deserialize)]
struct VaultSeedResponse {
    #[serde(default)]
    data: VaultSeedData,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultSeedData {
    random_bytes: String,
}


impl VaultDatakeyEngine {
    pub fn new(
        address: impl Into<String>,
        token: impl Into<String>,
        transit_key: impl Into<String>,
    ) -> Result<Self, BrokerError> {
        let client = build_vault_client()?;
        Ok(Self {
            vault_addr: address.into().trim_end_matches('/').to_string(),
            vault_token: token.into(),
            secret_key_name: transit_key.into(),
            client,
        })
    }

    /// Convenience loader directly from environment variables
    pub fn from_env(transit_key: impl Into<String>) -> Result<Self, BrokerError> {
        let vault_addr = std::env::var("DZTA_VAULT_ADDR")
            .unwrap_or_else(|_| "http://127.0.0.1:8200".into());
        let vault_token = std::env::var("DZTA_VAULT_TOKEN")
            .unwrap_or_else(|_| "root".into());

        Self::new(vault_addr, vault_token, transit_key)
    }

    /// Explicit custom client constructor (useful when injecting test configurations directly)
    pub fn with_client(
        address: impl Into<String>,
        token: impl Into<String>,
        transit_key: impl Into<String>,
        client: Client,
    ) -> Self {
        Self {
            client,
            vault_addr: address.into().trim_end_matches('/').to_string(),
            vault_token: token.into(),
            secret_key_name: transit_key.into(),
        }
    }

    /// Called once during Device Provisioning.
    /// Asks Vault to generate a Wallet DEK and a 32-byte Master Seed.
    /// Returns ciphertexts to be saved to disk  or wallet and RSA-wrapped secrets for the enclave.
    pub async fn provision_datakey(
        &self,
        enclave_public_key_pem: &str,
    ) -> Result<ProvisioningDataKeyResponse, BrokerError> {
        // --- 1. Generate Wallet DEK from Vault Transit ---
        let datakey_url = format!(
            "{}/v1/transit/datakey/plaintext/{}",
            self.vault_addr, self.secret_key_name
        );

        let response = self
            .client
            .post(&datakey_url)
            .header("X-Vault-Token", &self.vault_token)
            .send()
            .await?;

        let status = response.status();
        let resp: VaultDatakeyResponse = response.json().await.map_err(BrokerError::Request)?;

        if !status.is_success() {
            return Err(BrokerError::Provider {
                status,
                body: resp.errors.join(", "),
            });
        }

        let raw_dek_bytes = BASE64
            .decode(&resp.data.plaintext)
            .map_err(|e| BrokerError::Response(format!("invalid Vault plaintext: {e}")))?;

        // Wrap the raw DEK using the Enclave RSA Public Key
        let encrypted_wallet_key_for_enclave =
            self.wrap_bytes_for_enclave(&raw_dek_bytes, enclave_public_key_pem)?;

        // --- 2. Generate 32-byte ZKP Master Seed from Vault CPRNG ---
        let raw_master_seed = self.generate_vault_random_seed().await?;

        // Encrypt the master seed via Vault Transit for local disk storage
        let seed_ciphertext = self.encrypt(&raw_master_seed).await?;

        // Wrap the raw master seed using the Enclave RSA Public Key
        let encrypted_master_seed_for_enclave =
            self.wrap_bytes_for_enclave(&raw_master_seed, enclave_public_key_pem)?;

        Ok(ProvisioningDataKeyResponse {
            wallet_ciphertext: resp.data.ciphertext,
            encrypted_wallet_key_for_enclave,
            seed_ciphertext,
            encrypted_master_seed_for_enclave,
        })
    }

    ///  Called during subsequent ZKP generation sessions.
    /// Takes the `ciphertext` stored on the Device's disk, unwraps it via Vault Transit `/decrypt`,
    /// and re-wraps it strictly for the Enclave Public Key.
   
    pub async fn unwrap_datakey_for_enclave(
        &self,
        wallet_ciphertext: &str,
        enclave_public_key_pem: &str,
    ) -> Result<String, BrokerError> {
        // 1. Decrypt raw bytes using the VaultDecryptor trait
        let raw_dek_bytes = self
            .decrypt(wallet_ciphertext)
            .await
            .map_err(|e| BrokerError::Response(e.to_string()))?;

        // 2. Re-wrap DEK for Enclave Public Key
        self.wrap_bytes_for_enclave(&raw_dek_bytes, enclave_public_key_pem)
    }

    /// Helper to wrap raw byte payload with the enclave RSA public key
    pub fn wrap_bytes_for_enclave(
        &self,
        raw_bytes: &[u8],
        enclave_public_key_pem: &str,
    ) -> Result<String, BrokerError> {
        let rsa_pub = RsaPublicKey::from_public_key_pem(enclave_public_key_pem)
            .map_err(|e| BrokerError::Response(format!("invalid enclave public key: {e}")))?;
        let mut rng = rand::thread_rng();
        let encrypted_bytes = rsa_pub
            .encrypt(&mut rng, Oaep::new::<RsaSha256>(), raw_bytes)
            .map_err(|e| BrokerError::Response(format!("failed to wrap bytes for enclave: {e}")))?;

        Ok(BASE64.encode(encrypted_bytes))
    }
  
}

#[async_trait]
impl VaultSeed for VaultDatakeyEngine {
    /// Generates 32 bytes of secure entropy directly inside Vault aka Master Seed.
    /// Returns a `Zeroizing<Vec<u8>>` wrapper so memory is scrubbed on drop.
    async fn generate_vault_random_seed(&self) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
        let url = format!("{}/v1/transit/random/32", self.vault_addr);

        let response = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.vault_token)
            .json(&serde_json::json!({ "format": "base64" }))
            .send()
            .await?;

        let status = response.status();
        let resp: VaultSeedResponse = response.json().await.map_err(BrokerError::Request)?;

        if !status.is_success() {
            return Err(BrokerError::Provider {
                status,
                body: resp.errors.join(", "),
            });
        }

        // 1. Decode Base64 into a Zeroizing vector
        let decoded = BASE64
            .decode(&resp.data.random_bytes)
            .map_err(|e| BrokerError::Response(format!("invalid Vault random bytes: {e}")))?;

        // 2. Wrap in Zeroizing container
        Ok(Zeroizing::new(decoded))
    }
}

#[async_trait]
impl VaultEncryptor for VaultDatakeyEngine {
    async fn encrypt(&self, payload: &[u8]) -> BrokerResult<String> {
        let url = format!("{}/v1/transit/encrypt/{}", self.vault_addr, self.secret_key_name);
        let base64_payload = base64::engine::general_purpose::STANDARD.encode(payload);

        let response = self.client.post(&url)
            .bearer_auth(&self.vault_token)
            .json(&serde_json::json!({
                "plaintext": base64_payload
            }))
            .send()
            .await
            .map_err(|e| BrokerError::Response(format!("Vault encrypt request failed: {}", e)))?;

        let body: serde_json::Value = response.json().await
            .map_err(|e| BrokerError::Response(format!("Vault encrypt response read failed: {}", e)))?;

        body["data"]["ciphertext"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| BrokerError::Response("Vault returned no ciphertext".into()))
    }
}

#[async_trait]
impl VaultDecryptor for VaultDatakeyEngine {
    async fn decrypt(&self, ciphertext: &str) -> BrokerResult<Zeroizing<Vec<u8>>> {
        let url = format!(
            "{}/v1/transit/decrypt/{}",
            self.vault_addr, self.secret_key_name
        );

        let response = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.vault_token)
            .json(&serde_json::json!({ "ciphertext": ciphertext }))
            .send()
            .await
            .map_err(|e| BrokerError::Response(format!("Vault decrypt request failed: {}", e)))?;

        let status = response.status();
        let resp_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BrokerError::Response(format!("Vault decrypt response read failed: {}", e)))?;

        if !status.is_success() {
            let err_msg = resp_json["errors"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| format!("Vault transit decrypt failed with status {status}"));
            return Err(BrokerError::Response(err_msg));
        }

        let b64_plaintext = resp_json["data"]["plaintext"]
            .as_str()
            .ok_or_else(|| BrokerError::Response("Vault response missing plaintext field".to_string()))?;

        BASE64
            .decode(b64_plaintext)
            .map(Zeroizing::new)
            .map_err(|e| BrokerError::Response(format!("invalid Vault plaintext: {e}")))
    }
}