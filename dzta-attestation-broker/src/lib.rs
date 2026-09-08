use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::Client;
use rsa::{pkcs1::DecodeRsaPublicKey, Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2_10::Sha256 as RsaSha256;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("provider request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("provider returned HTTP {status}: {body}")]
    Provider { status: reqwest::StatusCode, body: String },
    #[error("invalid provider response: {0}")]
    Response(String),
    #[error("provider configuration error: {0}")]
    Configuration(String),
}

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
    pub fn new(address: impl Into<String>, token: impl Into<String>, transit_key: impl Into<String>) -> Result<Self, BrokerError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(BrokerError::Request)?;
        Ok(Self {
            client,
            address: address.into().trim_end_matches('/').to_string(),
            token: token.into(),
            transit_key: transit_key.into(),
        })
    }

    async fn decrypt_envelope(&self, ciphertext: &str) -> Result<Vec<u8>, BrokerError> {
        let url = format!("{}/v1/transit/decrypt/{}", self.address, self.transit_key);
        let response = self.client
            .post(url)
            .header("X-Vault-Token", &self.token)
            .json(&serde_json::json!({ "ciphertext": ciphertext }))
            .send()
            .await?;
        let status = response.status();
        let body: VaultDecryptResponse = response.json().await.map_err(BrokerError::Request)?;
        if !status.is_success() {
            return Err(BrokerError::Provider { status, body: body.errors.join(", ") });
        }
        let plaintext = body.data.plaintext.ok_or_else(|| BrokerError::Response("Vault returned no plaintext".to_string()))?;
        BASE64.decode(plaintext).map_err(|e| BrokerError::Response(format!("invalid Vault plaintext: {e}")))
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

/// The broker stores Vault Transit ciphertexts for the two secret envelopes.
/// `rewrap_for_enclave` is deliberately left as the broker's boundary method:
/// it must use an enclave-held public key encryption implementation, never send
/// `wallet_key` or `master_seed` to the client in plaintext.
pub struct VaultSecretRelease {
    pub wallet_ciphertext: String,
    pub seed_ciphertext: String,
    pub provider: VaultTransitProvider,
}

#[async_trait]
impl SecretProvider for VaultSecretRelease {
    async fn release_for_verified_enclave(
        &self,
        enclave: &VerifiedEnclave,
        credential_key_id: &str,
    ) -> Result<WrappedEnclaveSecrets, BrokerError> {
        if enclave.quote.is_empty() || enclave.report_data.is_empty() || enclave.enclave_public_key.is_empty() {
            return Err(BrokerError::Configuration("verified enclave identity is incomplete".to_string()));
        }
        let wallet_key = self.provider.decrypt_envelope(&self.wallet_ciphertext).await?;
        let master_seed = self.provider.decrypt_envelope(&self.seed_ciphertext).await?;
        let public_key = RsaPublicKey::from_pkcs1_pem(&enclave.enclave_public_key)
            .map_err(|e| BrokerError::Response(format!("invalid enclave public key: {e}")))?;
        let padding = Oaep::new::<RsaSha256>();
        let mut rng = rand::thread_rng();
        let encrypted_wallet_key = public_key.encrypt(&mut rng, padding, &wallet_key)
            .map_err(|e| BrokerError::Response(format!("failed to wrap wallet key: {e}")))?;
        let encrypted_master_seed = public_key.encrypt(&mut rng, Oaep::new::<RsaSha256>(), &master_seed)
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
    pub fn new(endpoint: impl Into<String>, bearer_token: Option<String>) -> Result<Self, BrokerError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(BrokerError::Request)?;
        Ok(Self { client, endpoint: endpoint.into(), bearer_token })
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
}

#[async_trait]
impl SecretProvider for HttpsKmsProvider {
    async fn release_for_verified_enclave(
        &self,
        enclave: &VerifiedEnclave,
        credential_key_id: &str,
    ) -> Result<WrappedEnclaveSecrets, BrokerError> {
        let mut request = self.client.post(&self.endpoint).json(&KmsReleaseRequest {
            quote: &enclave.quote,
            report_data: &enclave.report_data,
            enclave_public_key: &enclave.enclave_public_key,
            mrenclave: &enclave.mrenclave,
            mrsigner: &enclave.mrsigner,
            credential_key_id,
        });
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(BrokerError::Provider { status, body: response.text().await? });
        }
        response.json().await.map_err(BrokerError::Request)
    }
}
