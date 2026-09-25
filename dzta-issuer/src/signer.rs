//dzta-issuer/src/signer.rs
use async_trait::async_trait;
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use multibase::Base;
// use reqwest::Client;
use serde::Deserialize;
use shared::{WalletError, WalletResult, BrokerError, BrokerResult};
use std::collections::HashMap;
// use std::time::Duration;
// use std::fs;
use reqwest::{Client};
use zeroize::Zeroizing;
// use async_trait::async_trait;
use shared::vault_client::{VaultEncryptor};
use shared::vault_client::build_vault_client;

/// Credential signing abstraction. Production implementations keep private key
/// material outside the issuer process whenever possible.
#[async_trait]
pub trait CredentialSignerBackend: Send + Sync {
    async fn public_key_multibase(&self) -> WalletResult<String>;
    async fn sign(&self, payload: &[u8]) -> WalletResult<String>;
}

/// Local signer for development and deterministic tests only.
pub struct LocalCredentialSigner {
    signing_key: SigningKey,
}


impl LocalCredentialSigner {
    pub fn generate() -> WalletResult<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| WalletError::SigningError(format!("Signing key generation failed: {}", e)))?;
        Ok(Self::from_seed(seed))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { signing_key: SigningKey::from_bytes(&seed) }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_multibase_value(&self) -> String {
        multibase::encode(Base::Base58Btc, self.public_key_bytes())
    }

    pub fn sign_value(&self, payload: &[u8]) -> String {
        format!("u{}", URL_SAFE_NO_PAD.encode(self.signing_key.sign(payload).to_bytes()))
    }

    pub fn verify(public_key: &[u8; 32], payload: &[u8], proof_value: &str) -> WalletResult<()> {
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| WalletError::SigningError(format!("Invalid credential public key: {}", e)))?;
        let encoded = proof_value.strip_prefix('u').ok_or_else(|| {
            WalletError::SigningError("Proof value must use base64url encoding".into())
        })?;
        let signature_bytes = URL_SAFE_NO_PAD.decode(encoded)
            .map_err(|e| WalletError::SigningError(format!("Invalid proof encoding: {}", e)))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| WalletError::SigningError(format!("Invalid proof signature: {}", e)))?;
        key.verify(payload, &signature)
            .map_err(|e| WalletError::SigningError(format!("Credential proof verification failed: {}", e)))
    }
}

#[async_trait]
impl CredentialSignerBackend for LocalCredentialSigner {
    async fn public_key_multibase(&self) -> WalletResult<String> {
        Ok(self.public_key_multibase_value())
    }

    async fn sign(&self, payload: &[u8]) -> WalletResult<String> {
        Ok(self.sign_value(payload))
    }
}

/// Vault Transit signer. Vault owns the private key and returns only signatures.
pub struct VaultCredentialSigner {
    client: Client,
    address: String,
    token: String,
    transit_key: String,
}

impl VaultCredentialSigner {
 

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

    pub fn from_env() -> BrokerResult<Self> {
        let address = std::env::var("DZTA_VAULT_ADDR")
            .map_err(|_| BrokerError::Configuration("DZTA_VAULT_ADDR is required".into()))?;
        let token = std::env::var("DZTA_VAULT_TOKEN")
            .map_err(|_| BrokerError::Configuration("DZTA_VAULT_TOKEN is required".into()))?;
        let key = std::env::var("DZTA_CREDENTIAL_SIGNING_KEY")
            .map_err(|_| BrokerError::Configuration("DZTA_CREDENTIAL_SIGNING_KEY is required".into()))?;
        Self::new(address, token, key)
    }

    async fn get_key_type(&self) -> WalletResult<String> {
        let url = format!("{}/v1/transit/keys/{}", self.address, self.transit_key);
        let response = self.client.get(url).bearer_auth(&self.token).send().await
            .map_err(|e| WalletError::NetworkError(format!("Vault key info request failed: {}", e)))?;
        let response: VaultKeyResponse = self.request(response).await?;
        
        Ok(response.data.r#type.unwrap_or_else(|| "ed25519".to_string()))
    }

    async fn request<T: for<'de> Deserialize<'de>>(&self, response: reqwest::Response) -> WalletResult<T> {
        let status = response.status();
        let body = response.text().await
            .map_err(|e| WalletError::NetworkError(format!("Vault response read failed: {}", e)))?;
        if !status.is_success() {
            return Err(WalletError::SigningError(format!("Vault returned {}: {}", status, body)));
        }
        serde_json::from_str(&body).map_err(WalletError::SerializationError)
    }

}

#[derive(Debug, Deserialize)]
struct VaultKeyResponse {
    data: VaultKeyData,
}

#[derive(Debug, Deserialize)]

struct VaultKeyData {
    #[serde(default)]
    r#type: Option<String>,
    latest_version: serde_json::Value,
    keys: HashMap<String, VaultKeyVersion>,
}

#[derive(Debug, Deserialize)]
struct VaultKeyVersion {
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct VaultSignResponse {
    data: VaultSignData,
}

#[derive(Debug, Deserialize)]
struct VaultSignData {
    signature: String,
}

#[async_trait]
impl CredentialSignerBackend for VaultCredentialSigner {
    async fn public_key_multibase(&self) -> WalletResult<String> {
        let url = format!("{}/v1/transit/keys/{}", self.address, self.transit_key);
        let response = self.client.get(url).bearer_auth(&self.token).send().await
            .map_err(|e| WalletError::NetworkError(format!("Vault public-key request failed: {}", e)))?;
        let response: VaultKeyResponse = self.request(response).await?;
        let version_str = match &response.data.latest_version {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.clone(),
            _ => return Err(WalletError::SigningError("Invalid latest_version format".into())),
        };
        let key = response.data.keys.get(&version_str)
            .ok_or_else(|| WalletError::SigningError("Vault returned no latest public key".into()))?;
        let public_key = STANDARD.decode(&key.public_key)
            .map_err(|e| WalletError::SigningError(format!("Vault public-key decoding failed: {}", e)))?;
        if public_key.len() != 32 {
            return Err(WalletError::SigningError("Vault Ed25519 public key must be 32 bytes".into()));
        }
        Ok(multibase::encode(Base::Base58Btc, public_key))
    }

    async fn sign(&self, payload: &[u8]) -> WalletResult<String> {
        let key_type = self.get_key_type().await?;
        let url = format!("{}/v1/transit/sign/{}", self.address, self.transit_key);
        
        // Branch parameters based on Vault key type
        let body = if key_type.starts_with("rsa") {
            serde_json::json!({
                "input": STANDARD.encode(payload),
                "hash_algorithm": "sha2-256",
                "signature_algorithm": "pkcs1v15",
            })
        } else if key_type.starts_with("ecdsa") {
            serde_json::json!({
                "input": STANDARD.encode(payload),
                "hash_algorithm": "sha2-256",
            })
        } else {
            // Default to Ed25519 (requires input only)
            serde_json::json!({
                "input": STANDARD.encode(payload),
            })
        };

        let response = self.client.post(url)
            .bearer_auth(&self.token)
            .json(&body)
            .send().await
            .map_err(|e| WalletError::NetworkError(format!("Vault signing request failed: {}", e)))?;

        let response: VaultSignResponse = self.request(response).await?;
        let encoded_signature = response.data.signature.rsplit(':').next()
            .ok_or_else(|| WalletError::SigningError("Vault returned malformed signature".into()))?;
        let signature = STANDARD.decode(encoded_signature)
            .map_err(|e| WalletError::SigningError(format!("Vault signature decoding failed: {}", e)))?;

        Ok(format!("u{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}


#[async_trait]
impl VaultEncryptor for VaultCredentialSigner {
    async fn encrypt(&self, payload: &[u8]) -> BrokerResult<String> {
        let url = format!("{}/v1/transit/encrypt/{}", self.address, self.transit_key);
        let base64_payload = base64::engine::general_purpose::STANDARD.encode(payload);

        let response = self.client.post(&url)
            .bearer_auth(&self.token)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_signer_round_trips_a_signature() {
        let signer = LocalCredentialSigner::from_seed([7u8; 32]);
        let payload = b"credential proof payload";
        let proof = signer.sign_value(payload);
        LocalCredentialSigner::verify(&signer.public_key_bytes(), payload, &proof).unwrap();
    }
}
