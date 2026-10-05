
use async_trait::async_trait;
use zeroize::Zeroizing;

use reqwest::{Certificate, Client};
// use std::env;
use std::time::Duration;
// use tokio::fs;
use crate::errors::{BrokerError, BrokerResult};

/// Constructs an HTTP client configured specifically for Vault communication.
/// Supports custom Root CAs (`VAULT_CACERT`) and emergency TLS bypass (`VAULT_INSECURE_SKIP_VERIFY`).

pub fn build_vault_client() -> Result<Client, BrokerError> {
    let mut builder = Client::builder().timeout(Duration::from_secs(10));

    if std::env::var("VAULT_INSECURE_SKIP_VERIFY")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
    {
        builder = builder.danger_accept_invalid_certs(true);
    } else if let Ok(ca_path) = std::env::var("VAULT_CACERT") {
        if let Ok(ca_cert_bytes) = std::fs::read(&ca_path) {
            if let Ok(cert) = Certificate::from_pem(&ca_cert_bytes) {
                builder = builder.add_root_certificate(cert);
            }
        }
    }

    builder.build().map_err(BrokerError::Request)
}

#[async_trait]
pub trait VaultEncryptor: Send + Sync {
    async fn encrypt(&self, payload: &[u8]) -> BrokerResult<String>;
}

#[async_trait]
pub trait VaultSeed:Send + Sync {
    async fn generate_vault_random_seed(&self) -> BrokerResult<Zeroizing<Vec<u8>>>;
}

#[async_trait]
pub trait VaultDecryptor {
    async fn decrypt(&self, ciphertext: &str) -> BrokerResult<Zeroizing<Vec<u8>>>;
}

