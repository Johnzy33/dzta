// src/config.rs
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use crate::errors::{WalletError, WalletResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub name: String,
    pub version: String,
    pub client: ClientConfig,
    pub organizations: std::collections::HashMap<String, OrgConfig>,
    pub peers: std::collections::HashMap<String, PeerConfig>,
    pub orderers: std::collections::HashMap<String, OrdererConfig>,
    pub channels: std::collections::HashMap<String, ChannelConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(rename = "tlsCerts")]
    pub tls_certs: Option<TlsCertConfig>,
    pub credentialStore: Option<CredentialStoreConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertConfig {
    pub client: Option<ClientCertConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCertConfig {
    pub keyFile: String,
    pub certFile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStoreConfig {
    pub path: String,
    #[serde(rename = "cryptoStore")]
    // pub crypto_store: Option<String>,
    pub crypto_store: Option<CryptoStoreConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoStoreConfig {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgConfig {
    pub mspid: String,
    #[serde(rename = "cryptoPath")]
    pub crypto_path: Option<String>,
    pub peers: Option<Vec<String>>,
    pub orderers: Option<Vec<String>>,
    #[serde(rename = "certificateAuthorities")]
    pub certificate_authorities: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub url: String,
    #[serde(rename = "tlsCACerts")]
    pub tls_ca_certs: Option<TlsCAConfig>,
    pub grpcOptions: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCAConfig {
    pub pem: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrdererConfig {
    pub url: String,
    #[serde(rename = "tlsCACerts")]
    pub tls_ca_certs: Option<TlsCAConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub orderers: Option<Vec<String>>,
    pub peers: std::collections::HashMap<String, PeerChannelConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerChannelConfig {
    #[serde(rename = "endorsingPeer")]
    pub endorsing_peer: Option<bool>,
    #[serde(rename = "chaincodeQuery")]
    pub chaincode_query: Option<bool>,
    #[serde(rename = "ledgerQuery")]
    pub ledger_query: Option<bool>,
    #[serde(rename = "eventSource")]
    pub event_source: Option<bool>,
}

impl ConnectionConfig {
    /// Load connection profile from YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> WalletResult<Self> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| WalletError::ConfigError(format!("Failed to read config: {}", e)))?;

        serde_yaml::from_str(&content)
            .map_err(|e| WalletError::ConfigError(format!("Failed to parse YAML: {}", e)))
    }

    /// Get peer URL by name
    pub fn get_peer_url(&self, peer_name: &str) -> WalletResult<String> {
        self.peers
            .get(peer_name)
            .map(|p| p.url.clone())
            .ok_or_else(|| WalletError::ConfigError(format!("Peer not found: {}", peer_name)))
    }

    /// Get orderer URL
    pub fn get_orderer_url(&self, orderer_name: &str) -> WalletResult<String> {
        self.orderers
            .get(orderer_name)
            .map(|o| o.url.clone())
            .ok_or_else(|| WalletError::ConfigError(format!("Orderer not found: {}", orderer_name)))
    }

    /// Get organization MSP ID
    pub fn get_org_mspid(&self, org_name: &str) -> WalletResult<String> {
        self.organizations
            .get(org_name)
            .map(|o| o.mspid.clone())
            .ok_or_else(|| WalletError::ConfigError(format!("Org not found: {}", org_name)))
    }
}
