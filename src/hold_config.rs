pub struct UserContext {
    name: String,
    cert_pem: String,
    private_key: Vec<u8>,
    msp_id: String,
}

impl UserContext {
    pub fn from_enrollment(
        name: &str,
        cert_path: &str,
        key_path: &str,
        msp_id: &str,
    ) -> WalletResult<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| WalletError::ConfigError(format!("Failed to read cert: {}", e)))?;

        let private_key = std::fs::read(key_path)
            .map_err(|e| WalletError::ConfigError(format!("Failed to read key: {}", e)))?;

        Ok(UserContext {
            name: name.to_string(),
            cert_pem,
            private_key,
            msp_id: msp_id.to_string(),
        })
    }

    pub fn get_cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn sign_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        // Use RSA or ECDSA signing based on your key type
        use openssl::sign::Signer;
        use openssl::pkey::PKey;
        use openssl::hash::MessageDigest;

        let pkey = PKey::private_key_from_pem(&self.private_key)
            .map_err(|e| e.to_string())?;

        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
            .map_err(|e| e.to_string())?;
        
        signer.update(bytes)
            .map_err(|e| e.to_string())?;
        
        signer.sign_to_vec()
            .map_err(|e| e.to_string())
    }
}


// In errors.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Chaincode invocation failed: {0}")]
    ChaincodeFailed(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("gRPC error: {0}")]
    GrpcError(String),

    #[error("Timeout waiting for transaction confirmation")]
    TransactionTimeout,

    #[error("Invalid response from peer")]
    InvalidResponse,
}

pub type WalletResult<T> = Result<T, WalletError>;
