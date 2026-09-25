use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Fabric client error: {0}")]
    FabricError(String),
    #[error("VCX error: {0}")]
    VcxError(String),
    #[error("Askar error: {0}")]
    AskarError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Chaincode invocation failed: {0}")]
    ChaincodeFailed(String),
    #[error("Invalid response from peer")]
    InvalidResponse,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    #[error("DID not found: {0}")]
    DIDNotFound(String),
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    #[error("gRPC error: {0}")]
    GrpcError(String),
    #[error("Revocation check failed: {0}")]
    RevocationError(String),
    #[error("Timeout waiting for transaction confirmation")]
    TransactionTimeout,
    #[error("Tee Execution failed: {0}")]
    ExecutionFailed(String),
    #[error("provider request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("provider request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("provider returned HTTP {status}: {body}")]
    Provider { status: reqwest::StatusCode, body: String },
    #[error("wallet error: {0}")]
    Wallet(#[from] WalletError),
    #[error("invalid provider response: {0}")]
    Response(String),
    #[error("provider configuration error: {0}")]
    Configuration(String),
}

pub type WalletResult<T> = Result<T, WalletError>;
pub type BrokerResult<T> = Result<T, BrokerError>;