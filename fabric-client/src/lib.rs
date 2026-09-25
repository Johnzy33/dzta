// fabric-client/src/lib.rs
pub mod fabric_client;

pub mod config;
pub mod errors;
pub mod schema_engine;
pub use fabric_client::*;

pub use config::ConnectionConfig;
pub use errors::WalletError;
pub use shared::WalletResult;
pub use schema_engine::SchemaEngine;
pub use dzta_wallet::Wallet;