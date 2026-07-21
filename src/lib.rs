// src/lib.rs
pub mod fabric_client;
pub mod credential_manager;
pub mod witness_generator;
pub mod models;
pub mod config;
pub mod errors;
pub mod schema_engine;
pub mod zkp_core;
pub mod tee_runner;



pub use fabric_client::FabricClient;
pub use credential_manager::CredentialManager;
pub use witness_generator::ZKPWitnessGenerator;
pub use models::*;
pub use config::ConnectionConfig;
pub use errors::WalletError;
pub use schema_engine::SchemaEngine;
pub use zkp_core::ZkpCore;
pub use tee_runner::EnclaveExecutionProxy;