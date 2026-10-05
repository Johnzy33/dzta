
// dzta-attestation-broker/src/bin/attestation-broker.rs
use dzta_attestation_broker::{
    routes::{create_router, AppState},
    HttpsKmsProvider, SecretProvider, VaultDatakeyEngine, VaultSecretRelease, VaultTransitProvider,
};
use std::{env, sync::Arc};
use std::io::{self};
use tracing::{Level};
use tracing_subscriber::FmtSubscriber;

fn hex_env(name: &str) -> Result<Vec<u8>, String> {
    let value = env::var(name).map_err(|_| format!("missing {name}"))?;
    hex::decode(value).map_err(|e| format!("invalid {name}: {e}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // 1. Initialize Tracing Diagnostic Logging (strictly to stderr without ANSI colors)
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .with_writer(io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let vault_addr = env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
    let vault_token = env::var("VAULT_TOKEN").ok();
    let transit_key = env::var("DZTA_VAULT_TRANSIT_KEY").ok();

    let secret_provider: Arc<dyn SecretProvider> = match env::var("DZTA_SECRET_PROVIDER")
        .unwrap_or_else(|_| "https".to_string())
        .as_str()
    {
        "https" => Arc::new(HttpsKmsProvider::new(
            env::var("DZTA_KMS_ENDPOINT")?,
            env::var("DZTA_KMS_BEARER_TOKEN").ok(),
        )?),
        "vault" => Arc::new(VaultSecretRelease {
            provider: VaultTransitProvider::new(
                &vault_addr,
                vault_token
                    .as_ref()
                    .ok_or("missing VAULT_TOKEN for Vault provider")?,
                transit_key
                    .as_ref()
                    .ok_or("missing DZTA_VAULT_TRANSIT_KEY for Vault provider")?,
            )?,
        }),
        provider => return Err(format!("unsupported DZTA_SECRET_PROVIDER: {provider}").into()),
    };

    let datakey_engine = if let (Some(token), Some(key)) = (vault_token, transit_key) {
        Some(Arc::new(VaultDatakeyEngine::new(&vault_addr, token, key)?))
    } else {
        None
    };

    let state = AppState {
        pccs_url: env::var("PCCS_URL").unwrap_or_else(|_| "https://pccs.phala.network".to_string()),
        expected_mrenclave: hex_env("DZTA_MRENCLAVE")?,
        expected_mrsigner: hex_env("DZTA_MRSIGNER")?,
        kms: secret_provider,
        datakey_engine,
    };

    let app = create_router(state);

    let bind_addr =
        env::var("DZTA_ATTESTATION_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());
    println!(" dZTA Attestation Broker listening on {bind_addr}");

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
