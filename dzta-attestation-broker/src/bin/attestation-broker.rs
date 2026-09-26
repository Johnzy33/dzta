<<<<<<< HEAD

// dzta-attestation-broker/src/bin/attestation-broker.rs
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dcap_qvl::{collateral::CollateralClient, policy::QuotePolicy, verify::QuoteVerifier};
use dzta_attestation_broker::{
    HttpsKmsProvider, ProvisioningDataKeyResponse, SecretProvider, VaultDatakeyEngine,
    VaultSecretRelease, VaultTransitProvider, VerifiedEnclave, WrappedEnclaveSecrets,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    env,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
=======
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dcap_qvl::{collateral::CollateralClient, policy::QuotePolicy, verify::QuoteVerifier};
use dzta_attestation_broker::{HttpsKmsProvider, SecretProvider, VaultSecretRelease, VaultTransitProvider, VerifiedEnclave, WrappedEnclaveSecrets};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{env, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f

#[derive(Clone)]
struct AppState {
    pccs_url: String,
    expected_mrenclave: Vec<u8>,
    expected_mrsigner: Vec<u8>,
    kms: Arc<dyn SecretProvider>,
<<<<<<< HEAD
    datakey_engine: Option<Arc<VaultDatakeyEngine>>,
=======
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
}

#[derive(Debug, Deserialize)]
struct ReleaseRequest {
    quote: String,
    enclave_public_key: String,
    credential_key_id: String,
    required_clearance_level: u64,
<<<<<<< HEAD
    wallet_ciphertext: String,
    seed_ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct ProvisionDatakeyRequest {
    enclave_public_key: String,
}

#[derive(Debug, Deserialize)]
struct UnwrapDatakeyRequest {
    quote: String,
    enclave_public_key: String,
    required_clearance_level: u64,
    stored_ciphertext: String,
}

#[derive(Debug, Serialize)]
struct UnwrapDatakeyResponse {
    encrypted_datakey_for_enclave: String,
=======
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

<<<<<<< HEAD
// Helper function to verify SGX attestation quote and bind report data
fn verify_sgx_quote(
    state: &AppState,
    quote_b64: &str,
    enclave_public_key: &str,
    required_clearance_level: u64,
) -> Result<VerifiedEnclave, (StatusCode, Json<ErrorResponse>)> {
    let quote = BASE64.decode(quote_b64).map_err(bad_request)?;

    let collateral = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let client = CollateralClient::with_default_http(&state.pccs_url).map_err(internal)?;
            client.fetch(&quote).await.map_err(internal)
        })
    })?;

=======
async fn release(
    State(state): State<AppState>,
    Json(request): Json<ReleaseRequest>,
) -> Result<Json<WrappedEnclaveSecrets>, (StatusCode, Json<ErrorResponse>)> {
    let quote = BASE64.decode(request.quote).map_err(bad_request)?;
    let collateral = CollateralClient::with_default_http(&state.pccs_url)
        .map_err(internal)?
        .fetch(&quote)
        .await
        .map_err(internal)?;
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| internal(e.to_string()))?
        .as_secs();
<<<<<<< HEAD

=======
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
    let policy = QuotePolicy::strict(now);
    let claims = QuoteVerifier::new_prod()
        .verify_with_policy(&quote, collateral, now, &policy)
        .map_err(internal)?;
<<<<<<< HEAD

    let report = claims
        .report
        .as_sgx()
        .ok_or_else(|| bad_request("quote is not an SGX quote"))?;

=======
    let report = claims.report.as_sgx().ok_or_else(|| bad_request("quote is not an SGX quote"))?;
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
    if report.mr_enclave.as_slice() != state.expected_mrenclave.as_slice()
        || report.mr_signer.as_slice() != state.expected_mrsigner.as_slice()
    {
        return Err(bad_request("unexpected enclave measurement or signer"));
    }
<<<<<<< HEAD

    let mut binding = enclave_public_key.as_bytes().to_vec();
    binding.extend_from_slice(&required_clearance_level.to_be_bytes());
=======
    let mut binding = request.enclave_public_key.as_bytes().to_vec();
    binding.extend_from_slice(&request.required_clearance_level.to_be_bytes());
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"dZTA_SGX_SESSION_v1");
    hasher.update(&binding);
    let expected_report_data = hasher.finalize();
<<<<<<< HEAD

    if report.report_data[..32] != expected_report_data[..] {
        return Err(bad_request("quote report data does not match requested session"));
    }

    Ok(VerifiedEnclave {
        quote,
        report_data: report.report_data.to_vec(),
        enclave_public_key: enclave_public_key.to_string(),
        mrenclave: hex::encode(report.mr_enclave),
        mrsigner: hex::encode(report.mr_signer),
    })
}

// 1. Static Secret Release
async fn release(
    State(state): State<AppState>,
    Json(request): Json<ReleaseRequest>,
) -> Result<Json<WrappedEnclaveSecrets>, (StatusCode, Json<ErrorResponse>)> {
    let enclave = verify_sgx_quote(
        &state,
        &request.quote,
        &request.enclave_public_key,
        request.required_clearance_level,
    )?;

    state
        .kms
        .release_for_verified_enclave(
            &enclave,
            &request.credential_key_id,
            &request.wallet_ciphertext,
            &request.seed_ciphertext,
        )
=======
    if report.report_data[..32] != expected_report_data[..] {
        return Err(bad_request("quote report data does not match the requested session"));
    }

    let enclave = VerifiedEnclave {
        quote,
        report_data: report.report_data.to_vec(),
        enclave_public_key: request.enclave_public_key,
        mrenclave: hex::encode(report.mr_enclave),
        mrsigner: hex::encode(report.mr_signer),
    };
    state.kms.release_for_verified_enclave(&enclave, &request.credential_key_id)
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
        .await
        .map(Json)
        .map_err(internal)
}

<<<<<<< HEAD
// 2. Option A Phase 1: Device Initial Provisioning
async fn provision_datakey(
    State(state): State<AppState>,
    Json(request): Json<ProvisionDatakeyRequest>,
) -> Result<Json<ProvisioningDataKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let engine = state
        .datakey_engine
        .as_ref()
        .ok_or_else(|| internal("Datakey engine not initialized on broker"))?;

    engine
        .provision_datakey(&request.enclave_public_key)
        .await
        .map(Json)
        .map_err(internal)
}

// 3. Option A Phase 2: Session Unwrap with Attestation Verification
async fn unwrap_datakey(
    State(state): State<AppState>,
    Json(request): Json<UnwrapDatakeyRequest>,
) -> Result<Json<UnwrapDatakeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let engine = state
        .datakey_engine
        .as_ref()
        .ok_or_else(|| internal("Datakey engine not initialized on broker"))?;

    // Verify SGX quote BEFORE unwrapping datakey from Vault
    let enclave = verify_sgx_quote(
        &state,
        &request.quote,
        &request.enclave_public_key,
        request.required_clearance_level,
    )?;

    let encrypted_dek = engine
        .unwrap_datakey_for_enclave(&request.stored_ciphertext, &enclave.enclave_public_key)
        .await
        .map_err(internal)?;

    Ok(Json(UnwrapDatakeyResponse {
        encrypted_datakey_for_enclave: encrypted_dek,
    }))
}

fn bad_request(error: impl ToString) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
}

fn internal(error: impl ToString) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
=======
fn bad_request(error: impl ToString) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: error.to_string() }))
}

fn internal(error: impl ToString) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: error.to_string() }))
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
}

fn hex_env(name: &str) -> Result<Vec<u8>, String> {
    let value = env::var(name).map_err(|_| format!("missing {name}"))?;
    hex::decode(value).map_err(|e| format!("invalid {name}: {e}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
<<<<<<< HEAD
    let vault_addr = env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
    let vault_token = env::var("VAULT_TOKEN").ok();
    let transit_key = env::var("DZTA_VAULT_TRANSIT_KEY").ok();

=======
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
    let secret_provider: Arc<dyn SecretProvider> = match env::var("DZTA_SECRET_PROVIDER")
        .unwrap_or_else(|_| "https".to_string())
        .as_str()
    {
        "https" => Arc::new(HttpsKmsProvider::new(
            env::var("DZTA_KMS_ENDPOINT")?,
            env::var("DZTA_KMS_BEARER_TOKEN").ok(),
        )?),
        "vault" => Arc::new(VaultSecretRelease {
<<<<<<< HEAD
            provider: VaultTransitProvider::new(
                &vault_addr,
                vault_token.as_ref().ok_or("missing VAULT_TOKEN for Vault provider")?,
                transit_key.as_ref().ok_or("missing DZTA_VAULT_TRANSIT_KEY for Vault provider")?,
=======
            wallet_ciphertext: env::var("DZTA_VAULT_WALLET_CIPHERTEXT")?,
            seed_ciphertext: env::var("DZTA_VAULT_SEED_CIPHERTEXT")?,
            provider: VaultTransitProvider::new(
                env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string()),
                env::var("VAULT_TOKEN")?,
                env::var("DZTA_VAULT_TRANSIT_KEY")?,
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
            )?,
        }),
        provider => return Err(format!("unsupported DZTA_SECRET_PROVIDER: {provider}").into()),
    };

<<<<<<< HEAD
    // Initialize VaultDatakeyEngine if Vault environment variables are present
    let datakey_engine = if let (Some(token), Some(key)) = (vault_token, transit_key) {
        Some(Arc::new(VaultDatakeyEngine::new(&vault_addr, token, key)?))
    } else {
        None
    };

=======
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
    let state = AppState {
        pccs_url: env::var("PCCS_URL").unwrap_or_else(|_| "https://pccs.phala.network".to_string()),
        expected_mrenclave: hex_env("DZTA_MRENCLAVE")?,
        expected_mrsigner: hex_env("DZTA_MRSIGNER")?,
        kms: secret_provider,
<<<<<<< HEAD
        datakey_engine,
    };

    let app = Router::new()
        .route("/v1/key-release", post(release))
        .route("/v1/datakey/provision", post(provision_datakey))
        .route("/v1/datakey/unwrap", post(unwrap_datakey))
        .with_state(state);

    let bind_addr = env::var("DZTA_ATTESTATION_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());
    println!("🚀 dZTA Attestation Broker listening on {bind_addr}");

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
=======
    };
    let app = Router::new().route("/v1/key-release", post(release)).with_state(state);
    let listener = tokio::net::TcpListener::bind(
        env::var("DZTA_ATTESTATION_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string()),
    ).await?;
>>>>>>> 835470a2297f770aa1f6e65006e304bbf8f4bb4f
    axum::serve(listener, app).await?;
    Ok(())
}