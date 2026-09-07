use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dcap_qvl::{collateral::CollateralClient, policy::QuotePolicy, verify::QuoteVerifier};
use dzta_attestation_broker::{HttpsKmsProvider, SecretProvider, VaultSecretRelease, VaultTransitProvider, VerifiedEnclave, WrappedEnclaveSecrets};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{env, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

#[derive(Clone)]
struct AppState {
    pccs_url: String,
    expected_mrenclave: Vec<u8>,
    expected_mrsigner: Vec<u8>,
    kms: Arc<dyn SecretProvider>,
}

#[derive(Debug, Deserialize)]
struct ReleaseRequest {
    quote: String,
    enclave_public_key: String,
    credential_key_id: String,
    required_clearance_level: u64,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| internal(e.to_string()))?
        .as_secs();
    let policy = QuotePolicy::strict(now);
    let claims = QuoteVerifier::new_prod()
        .verify_with_policy(&quote, collateral, now, &policy)
        .map_err(internal)?;
    let report = claims.report.as_sgx().ok_or_else(|| bad_request("quote is not an SGX quote"))?;
    if report.mr_enclave.as_slice() != state.expected_mrenclave.as_slice()
        || report.mr_signer.as_slice() != state.expected_mrsigner.as_slice()
    {
        return Err(bad_request("unexpected enclave measurement or signer"));
    }
    let mut binding = request.enclave_public_key.as_bytes().to_vec();
    binding.extend_from_slice(&request.required_clearance_level.to_be_bytes());
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"dZTA_SGX_SESSION_v1");
    hasher.update(&binding);
    let expected_report_data = hasher.finalize();
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
        .await
        .map(Json)
        .map_err(internal)
}

fn bad_request(error: impl ToString) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: error.to_string() }))
}

fn internal(error: impl ToString) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: error.to_string() }))
}

fn hex_env(name: &str) -> Result<Vec<u8>, String> {
    let value = env::var(name).map_err(|_| format!("missing {name}"))?;
    hex::decode(value).map_err(|e| format!("invalid {name}: {e}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_provider: Arc<dyn SecretProvider> = match env::var("DZTA_SECRET_PROVIDER")
        .unwrap_or_else(|_| "https".to_string())
        .as_str()
    {
        "https" => Arc::new(HttpsKmsProvider::new(
            env::var("DZTA_KMS_ENDPOINT")?,
            env::var("DZTA_KMS_BEARER_TOKEN").ok(),
        )?),
        "vault" => Arc::new(VaultSecretRelease {
            wallet_ciphertext: env::var("DZTA_VAULT_WALLET_CIPHERTEXT")?,
            seed_ciphertext: env::var("DZTA_VAULT_SEED_CIPHERTEXT")?,
            provider: VaultTransitProvider::new(
                env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string()),
                env::var("VAULT_TOKEN")?,
                env::var("DZTA_VAULT_TRANSIT_KEY")?,
            )?,
        }),
        provider => return Err(format!("unsupported DZTA_SECRET_PROVIDER: {provider}").into()),
    };

    let state = AppState {
        pccs_url: env::var("PCCS_URL").unwrap_or_else(|_| "https://pccs.phala.network".to_string()),
        expected_mrenclave: hex_env("DZTA_MRENCLAVE")?,
        expected_mrsigner: hex_env("DZTA_MRSIGNER")?,
        kms: secret_provider,
    };
    let app = Router::new().route("/v1/key-release", post(release)).with_state(state);
    let listener = tokio::net::TcpListener::bind(
        env::var("DZTA_ATTESTATION_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string()),
    ).await?;
    axum::serve(listener, app).await?;
    Ok(())
}