
// dzta-attestation-broker/src/routes/datakey.rs
use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dcap_qvl::{collateral::CollateralClient, policy::QuotePolicy, verify::QuoteVerifier};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::time::{SystemTime, UNIX_EPOCH};
use shared::{VaultSeed, VaultEncryptor};

use crate::{
    routes::{ApiError, AppState},
    ProvisioningDataKeyResponse, VerifiedEnclave, WrappedEnclaveSecrets,
};

// ----------------------------------------------------------------------------
// Data Transfer Objects (DTOs)
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
pub struct ProvisionDatakeyRequest {
    pub enclave_public_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnwrapDatakeyRequest {
    pub quote: String,
    pub enclave_public_key: String,
    pub required_clearance_level: u64,
    pub wallet_ciphertext: String,
    pub seed_ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnwrapDatakeyResponse {
    pub encrypted_wallet_key_for_enclave: String,
    pub encrypted_master_seed_for_enclave: String,
}

#[derive(Debug, Deserialize)]
pub struct ReleaseRequest {
    pub quote: String,
    pub enclave_public_key: String,
    pub credential_key_id: String,
    pub required_clearance_level: u64,
    pub wallet_ciphertext: String,
    pub seed_ciphertext: String,
}

// ----------------------------------------------------------------------------
// SGX Verification Helper
// ----------------------------------------------------------------------------

pub fn verify_sgx_quote(
    state: &AppState,
    quote_b64: &str,
    enclave_public_key: &str,
    required_clearance_level: u64,
) -> Result<VerifiedEnclave, ApiError> {
    let quote = BASE64.decode(quote_b64).map_err(|e| {
        ApiError(StatusCode::BAD_REQUEST, format!("Invalid base64 quote: {e}"))
    })?;

    let collateral = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let client = CollateralClient::with_default_http(&state.pccs_url).map_err(|e| {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("PCCS client error: {e}"))
            })?;
            client.fetch(&quote).await.map_err(|e| {
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to fetch collateral: {e}"))
            })
        })
    })?;

    let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .as_secs();

    let policy = QuotePolicy::strict(now);
    let claims = QuoteVerifier::new_prod()
    .verify_with_policy(&quote, collateral, now, &policy)
    .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("Quote verification failed: {e}")))?;

    let report = claims
    .report
    .as_sgx()
    .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "Quote is not an SGX quote".into()))?;

    if report.mr_enclave.as_slice() != state.expected_mrenclave.as_slice()
        || report.mr_signer.as_slice() != state.expected_mrsigner.as_slice()
        {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "Unexpected enclave measurement or signer".into(),
            ));
        }

        let mut binding = enclave_public_key.as_bytes().to_vec();
    binding.extend_from_slice(&required_clearance_level.to_be_bytes());
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"dZTA_SGX_SESSION_v1");
    hasher.update(&binding);
    let expected_report_data = hasher.finalize();

    if report.report_data[..32] != expected_report_data[..] {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "Quote report data does not match requested session".into(),
        ));
    }

    Ok(VerifiedEnclave {
        quote,
       report_data: report.report_data.to_vec(),
       enclave_public_key: enclave_public_key.to_string(),
       mrenclave: hex::encode(report.mr_enclave),
       mrsigner: hex::encode(report.mr_signer),
    })
}

// ----------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------

pub async fn provision_datakey(
    State(state): State<AppState>, Json(request): Json<ProvisionDatakeyRequest>,
) -> Result<Json<ProvisioningDataKeyResponse>, ApiError> {
    if request.enclave_public_key.trim().is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "Enclave public key cannot be empty".into(),
        ));
    }

    let engine = state
    .datakey_engine
    .as_ref()
    .ok_or_else(|| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Datakey engine not initialized".into()))?;

    // 1. Provision the primary Wallet DEK
    let wallet_provision = engine
    .provision_datakey(&request.enclave_public_key)
    .await?;

    // 2. Generate 32 bytes of cryptographic entropy for the ZKP Master Seed from Vault
    let raw_master_seed: Vec<u8> = engine
    .generate_vault_random_seed()
    .await?
    .to_vec();

    // 3. Encrypt the master seed using Vault Transit for long-term storage
    let seed_ciphertext = engine
    .encrypt(&raw_master_seed)
    .await?;

    // 4. Wrap the raw master seed using the enclave's RSA public key
    let encrypted_master_seed_for_enclave = engine
    .wrap_bytes_for_enclave(&raw_master_seed, &request.enclave_public_key)?;

    Ok(Json(ProvisioningDataKeyResponse {
        wallet_ciphertext: wallet_provision.wallet_ciphertext,
        encrypted_wallet_key_for_enclave: wallet_provision.encrypted_wallet_key_for_enclave,
        seed_ciphertext,
        encrypted_master_seed_for_enclave,
    }))
}

pub async fn unwrap_datakey(
    State(state): State<AppState>,
                            Json(request): Json<UnwrapDatakeyRequest>,
) -> Result<Json<UnwrapDatakeyResponse>, ApiError> {
    if request.quote.trim().is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "Invalid or empty enclave quote".into(),
        ));
    }

    if request.wallet_ciphertext.trim().is_empty() || request.seed_ciphertext.trim().is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "Missing stored wallet or seed ciphertext".into(),
        ));
    }

    let engine = state
    .datakey_engine
    .as_ref()
    .ok_or_else(|| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Datakey engine not initialized".into()))?;

    // 1. Verify SGX Quote BEFORE unwrapping datakeys from Vault
    let enclave = verify_sgx_quote(
        &state,
        &request.quote,
        &request.enclave_public_key,
        request.required_clearance_level,
    )?;

    // 2. Unwrap Wallet DEK
    let encrypted_wallet_key = engine
    .unwrap_datakey_for_enclave(&request.wallet_ciphertext, &enclave.enclave_public_key)
    .await?;

    // 3. Unwrap ZKP Master Seed
    let encrypted_master_seed = engine
    .unwrap_datakey_for_enclave(&request.seed_ciphertext, &enclave.enclave_public_key)
    .await?;

    Ok(Json(UnwrapDatakeyResponse {
        encrypted_wallet_key_for_enclave: encrypted_wallet_key,
        encrypted_master_seed_for_enclave: encrypted_master_seed,
    }))
}

pub async fn release_key(
    State(state): State<AppState>,
                         Json(request): Json<ReleaseRequest>,
) -> Result<Json<WrappedEnclaveSecrets>, ApiError> {
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
    .await
    .map(Json)
    .map_err(ApiError::from)
}

// ----------------------------------------------------------------------------
// Datakey Sub-Router
// ----------------------------------------------------------------------------

pub fn router() -> Router<AppState> {
    Router::new()
    .route("/provision", post(provision_datakey))
    .route("/unwrap", post(unwrap_datakey))
    .route("/release", post(release_key))
}
