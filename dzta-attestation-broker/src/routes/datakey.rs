//dzta-attestation-broker/src/routes/datakey.rs
use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use shared::vault_client::{VaultSeed, VaultEncryptor};

use crate::{
    routes::{ApiError, AppState},
    ProvisioningDataKeyResponse,
};

// ----------------------------------------------------------------------------
// Data Transfer Objects (DTOs)
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
pub struct ProvisionDatakeyRequest {
    pub enclave_public_key: String,
}

// #[derive(Debug, Deserialize, Serialize)]
// pub struct UnwrapDatakeyRequest {
//     pub quote: String,
//     pub enclave_public_key: String,
//     pub required_clearance_level: u64,
//     pub stored_ciphertext: String,
// }

#[derive(Debug, Deserialize, Serialize)]
pub struct UnwrapDatakeyRequest {
    pub quote: String,
    pub enclave_public_key: String,
    pub required_clearance_level: u64,
    pub wallet_ciphertext: String,
    pub seed_ciphertext: String,
}

// #[derive(Debug, Serialize, Deserialize)]
// pub struct UnwrapDatakeyResponse {
//     pub encrypted_datakey_for_enclave: String,
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct UnwrapDatakeyResponse {
    pub encrypted_wallet_key_for_enclave: String,
    pub encrypted_master_seed_for_enclave: String,
}


// ----------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------

// pub async fn provision_datakey(
//     State(state): State<AppState>,
//     Json(request): Json<ProvisionDatakeyRequest>,
// ) -> Result<Json<ProvisioningDataKeyResponse>, ApiError> {
//     if request.enclave_public_key.trim().is_empty() {
//         return Err(ApiError(
//             StatusCode::BAD_REQUEST,
//             "Enclave public key cannot be empty".into(),
//         ));
//     }

//     let response = state
//         .datakey_engine
//         .provision_datakey(&request.enclave_public_key)
//         .await?;

//     Ok(Json(response))
// }

pub async fn provision_datakey(
    State(state): State<AppState>,
    Json(request): Json<ProvisionDatakeyRequest>,
) -> Result<Json<ProvisioningDataKeyResponse>, ApiError> {
    if request.enclave_public_key.trim().is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "Enclave public key cannot be empty".into(),
        ));
    }

    // 1. Provision the primary Wallet DEK
    let wallet_provision = state
        .datakey_engine
        .provision_datakey(&request.enclave_public_key)
        .await?;

    // 2. Generate 32 bytes of cryptographic entropy for the ZKP Master Seed from Vault
    let raw_master_seed: Vec<u8> = state
        .datakey_engine
        .generate_vault_random_seed()
        .await?
        .to_vec();

    // 3. Encrypt the master seed using Vault Transit for long-term storage
    let seed_ciphertext = state
        .datakey_engine
        .encrypt(&raw_master_seed)
        .await?;

    // 4. Wrap the raw master seed using the enclave's RSA public key
    let encrypted_master_seed_for_enclave = state
        .datakey_engine
        .wrap_bytes_for_enclave(&raw_master_seed, &request.enclave_public_key)?;

    Ok(Json(ProvisioningDataKeyResponse {
        wallet_ciphertext: wallet_provision.wallet_ciphertext,
        encrypted_wallet_key_for_enclave: wallet_provision.encrypted_wallet_key_for_enclave,
        seed_ciphertext,
        encrypted_master_seed_for_enclave,
    }))
}

// pub async fn unwrap_datakey(
//     State(state): State<AppState>,
//     Json(request): Json<UnwrapDatakeyRequest>,
// ) -> Result<Json<UnwrapDatakeyResponse>, ApiError> {
//     if request.quote.trim().is_empty() {
//         return Err(ApiError(
//             StatusCode::BAD_REQUEST,
//             "Invalid or empty enclave quote".into(),
//         ));
//     }

//     if request.stored_ciphertext.trim().is_empty() {
//         return Err(ApiError(
//             StatusCode::BAD_REQUEST,
//             "Missing stored ciphertext".into(),
//         ));
//     }

//     let encrypted_dek = state
//         .datakey_engine
//         .unwrap_datakey_for_enclave(&request.stored_ciphertext, &request.enclave_public_key)
//         .await?;

//     Ok(Json(UnwrapDatakeyResponse {
//         encrypted_datakey_for_enclave: encrypted_dek,
//     }))
// }


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

    // Note: SGX Attestation Quote verification can be invoked here via state or middleware

    // Unwrap Wallet DEK
    let encrypted_wallet_key = state
        .datakey_engine
        .unwrap_datakey_for_enclave(&request.wallet_ciphertext, &request.enclave_public_key)
        .await?;

    // Unwrap ZKP Master Seed
    let encrypted_master_seed = state
        .datakey_engine
        .unwrap_datakey_for_enclave(&request.seed_ciphertext, &request.enclave_public_key)
        .await?;

    Ok(Json(UnwrapDatakeyResponse {
        encrypted_wallet_key_for_enclave: encrypted_wallet_key,
        encrypted_master_seed_for_enclave: encrypted_master_seed,
    }))
}

// ----------------------------------------------------------------------------
// Datakey Sub-Router
// ----------------------------------------------------------------------------

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/provision", post(provision_datakey))
        .route("/unwrap", post(unwrap_datakey))
}