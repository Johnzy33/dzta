
pub mod datakey;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::error;

use crate::{SecretProvider, VaultDatakeyEngine};

// ----------------------------------------------------------------------------
// Unified App State
// ----------------------------------------------------------------------------



#[derive(Clone)]
pub struct AppState {
    pub pccs_url: String,
    pub expected_mrenclave: Vec<u8>,
    pub expected_mrsigner: Vec<u8>,

    /// Policy-gated secret release backend (Vault or HTTP KMS)
    pub kms: Arc<dyn SecretProvider>,

    /// Wallet DEK and ZKP Seed generator (Vault Transit)
    pub datakey_engine: Option<Arc<VaultDatakeyEngine>>,
}
// ----------------------------------------------------------------------------
// Shared Error Adapters
// ----------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse { error: self.1 });
        (self.0, body).into_response()
    }
}

impl From<crate::BrokerError> for ApiError {
    fn from(err: crate::BrokerError) -> Self {
        error!(error = %err, "Broker internal failure");
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            err.to_string(),
        )
    }
}

// ----------------------------------------------------------------------------
// Master Router Builder
// ----------------------------------------------------------------------------

pub fn create_router(state: AppState) -> Router {
    Router::new()
    .nest("/v1/datakey", datakey::router())
    .layer(TraceLayer::new_for_http())
    .with_state(state)
}
