// dzta-attestation-broker/src/routes/mod.rs
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

use crate::VaultDatakeyEngine;

// ----------------------------------------------------------------------------
// Shared App State
// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub datakey_engine: Arc<VaultDatakeyEngine>,
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

/// Assembles all sub-routers under their respective API prefixes.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Nests datakey endpoints under /v1/datakey
        .nest("/v1/datakey", datakey::router())
        // Future endpoints can easily be added here:
        // .nest("/v1/attestation", attestation::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}