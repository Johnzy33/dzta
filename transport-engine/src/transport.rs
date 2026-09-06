use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_ENVOY_URL: &str = "http://127.0.0.1:10000";
const DEFAULT_PROOF_HEADER: &str = "x-dzta-proof";
const DEFAULT_PUBLIC_INPUTS_HEADER: &str = "x-dzta-public-inputs";
const DEFAULT_REVOCATION_HEADER: &str = "x-dzta-revocation-id";

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("transport configuration is invalid: {0}")]
    Config(String),
    #[error("request was rejected by the gateway: status={status} body={body}")]
    Rejected { status: reqwest::StatusCode, body: String },
    #[error("proof payload is missing required data: {0}")]
    MissingData(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportConfig {
    pub envoy_url: String,
    pub timeout: Option<Duration>,
    #[serde(default = "default_proof_header")]
    pub proof_header: String,
    #[serde(default = "default_public_inputs_header")]
    pub public_inputs_header: String,
    #[serde(default = "default_revocation_header")]
    pub revocation_header: String,
    #[serde(default = "default_request_path")]
    pub request_path: String,
}

impl TransportConfig {
    pub fn new(envoy_url: impl Into<String>) -> Self {
        Self {
            envoy_url: envoy_url.into(),
            timeout: Some(Duration::from_secs(30)),
            proof_header: default_proof_header(),
            public_inputs_header: default_public_inputs_header(),
            revocation_header: default_revocation_header(),
            request_path: default_request_path(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn validated(&self) -> Result<(), TransportError> {
        let url = self.envoy_url.trim();
        if url.is_empty() {
            return Err(TransportError::Config(
                "envoy_url must not be empty".to_string(),
            ));
        }
        if self.proof_header.trim().is_empty() {
            return Err(TransportError::Config(
                "proof_header must not be empty".to_string(),
            ));
        }
        if self.public_inputs_header.trim().is_empty() {
            return Err(TransportError::Config(
                "public_inputs_header must not be empty".to_string(),
            ));
        }
        if self.revocation_header.trim().is_empty() {
            return Err(TransportError::Config(
                "revocation_header must not be empty".to_string(),
            ));
        }
        Ok(())
    }
}

fn default_proof_header() -> String {
    DEFAULT_PROOF_HEADER.to_string()
}

fn default_public_inputs_header() -> String {
    DEFAULT_PUBLIC_INPUTS_HEADER.to_string()
}

fn default_revocation_header() -> String {
    DEFAULT_REVOCATION_HEADER.to_string()
}

fn default_request_path() -> String {
    "/api/v1/resource".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    pub request_id: String,
    pub device_id: String,
    pub edge_id: String,
    pub action: String,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_inputs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_id: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl ProofRequest {
    pub fn new(action: impl Into<String>, device_id: impl Into<String>, edge_id: impl Into<String>) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            device_id: device_id.into(),
            edge_id: edge_id.into(),
            action: action.into(),
            payload: Value::Object(serde_json::Map::new()),
            proof: None,
            public_inputs: None,
            revocation_id: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }

    pub fn with_proof(mut self, proof: impl Into<String>, public_inputs: impl Into<String>) -> Self {
        self.proof = Some(proof.into());
        self.public_inputs = Some(public_inputs.into());
        self
    }

    pub fn with_revocation_id(mut self, revocation_id: impl Into<String>) -> Self {
        self.revocation_id = Some(revocation_id.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub request_id: String,
    pub device_id: String,
    pub edge_id: String,
    pub proof: String,
    pub public_inputs: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_id: Option<String>,
    pub status: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub collected_at: DateTime<Utc>,
}

impl ProofArtifact {
    pub fn new(
        request_id: impl Into<String>,
        device_id: impl Into<String>,
        edge_id: impl Into<String>,
        proof: impl Into<String>,
        public_inputs: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            device_id: device_id.into(),
            edge_id: edge_id.into(),
            proof: proof.into(),
            public_inputs: public_inputs.into(),
            revocation_id: None,
            status: "ready".to_string(),
            metadata: BTreeMap::new(),
            collected_at: Utc::now(),
        }
    }

    pub fn with_revocation_id(mut self, revocation_id: impl Into<String>) -> Self {
        self.revocation_id = Some(revocation_id.into());
        self
    }

    pub fn set_status(mut self, status: impl Into<String>) -> Self {
        self.status = status.into();
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct ProofEnvelope {
//     pub request_id: String,
//     pub status: String,
//     pub message: String,
//     #[serde(default)]
//     pub artifact: Option<ProofArtifact>,
//     pub submitted_at: DateTime<Utc>,
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEnvelope {
    #[serde(default = "default_request_id")]
    pub request_id: String,
    pub status: String,
    pub message: String,
    #[serde(default)]
    pub artifact: Option<ProofArtifact>,
    #[serde(default = "Utc::now")]
    pub submitted_at: DateTime<Utc>,
}

fn default_request_id() -> String {
    Uuid::new_v4().to_string()
}

#[derive(Debug, Clone, Default)]
pub struct HeaderBundle {
    pub proof: Option<String>,
    pub public_inputs: Option<String>,
    pub revocation_id: Option<String>,
}

impl HeaderBundle {
    pub fn with_proof(mut self, proof: impl Into<String>) -> Self {
        self.proof = Some(proof.into());
        self
    }

    pub fn with_public_inputs(mut self, public_inputs: impl Into<String>) -> Self {
        self.public_inputs = Some(public_inputs.into());
        self
    }

    pub fn with_revocation_id(mut self, revocation_id: impl Into<String>) -> Self {
        self.revocation_id = Some(revocation_id.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct TransportEngine {
    client: Client,
    config: TransportConfig,
}

impl TransportEngine {
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        config.validated()?;

        let client = match config.timeout {
            Some(timeout) => Client::builder().timeout(timeout).build()?,
            None => Client::new(),
        };

        Ok(Self { client, config })
    }

    pub fn default() -> Result<Self, TransportError> {
        Self::new(TransportConfig {
            envoy_url: DEFAULT_ENVOY_URL.to_string(),
            timeout: Some(Duration::from_secs(30)),
            proof_header: default_proof_header(),
            public_inputs_header: default_public_inputs_header(),
            revocation_header: default_revocation_header(),
            request_path: default_request_path(),
        })
    }

    pub fn proof_headers(&self, bundle: &HeaderBundle) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        if let Some(proof) = bundle.proof.as_ref().filter(|value| !value.trim().is_empty()) {
            headers.push((self.config.proof_header.clone(), proof.clone()));
        }

        if let Some(inputs) = bundle
            .public_inputs
            .as_ref()
            .filter(|value| !value.trim().is_empty())
        {
            headers.push((self.config.public_inputs_header.clone(), inputs.clone()));
        }

        if let Some(rev_id) = bundle
            .revocation_id
            .as_ref()
            .filter(|value| !value.trim().is_empty())
        {
            headers.push((self.config.revocation_header.clone(), rev_id.clone()));
        }

        headers
    }

    pub fn apply_headers(&self, request: RequestBuilder, bundle: &HeaderBundle) -> RequestBuilder {
        let mut request = request;
        for (header_name, header_value) in self.proof_headers(bundle) {
            request = request.header(header_name, header_value);
        }
        request
    }

    pub fn target_url(&self, path: Option<&str>) -> String {
        let env_url = self.config.envoy_url.trim();
        let path = path.unwrap_or(&self.config.request_path);

        if env_url.ends_with('/') && path.starts_with('/') {
            format!("{}{}", env_url.trim_end_matches('/'), path)
        } else if !env_url.ends_with('/') && !path.starts_with('/') {
            format!("{}/{}", env_url, path)
        } else {
            format!("{}{}", env_url, path)
        }
    }

    pub async fn submit_proof_request(
        &self,
        request: &ProofRequest,
    ) -> Result<ProofEnvelope, TransportError> {
        let bundle = HeaderBundle {
            proof: request.proof.clone(),
            public_inputs: request.public_inputs.clone(),
            revocation_id: request.revocation_id.clone(),
        };

        let response = self
            .apply_headers(
                self.client
                    .request(Method::POST, self.target_url(None))
                    .header("Content-Type", "application/json")
                    .header("X-DZTA-Request-Id", &request.request_id)
                    .header("X-DZTA-Device-Id", &request.device_id)
                    .header("X-DZTA-Edge-Id", &request.edge_id)
                    .header("X-DZTA-Action", &request.action),
                &bundle,
            )
            .json(request)
            .send()
            .await?;

        self.handle_response(response).await
    }

    pub async fn submit_proof_result(
        &self,
        artifact: &ProofArtifact,
    ) -> Result<ProofEnvelope, TransportError> {
        let bundle = HeaderBundle {
            proof: Some(artifact.proof.clone()),
            public_inputs: Some(artifact.public_inputs.clone()),
            revocation_id: artifact.revocation_id.clone(),
        };

        let response = self
            .apply_headers(
                self.client
                    .request(Method::POST, self.target_url(None))
                    .header("Content-Type", "application/json")
                    .header("X-DZTA-Request-Id", &artifact.request_id)
                    .header("X-DZTA-Device-Id", &artifact.device_id)
                    .header("X-DZTA-Edge-Id", &artifact.edge_id)
                    .header("X-DZTA-Status", &artifact.status),
                &bundle,
            )
            .json(artifact)
            .send()
            .await?;

        self.handle_response(response).await
    }

    pub async fn collect_proof(
        &self,
        request_id: &str,
    ) -> Result<ProofArtifact, TransportError> {
        let response = self
            .client
            .get(self.target_url(Some(&format!("/api/v1/resource/{}", request_id))))
            .header("X-DZTA-Request-Id", request_id)
            .send()
            .await?;

        let payload: ProofArtifact = self.parse_json(response).await?;
        Ok(payload)
    }

    pub async fn request_proof(
        &self,
        device_id: impl Into<String>,
        edge_id: impl Into<String>,
        action: impl Into<String>,
        payload: Value,
    ) -> Result<ProofEnvelope, TransportError> {
        let request = ProofRequest {
            request_id: Uuid::new_v4().to_string(),
            device_id: device_id.into(),
            edge_id: edge_id.into(),
            action: action.into(),
            payload,
            proof: None,
            public_inputs: None,
            revocation_id: None,
            metadata: BTreeMap::new(),
        };

        self.submit_proof_request(&request).await
    }

    async fn handle_response(&self, response: Response) -> Result<ProofEnvelope, TransportError> {
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_else(|_| "failed to read body".to_string());
            return Err(TransportError::Rejected { status, body });
        }

        let payload: ProofEnvelope = self.parse_json(response).await?;
        Ok(payload)
    }

    async fn parse_json<T>(&self, response: Response) -> Result<T, TransportError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let body = response.text().await.map_err(|err| {
            TransportError::Serialization(format!("failed to read gateway response: {err}"))
        })?;

        serde_json::from_str(&body).map_err(|err| {
            TransportError::Serialization(format!("failed to decode gateway response: {err}; body={body}"))
        })
    }

    pub fn encode_proof_for_headers(proof: &[u8]) -> String {
        BASE64.encode(proof)
    }

    pub fn encode_public_inputs_for_headers(public_inputs: &[u8]) -> String {
        BASE64.encode(public_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proof_headers_are_injected_for_valid_payloads() {
        let engine = TransportEngine::default().expect("default transport should be valid");
        let bundle = HeaderBundle::default()
            .with_proof("proof-base64")
            .with_public_inputs("inputs-base64");

        let headers = engine.proof_headers(&bundle);
        assert_eq!(headers.len(), 2);
        assert!(headers.iter().any(|(name, value)| name == "x-dzta-proof" && value == "proof-base64"));
        assert!(headers.iter().any(|(name, value)| name == "x-dzta-public-inputs" && value == "inputs-base64"));
    }

    #[test]
    fn target_url_builds_envoy_endpoint() {
        let engine = TransportEngine::default().expect("default transport should be valid");
        assert_eq!(
            engine.target_url(None),
            "http://127.0.0.1:10000/api/v1/resource"
        );
        assert_eq!(
            engine.target_url(Some("/api/v1/resource")),
            "http://127.0.0.1:10000/api/v1/resource"
        );
    }

    #[test]
    fn proof_request_builds_valid_serializable_payload() {
        let request = ProofRequest::new("verify", "device-1", "edge-1")
            .with_payload(json!({ "challenge": "abc" }))
            .with_proof("proof", "public-inputs");

        let json = serde_json::to_value(&request).expect("serialization should succeed");
        assert_eq!(json["device_id"], "device-1");
        assert_eq!(json["edge_id"], "edge-1");
        assert_eq!(json["proof"], "proof");
        assert_eq!(json["public_inputs"], "public-inputs");
    }
}
