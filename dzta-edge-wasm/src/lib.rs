use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::sync::OnceLock;

const VK_BYTES: &[u8] = include_bytes!("../keys/edge_verification_key.bin");
static PVK: OnceLock<Option<PreparedVerifyingKey<Bls12_381>>> = OnceLock::new();

fn get_pvk() -> Option<&'static PreparedVerifyingKey<Bls12_381>> {
    PVK.get_or_init(|| {
        match VerifyingKey::<Bls12_381>::deserialize_compressed(VK_BYTES) {
            Ok(vk) => Some(ark_groth16::prepare_verifying_key(&vk)),
            Err(e) => {
                log::error!("Layer 4 Wasm: Failed to deserialize VK: {:?}", e);
                None
            }
        }
    })
    .as_ref()
}

#[derive(Deserialize, Debug, Clone, Default)]
struct PluginConfig {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    admin_token: String,
}

proxy_wasm::main!({
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| Box::new(ZkpAuthzRoot {
        config: PluginConfig::default(),
    }));
});

struct ZkpAuthzRoot {
    config: PluginConfig,
}

impl Context for ZkpAuthzRoot {}

impl RootContext for ZkpAuthzRoot {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            if let Ok(parsed) = serde_json::from_slice::<PluginConfig>(&config_bytes) {
                log::info!("Layer 4 Wasm: Context initialized with mode = '{}'", parsed.mode);
                self.config = parsed;
                return true;
            }
        }
        log::warn!("Layer 4 Wasm: Defaulting to validate_only configuration.");
        true
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(ZkpAuthzHttp {
            context_id,
            config: self.config.clone(),
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct ZkpAuthzHttp {
    context_id: u32,
    config: PluginConfig,
}

impl Context for ZkpAuthzHttp {}

impl HttpContext for ZkpAuthzHttp {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let path = self.get_http_request_header(":path").unwrap_or_default();

        // ---------------------------------------------------------------------
        // 1. ADMIN INGESTION INTERCEPTOR
        // ---------------------------------------------------------------------
        if path.starts_with("/_wasm_admin/revoke") {
            // Guard 1: Verify mode permission
            if self.config.mode != "admin_enabled" {
                log::warn!("Security Violation: Revocation attempt on unauthorized listener.");
                self.send_http_response(403, vec![], Some(b"Forbidden: Admin endpoint disabled\n"));
                return Action::Pause;
            }

            // Guard 2: Verify Administrative Token
            let provided_token = self.get_http_request_header("X-Wasm-Admin-Token").unwrap_or_default();
            if provided_token.is_empty() || provided_token != self.config.admin_token {
                log::warn!("Security Violation: Invalid or missing X-Wasm-Admin-Token header.");
                self.send_http_response(401, vec![], Some(b"Unauthorized: Invalid Admin Token\n"));
                return Action::Pause;
            }

            // Extract target ID from query param (e.g. /_wasm_admin/revoke?id=<UUID>)
            let target_id = path
                .split('?')
                .nth(1)
                .and_then(|query| {
                    query.split('&').find_map(|pair| {
                        let mut parts = pair.split('=');
                        if parts.next() == Some("id") {
                            parts.next()
                        } else {
                            None
                        }
                    })
                });

            let id = match target_id {
                Some(val) if !val.is_empty() => val,
                _ => {
                    self.send_http_response(400, vec![], Some(b"Bad Request: Missing 'id' parameter\n"));
                    return Action::Pause;
                }
            };

            // Store in global Wasm Shared Data Store
            let key = format!("revoked.{}", id);
            match self.set_shared_data(&key, Some(b"true"), None) {
                Ok(_) => {
                    log::info!("Successfully stored revocation in Wasm SharedData: Key = {}", key);
                    self.send_http_response(200, vec![], Some(b"OK: Credential Revocation Recorded\n"));
                }
                Err(e) => {
                    log::error!("Failed to set SharedData for key {}: {:?}", key, e);
                    self.send_http_response(500, vec![], Some(b"Internal Error: Storage Failure\n"));
                }
            }
            return Action::Pause;
        }

        // ---------------------------------------------------------------------
        // 2. PUBLIC TRAFFIC GATEKEEPER VALIDATION
        // ---------------------------------------------------------------------
        let pvk = match get_pvk() {
            Some(p) => p,
            None => {
                self.send_http_response(500, vec![], Some(b"Internal Error: Missing VK\n"));
                return Action::Pause;
            }
        };

        let proof_header = self.get_http_request_header("x-dzta-proof");
        let inputs_header = self.get_http_request_header("x-dzta-public-inputs");
        let rev_status_header = self.get_http_request_header("x-dzta-revocation-id");

        if proof_header.is_none() || inputs_header.is_none() || rev_status_header.is_none() {
            self.send_http_response(401, vec![], Some(b"Unauthorized: Missing dZTA Headers\n"));
            return Action::Pause;
        }

        let rev_id = rev_status_header.unwrap();

        // Query global Shared Data Store for Revocation State
        // let shared_key = format!("revoked.{}", rev_id);
        // if let Ok((Some(val), _cas)) = self.get_shared_data(&shared_key) {
        //     if val == b"true" {
        //         log::warn!("Access Denied: Credential ID {} is marked REVOKED in SharedData", rev_id);
        //         self.send_http_response(403, vec![], Some(b"Access Revoked\n"));
        //         return Action::Pause;
        //     }
        // }
        let shared_key = format!("revoked.{}", rev_id);
        if let (Some(val), _cas) = self.get_shared_data(&shared_key) {
            if val == b"true" {
                log::warn!("Access Denied: Credential ID {} is marked REVOKED in SharedData", rev_id);
                self.send_http_response(403, vec![], Some(b"Access Revoked\n"));
                return Action::Pause;
            }
        }

        // Validate Groth16 ZK Proof mathematically
        match self.verify_zkp(pvk, &proof_header.unwrap(), &inputs_header.unwrap()) {
            Ok(true) => Action::Continue,
            Ok(false) => {
                self.send_http_response(403, vec![], Some(b"Forbidden: Invalid ZK Proof\n"));
                Action::Pause
            }
            Err(e) => {
                log::error!("ZKP Verification Error: {}", e);
                self.send_http_response(400, vec![], Some(b"Bad Request: Malformed ZKP Data\n"));
                Action::Pause
            }
        }
    }
}

impl ZkpAuthzHttp {
    fn verify_zkp(
        &self,
        pvk: &PreparedVerifyingKey<Bls12_381>,
        proof_b64: &str,
        inputs_b64: &str,
    ) -> Result<bool, String> {
        let proof_bytes = BASE64
            .decode(proof_b64)
            .map_err(|e| format!("Base64 proof decode error: {}", e))?;
        let inputs_bytes = BASE64
            .decode(inputs_b64)
            .map_err(|e| format!("Base64 public inputs decode error: {}", e))?;

        let proof = Proof::<Bls12_381>::deserialize_compressed(&proof_bytes[..])
            .map_err(|e| format!("Proof deserialization error: {:?}", e))?;

        let public_inputs = Vec::<Fr>::deserialize_compressed(&inputs_bytes[..])
            .map_err(|e| format!("Inputs deserialization error: {:?}", e))?;

        Groth16::<Bls12_381>::verify_proof(pvk, &proof, &public_inputs)
            .map_err(|e| format!("Verification algorithm error: {:?}", e))
    }
}