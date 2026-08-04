use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::sync::Arc;

proxy_wasm::main!({{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| Box::new(ZkpAuthzRoot::default()));
}});

struct ZkpAuthzRoot {
    pvk: Option<Arc<PreparedVerifyingKey<Bls12_381>>>,
}

impl Default for ZkpAuthzRoot {
    fn default() -> Self {
        Self { pvk: None }
    }
}

impl Context for ZkpAuthzRoot {}

impl RootContext for ZkpAuthzRoot {
    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        // Embedded Verification Key bytes (BLS12-381 Groth16 VK)
        let vk_bytes: &[u8] = include_bytes!("../keys/edge_verification_key.bin");

        match VerifyingKey::<Bls12_381>::deserialize_compressed(vk_bytes) {
            Ok(vk) => {
                let pvk = ark_groth16::prepare_verifying_key(&vk);
                self.pvk = Some(Arc::new(pvk));
                log::info!("Layer 4 Wasm: Groth16 Verification Key successfully loaded and prepared.");
                true
            }
            Err(e) => {
                log::error!("Layer 4 Wasm: Failed to deserialize Verification Key: {:?}", e);
                false
            }
        }
    }

    // Fixed signature: &self (immutable) and returns Option<Box<dyn HttpContext>>
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(ZkpAuthzHttp {
            pvk: self.pvk.clone(),
        }))
    }
}

struct ZkpAuthzHttp {
    pvk: Option<Arc<PreparedVerifyingKey<Bls12_381>>>,
}

impl Context for ZkpAuthzHttp {}

impl HttpContext for ZkpAuthzHttp {
    // Fixed signature: added missing `_end_of_stream: bool` parameter
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let pvk = match &self.pvk {
            Some(p) => p,
            None => {
                log::error!("Wasm context missing prepared verification key");
                self.send_http_response(500, vec![], Some(b"Internal Server Error: Missing VK\n"));
                return Action::Pause;
            }
        };

        // Extract header attributes
        let proof_header = self.get_http_request_header("x-dzta-proof");
        let inputs_header = self.get_http_request_header("x-dzta-public-inputs");
        let rev_status_header = self.get_http_request_header("x-dzta-revocation-id");

        if proof_header.is_none() || inputs_header.is_none() {
            log::warn!("Access Denied: Missing dZTA proof headers");
            self.send_http_response(401, vec![], Some(b"Unauthorized: Missing dZTA ZKP Headers\n"));
            return Action::Pause;
        }

        let proof_raw = proof_header.unwrap();
        let inputs_raw = inputs_header.unwrap();

        // 1. Verify Groth16 ZK Proof
        match self.verify_zkp(pvk, &proof_raw, &inputs_raw) {
            Ok(true) => log::debug!("Groth16 ZK Proof successfully validated."),
            Ok(false) => {
                log::warn!("Access Denied: Invalid Groth16 ZK Proof");
                self.send_http_response(403, vec![], Some(b"Forbidden: Invalid ZK Proof\n"));
                return Action::Pause;
            }
            Err(e) => {
                log::error!("ZKP Verification Error: {}", e);
                self.send_http_response(400, vec![], Some(b"Bad Request: Malformed ZKP Data\n"));
                return Action::Pause;
            }
        }

        // 2. Perform edge revocation check if credential ID header is present
        if let Some(rev_id) = rev_status_header {
            if self.is_revoked(&rev_id) {
                log::warn!("Access Denied: Credential ID {} has been revoked", rev_id);
                self.send_http_response(403, vec![], Some(b"Forbidden: Credential Revoked\n"));
                return Action::Pause;
            }
        }

        // Allow traffic to downstream application microservices
        Action::Continue
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

    fn is_revoked(&self, revocation_id: &str) -> bool {
        let path = format!("revoked.{}", revocation_id);
        if let Some(val) = self.get_property(vec!["runtime", &path]) {
            return val == b"true";
        }
        false
    }
}