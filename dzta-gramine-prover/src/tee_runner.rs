use std::time::{SystemTime, UNIX_EPOCH};

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use sha2::{Digest, Sha256};

use shared::errors::{WalletError, WalletResult};
use shared::models::{VerificationReceipt, ZKPWitness};
use shared::zkp_core::{ProverOutputResponse, ZkpCore};

use crate::runner::{ExecutionMode, GramineProverRunner};

pub struct GramineExecutionProxy {
    runner: GramineProverRunner,
}

impl GramineExecutionProxy {
    pub fn new(target_path: &str, mode: ExecutionMode) -> Self {
        Self {
            runner: GramineProverRunner::new(target_path, mode),
        }
    }

    /// Compiles witness parameters via ZkpCore, dispatches execution to Gramine, and returns envelope response
    pub fn prove_witness_in_gramine(
        &self,
        witness: &ZKPWitness,
        required_clearance: u8,
        secret_seed: &[u8],
    ) -> WalletResult<ProverOutputResponse> {
        // Delegate payload compilation to ZkpCore
        let payload = ZkpCore::compile_prover_payload(witness, required_clearance, secret_seed);

        // Execute via GramineProverRunner
        self.runner.execute_proof(&payload).map_err(|e| {
            WalletError::ExecutionFailed(format!("Gramine proof execution failed: {e:#}"))
        })
    }

    /// Verifies raw Groth16 proof bytes against prepared verifying key
    pub fn verify_groth16_proof(
        &self,
        proof_bytes: &[u8],
        required_clearance: u64,
        public_commitment: Fr,
        pvk: &PreparedVerifyingKey<Bls12_381>,
    ) -> WalletResult<bool> {
        let proof = Proof::<Bls12_381>::deserialize_compressed(proof_bytes)
            .or_else(|_| Proof::<Bls12_381>::deserialize_uncompressed(proof_bytes))
            .map_err(|e| WalletError::ExecutionFailed(format!("Failed to deserialize proof: {e}")))?;

        let public_fr_inputs: Vec<Fr> = vec![
            Fr::from(required_clearance),
            public_commitment,
        ];

        Groth16::<Bls12_381>::verify_with_processed_vk(pvk, &public_fr_inputs, &proof)
            .map_err(|e| WalletError::ExecutionFailed(format!("Groth16 verification error: {e}")))
    }

    /// Constructs the Fabric chaincode receipt from Gramine response
    pub fn build_verification_receipt(
        &self,
        credential_id: &str,
        verifier_mec_id: &str,
        response: &ProverOutputResponse,
    ) -> WalletResult<VerificationReceipt> {
        let verified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| WalletError::ExecutionFailed(e.to_string()))?
            .as_secs() as i64;

        // Extract real DCAP quote if available, otherwise construct a deterministic simulated quote
        let tee_quote = match &response.sgx_dcap_quote_hex {
            Some(quote) if !quote.is_empty() => quote.clone(),
            _ => {
                // Compute SHA-256 digest over proof & public inputs to prevent receipt replay
                let mut hasher = Sha256::new();
                hasher.update(response.x_dzta_proof.as_bytes());
                hasher.update(response.x_dzta_public_inputs.as_bytes());
                let digest_hex = hex::encode(hasher.finalize());

                format!("simulated_dcap_quote_v1:[proof_hash:{digest_hex}]")
            }
        };

        Ok(VerificationReceipt {
            credential_id: credential_id.to_string(),
            verifier_mec: verifier_mec_id.to_string(),
            verified_at,
            tee_quote,
        })
    }
}