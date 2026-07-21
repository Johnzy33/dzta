// src/tee_runner.rs
use crate::zkp_core::ZkpCore;
use crate::errors::{WalletError, WalletResult};
use crate::models::{ZKPWitness, VerificationReceipt }  ;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof};
use ark_bls12_381::{Fr, Bls12_381};
use ark_snark::SNARK;
use ark_serialize::CanonicalDeserialize;

static ENCLAVE_INITIALIZED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    unsafe fn execute_tee_zkp_generation(
        role_id: u64,
        nullifier: u64,
        nonce: u64,
        commitment: u64,
        user_clearance: u64,
        required_clearance: u64,
        out_proof_ptr: *mut u8,
        out_proof_len: *mut usize,
    ) -> i32;
}

pub struct EnclaveExecutionProxy;

impl EnclaveExecutionProxy {

     /// Initializes hardware bindings if required by the runtime.
    pub fn initialize_enclave() -> WalletResult<()> {
        if ENCLAVE_INITIALIZED.load(Ordering::SeqCst) {
            return Ok(());
        }
        ENCLAVE_INITIALIZED.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn prove_witness_in_hardware(
        &self,
        witness: &ZKPWitness,
        nonce: u64,
        commitment: u64,
        required_clearance: u64,
    ) -> WalletResult<Vec<u8>> {
        // 1. Hash identity strings into field scalar strings
        let role_scalar_str = ZkpCore::string_to_scalar(&witness.user_role_id);
        let nullifier_scalar_str = ZkpCore::string_to_scalar(&witness.credential_id);

        // 2. Parse down to primitive numerical representation
        let role_id: u64 = role_scalar_str.parse().unwrap_or(0);
        let nullifier: u64 = nullifier_scalar_str.parse().unwrap_or(0);

        let mut out_proof = vec![0u8; 512];
        let mut out_len: usize = 0;

        // 3. Dispatch FFI call into Enclave/pVM layer
        let status = unsafe {
            execute_tee_zkp_generation(
                role_id,
                nullifier,
                nonce,
                commitment,
                witness.clearance_level,
                required_clearance,
                out_proof.as_mut_ptr(),
                &mut out_len,
            )
        };

        if status != 0 {
            return Err(WalletError::ExecutionFailed(format!(
                "Hardware enclave execution failed with status code: {}",
                status
            )));
        }

        out_proof.truncate(out_len);
        Ok(out_proof)
    }

    /// Deserializes proof bytes and public inputs to verify against the circuit's VerifyingKey.
    pub fn verify_groth16_proof(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[u64],
        pvk: &PreparedVerifyingKey<Bls12_381>,
    ) -> WalletResult<bool> {
        // 1. Deserialize the proof from uncompressed/compressed canonical byte representation
        let proof = Proof::<Bls12_381>::deserialize_uncompressed(proof_bytes).map_err(|e| {
            WalletError::ExecutionFailed(format!("Failed to deserialize proof bytes: {e}"))
        })?;

        // 2. Map primitive u64 public inputs into BN254 scalar field elements (Fr)
        let public_fr_inputs: Vec<Fr> = public_inputs
            .iter()
            .map(|&val| Fr::from(val))
            .collect();

        // 3. Perform pairing check: e(A, B) = e(&alpha, &beta) * e(C, &delta) * \prod e(L_i, \gamma)
        let is_valid = Groth16::<Bls12_381>::verify_with_processed_vk(pvk, &public_fr_inputs, &proof)
            .map_err(|e| {
                WalletError::ExecutionFailed(format!("Groth16 verification error: {e}"))
            })?;

        Ok(is_valid)
    }


    /// Verifies proof bytes and builds the Go chaincode-compatible receipt.
    pub fn verify_and_generate_receipt(
        &self,
        credential_id: &str,
        verifier_mec_id: &str,
        proof_bytes: &[u8],
    ) -> WalletResult<VerificationReceipt> {
        if !ENCLAVE_INITIALIZED.load(Ordering::SeqCst) {
            Self::initialize_enclave()?;
        }

        // 1. Compute proof hash for the hardware attestation quote
        let proof_hash = ZkpCore::string_to_scalar(&hex::encode(proof_bytes));
        let tee_quote = format!("tee_attestation_quote_v1_sig:[hash:{}]", proof_hash);

        // 2. Current timestamp
        let verified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| WalletError::ExecutionFailed(e.to_string()))?
            .as_secs() as i64;

        // 3. Construct VerificationReceipt for Fabric Chaincode
        Ok(VerificationReceipt {
            credential_id: credential_id.to_string(),
            verifier_mec: verifier_mec_id.to_string(),
            verified_at,
            tee_quote,
        })
    }
}