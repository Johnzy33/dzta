use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use log::debug;
use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::errors::WalletResult;
use crate::models::ZKPWitness;

const BLS12_381_SCALAR_FIELD_PRIME: &str =
    "52435875175126190479447740508185965837690552500527637822603658699938581184513";

/// Native Rust payload passed to the Arkworks Prover runner binary / execution layer
#[derive(Debug, Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct ProverInputPayload {
    pub user_clearance_level: u8,
    pub user_role_scalar: String,
    pub secret_nullifier: Vec<u8>,
    pub required_clearance_level: u8,
    pub public_commitment: Vec<u8>,
}

/// Dynamic proof and verification payload returned from prover execution
#[derive(Debug, Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct ProverOutputResponse {
    pub x_dzta_proof: String,
    pub x_dzta_public_inputs: String,
    pub sgx_dcap_quote_hex: Option<String>,
}

pub struct ZkpCore;

impl ZkpCore {
    // =========================================================================
    // 1. Arkworks / FastRoleVerification Pipeline
    // =========================================================================

    /// Computes public_commitment = (nullifier * clearance_level * role_scalar) mod r
    /// Directly satisfies Constraint: commitment == nullifier * user_clearance * role_scalar
    pub fn compute_commitment(
        nullifier_bytes: &[u8; 32],
        user_clearance: u8,
        role_scalar_str: &str,
    ) -> Vec<u8> {
        let nullifier_fr = Fr::from_le_bytes_mod_order(nullifier_bytes);
        let clearance_fr = Fr::from(user_clearance);

        let role_biguint = BigUint::from_str_radix(role_scalar_str, 10).unwrap_or_default();
        let role_fr = Fr::from_le_bytes_mod_order(&role_biguint.to_bytes_le());

        let commitment_fr = nullifier_fr * clearance_fr * role_fr;

        commitment_fr
            .into_bigint()
            .to_bytes_le()
            .to_vec()
    }

    /// Derives 32-byte nullifier deterministically from subject DID, Credential ID, and secret seed bytes
    pub fn derive_nullifier(
        subject_did: &str,
        credential_id: &str,
        secret_seed_bytes: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(subject_did.as_bytes());
        hasher.update(credential_id.as_bytes());
        hasher.update(secret_seed_bytes);
        hasher.finalize().into()
    }

    /// Compiles a `ZKPWitness` directly into a strongly-typed `ProverInputPayload`
    pub fn compile_prover_payload(
        witness: &ZKPWitness,
        required_clearance: u8,
        secret_seed_bytes: &[u8],
    ) -> ProverInputPayload {
        let nullifier = Self::derive_nullifier(
            &witness.subject_did,
            &witness.credential_id,
            secret_seed_bytes,
        );
        let user_clearance = witness.clearance_level as u8;
        let role_scalar = Self::string_to_scalar(&witness.user_role_id);
        let commitment = Self::compute_commitment(&nullifier, user_clearance, &role_scalar);

        ProverInputPayload {
            user_clearance_level: user_clearance,
            user_role_scalar: role_scalar,
            secret_nullifier: nullifier.to_vec(),
            required_clearance_level: required_clearance,
            public_commitment: commitment,
        }
    }

    /// JSON Value wrapper for dynamic JSON consumption layers
    pub fn compile_fast_prover_inputs(
        witness: &ZKPWitness,
        required_clearance: u8,
        secret_seed_bytes: &[u8],
    ) -> WalletResult<Value> {
        debug!("Compiling ZK witness into RoleVerification inputs");
        let payload = Self::compile_prover_payload(witness, required_clearance, secret_seed_bytes);
        Ok(serde_json::to_value(payload)?)
    }

    // =========================================================================
    // 2. Helper Utilities
    // =========================================================================

    /// Transforms any arbitrary UTF-8 string into a deterministic scalar string element.
    pub fn string_to_scalar(input: &str) -> String {
        if input.is_empty() {
            return "0".to_string();
        }

        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hash_result = hasher.finalize();

        let num = BigUint::from_bytes_be(&hash_result);
        let prime = BigUint::from_str_radix(BLS12_381_SCALAR_FIELD_PRIME, 10).unwrap();
        let scalar_field_element = num % prime;

        scalar_field_element.to_str_radix(10)
    }
}