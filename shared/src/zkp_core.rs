// //shared/src/zkp_core.rs
// use ark_bls12_381::Fr;
// use ark_ff::{BigInteger, PrimeField};
// use log::debug;
// use num_bigint::BigUint;
// use num_traits::Num;
// use serde::{Deserialize, Serialize};
// use serde_json::Value;
// use sha2::{Digest, Sha256};
// use zeroize::Zeroize;

// use crate::errors::WalletResult;
// use crate::models::ZKPWitness;

// const BLS12_381_SCALAR_FIELD_PRIME: &str =
//     "52435875175126190479447740508185965837690552500527637822603658699938581184513";

// /// Native Rust payload passed to the Arkworks Prover runner binary / execution layer
// #[derive(Debug, Deserialize, Serialize, Zeroize)]
// #[zeroize(drop)]
// pub struct ProverInputPayload {
//     pub user_clearance_level: u8,
//     pub user_role_scalar: String,
//     pub secret_nullifier: Vec<u8>,
//     pub required_clearance_level: u8,
//     pub public_commitment: Vec<u8>,
// }

// /// Dynamic proof and verification payload returned from prover execution
// #[derive(Debug, Deserialize, Serialize, Zeroize)]
// #[zeroize(drop)]
// pub struct ProverOutputResponse {
//     pub x_dzta_proof: String,
//     pub x_dzta_public_inputs: String,
//     pub sgx_dcap_quote_hex: Option<String>,
// }

// pub struct ZkpCore;

// impl ZkpCore {
//     // =========================================================================
//     // 1. Arkworks / FastRoleVerification Pipeline
//     // =========================================================================

//     /// Computes public_commitment = (nullifier * clearance_level * role_scalar) mod r
//     /// Directly satisfies Constraint: commitment == nullifier * user_clearance * role_scalar
//     pub fn compute_commitment(
//         nullifier_bytes: &[u8; 32],
//         user_clearance: u8,
//         role_scalar_str: &str,
//     ) -> Vec<u8> {
//         let nullifier_fr = Fr::from_le_bytes_mod_order(nullifier_bytes);
//         let clearance_fr = Fr::from(user_clearance);

//         let role_biguint = BigUint::from_str_radix(role_scalar_str, 10).unwrap_or_default();
//         let role_fr = Fr::from_le_bytes_mod_order(&role_biguint.to_bytes_le());

//         let commitment_fr = nullifier_fr * clearance_fr * role_fr;

//         commitment_fr
//             .into_bigint()
//             .to_bytes_le()
//             .to_vec()
//     }

//     /// Derives 32-byte nullifier deterministically from subject DID, Credential ID, and secret seed bytes
//     pub fn derive_nullifier(
//         subject_did: &str,
//         credential_id: &str,
//         secret_seed_bytes: &[u8],
//     ) -> [u8; 32] {
//         let mut hasher = Sha256::new();
//         hasher.update(subject_did.as_bytes());
//         hasher.update(credential_id.as_bytes());
//         hasher.update(secret_seed_bytes);
//         hasher.finalize().into()
//     }

//     /// Compiles a `ZKPWitness` directly into a strongly-typed `ProverInputPayload`
//     pub fn compile_prover_payload(
//         witness: &ZKPWitness,
//         required_clearance: u8,
//         secret_seed_bytes: &[u8],
//     ) -> ProverInputPayload {
//         let nullifier = Self::derive_nullifier(
//             &witness.subject_did,
//             &witness.credential_id,
//             secret_seed_bytes,
//         );
//         let user_clearance = witness.clearance_level as u8;
//         let role_scalar = Self::string_to_scalar(&witness.user_role_id);
//         let commitment = Self::compute_commitment(&nullifier, user_clearance, &role_scalar);

//         ProverInputPayload {
//             user_clearance_level: user_clearance,
//             user_role_scalar: role_scalar,
//             secret_nullifier: nullifier.to_vec(),
//             required_clearance_level: required_clearance,
//             public_commitment: commitment,
//         }
//     }

//     /// JSON Value wrapper for dynamic JSON consumption layers
//     pub fn compile_fast_prover_inputs(
//         witness: &ZKPWitness,
//         required_clearance: u8,
//         secret_seed_bytes: &[u8],
//     ) -> WalletResult<Value> {
//         debug!("Compiling ZK witness into RoleVerification inputs");
//         let payload = Self::compile_prover_payload(witness, required_clearance, secret_seed_bytes);
//         Ok(serde_json::to_value(payload)?)
//     }

//     // =========================================================================
//     // 2. Helper Utilities
//     // =========================================================================

//     /// Transforms any arbitrary UTF-8 string into a deterministic scalar string element.
//     pub fn string_to_scalar(input: &str) -> String {
//         if input.is_empty() {
//             return "0".to_string();
//         }

//         let mut hasher = Sha256::new();
//         hasher.update(input.as_bytes());
//         let hash_result = hasher.finalize();

//         let num = BigUint::from_bytes_be(&hash_result);
//         let prime = BigUint::from_str_radix(BLS12_381_SCALAR_FIELD_PRIME, 10).unwrap();
//         let scalar_field_element = num % prime;

//         scalar_field_element.to_str_radix(10)
//     }
// }


// shared/src/zkp_core.rs
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{WalletError, WalletResult};

const BLS12_381_SCALAR_FIELD_PRIME: &str =
    "52435875175126190479447740508185965837690552500527637822603658699938581184513";

/// Payload passed Host OS -> Gramine SGX Enclave via stdin.
/// Contains ONLY raw encrypted wallet records and key material.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EnclaveIngestionPayload {
    /// Raw encrypted store record as retrieved directly from Askar/SQLite storage on disk
    pub raw_wallet_ciphertext: Vec<u8>,
    /// Master key/passphrase used to decrypt the Askar storage record
    pub wallet_db_key: Vec<u8>,
    /// Required clearance level demanded by the verifier (Public Input)
    pub required_clearance_level: u64,
    /// Holder's master seed for single-use nullifier derivation
    pub master_seed: [u8; 32],
}

/// Credential payload structure parsed strictly inside enclave RAM
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DecryptedCredentialSubject {
    pub user_clearance_level: u64,
    pub user_role_scalar: String,
    pub subject_did: String,
    pub credential_id: String,
}

/// In-enclave structure containing derived scalar parameters ready for R1CS circuit ingestion
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct DerivedEnclaveWitness {
    pub clearance_level: u64,
    pub user_role_scalar: String,
    pub secret_nullifier: [u8; 32],
    pub public_commitment: Vec<u8>,
}

/// Dynamic proof and verification payload returned from prover execution
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProverOutputResponse {
    pub x_dzta_proof: String,
    pub x_dzta_public_inputs: String,
    pub sgx_dcap_quote_hex: Option<String>,
}

pub struct ZkpCore;

impl ZkpCore {
    // =========================================================================
    // 1. In-Enclave Witness Derivation & Unsealing
    // =========================================================================

    /// Unseals raw wallet record using DB key inside TEE RAM, parses the credential subject,
    /// and derives all ZKP witness parameters without exposing cleartext to Host OS.
    // pub fn unseal_and_derive_witness(
    //     raw_ciphertext: &[u8],
    //     db_key: &[u8],
    //     master_seed: &[u8; 32],
    // ) -> WalletResult<DerivedEnclaveWitness> {
    //     // Unseal/decrypt the payload. Handles raw JSON fallback or key-derived unsealing.
    //     let cleartext_bytes = if db_key.is_empty() {
    //         raw_ciphertext.to_vec()
    //     } else {
    //         // Decrypt raw ciphertext via XOR stream/AEAD key envelope (or JSON fallback if unencrypted envelope)
    //         serde_json::from_slice::<DecryptedCredentialSubject>(raw_ciphertext)
    //             .map(|_| raw_ciphertext.to_vec())
    //             .unwrap_or_else(|_| {
    //                 raw_ciphertext
    //                     .iter()
    //                     .zip(db_key.iter().cycle())
    //                     .map(|(&c, &k)| c ^ k)
    //                     .collect()
    //             })
    //     };

    //     let subject: DecryptedCredentialSubject = serde_json::from_slice(&cleartext_bytes)
    //         .map_err(|e| WalletError::ExecutionFailed(format!("Failed to parse unsealed credential subject: {e}")))?;

    //     let secret_nullifier = Self::derive_nullifier(
    //         &subject.subject_did,
    //         &subject.credential_id,
    //         master_seed,
    //     );

    //     let public_commitment = Self::compute_commitment(
    //         &secret_nullifier,
    //         subject.user_clearance_level,
    //         &subject.user_role_scalar,
    //     );

    //     Ok(DerivedEnclaveWitness {
    //         clearance_level: subject.user_clearance_level,
    //         user_role_scalar: subject.user_role_scalar.clone(),
    //         secret_nullifier,
    //         public_commitment,
    //     })
    // }

    pub fn unseal_and_derive_witness(
        raw_ciphertext: &[u8],
        db_key: &[u8],
        master_seed: &[u8; 32],
    ) -> WalletResult<DerivedEnclaveWitness> {
        // Step 1: Decrypt if key is provided; otherwise treat as plaintext
        let cleartext_bytes = if db_key.is_empty() {
            // No key → raw_ciphertext is already plaintext JSON
            raw_ciphertext.to_vec()
        } else {
            // Key provided → raw_ciphertext is XOR-encrypted; decrypt it
            raw_ciphertext
                .iter()
                .zip(db_key.iter().cycle())
                .map(|(&c, &k)| c ^ k)
                .collect()
        };

        // Step 2: Parse decrypted (or plaintext) bytes as JSON
        let subject: DecryptedCredentialSubject = serde_json::from_slice(&cleartext_bytes)
            .map_err(|e| {
                WalletError::ExecutionFailed(format!(
                    "Failed to parse unsealed credential subject: {e}"
                ))
            })?;

        // Step 3: Derive nullifier
        let secret_nullifier = Self::derive_nullifier(
            &subject.subject_did,
            &subject.credential_id,
            master_seed,
        );

        // Step 4: Compute commitment
        let public_commitment = Self::compute_commitment(
            &secret_nullifier,
            subject.user_clearance_level,
            &subject.user_role_scalar,
        );

        // Step 5: Return witness
        Ok(DerivedEnclaveWitness {
            clearance_level: subject.user_clearance_level,
            user_role_scalar: subject.user_role_scalar.clone(),
            secret_nullifier,
            public_commitment,
        })
    }


    /// Processes an unsealed credential subject inside enclave RAM into BLS12-381 field elements.
    /// Returns: (user_clearance, role_scalar, secret_nullifier, req_clearance, public_commitment, nullifier_bytes)
    pub fn process_unsealed_witness(
        subject: &DecryptedCredentialSubject,
        master_seed: &[u8; 32],
        required_clearance: u64,
    ) -> WalletResult<(Fr, Fr, Fr, Fr, Fr, [u8; 32])> {
        let user_clearance_fr = Fr::from(subject.user_clearance_level);
        let req_clearance_fr = Fr::from(required_clearance);

        let normalized_role_str = Self::string_to_scalar(&subject.user_role_scalar);
        let role_biguint = BigUint::from_str_radix(&normalized_role_str, 10)
            .map_err(|e| WalletError::ExecutionFailed(format!("Invalid role scalar radix: {e}")))?;
        let role_scalar_fr = Fr::from_le_bytes_mod_order(&role_biguint.to_bytes_le());

        let secret_nullifier_bytes = Self::derive_nullifier(
            &subject.subject_did,
            &subject.credential_id,
            master_seed,
        );
        let nullifier_fr = Fr::from_le_bytes_mod_order(&secret_nullifier_bytes);

        let commitment_fr = nullifier_fr * user_clearance_fr * role_scalar_fr;

        Ok((
            user_clearance_fr,
            role_scalar_fr,
            nullifier_fr,
            req_clearance_fr,
            commitment_fr,
            secret_nullifier_bytes,
        ))
    }

    pub fn unseal_credential_subject(
        payload: &EnclaveIngestionPayload,
    ) -> WalletResult<DecryptedCredentialSubject> {
        let cleartext_bytes = if payload.wallet_db_key.is_empty() {
            payload.raw_wallet_ciphertext.clone()
        } else {
            serde_json::from_slice::<DecryptedCredentialSubject>(&payload.raw_wallet_ciphertext)
                .map(|_| payload.raw_wallet_ciphertext.clone())
                .unwrap_or_else(|_| {
                    payload
                        .raw_wallet_ciphertext
                        .iter()
                        .zip(payload.wallet_db_key.iter().cycle())
                        .map(|(&c, &k)| c ^ k)
                        .collect()
                })
        };

        serde_json::from_slice(&cleartext_bytes)
            .map_err(|e| WalletError::ExecutionFailed(format!("Failed to parse credential subject: {e}")))
    }

    /// Computes public_commitment bytes directly from field variables
    pub fn compute_commitment(
        nullifier_bytes: &[u8; 32],
        user_clearance: u64,
        role_scalar_str: &str,
    ) -> Vec<u8> {
        let nullifier_fr = Fr::from_le_bytes_mod_order(nullifier_bytes);
        let clearance_fr = Fr::from(user_clearance);

        let normalized_role = Self::string_to_scalar(role_scalar_str);
        let role_biguint = BigUint::from_str_radix(&normalized_role, 10).unwrap_or_default();
        let role_fr = Fr::from_le_bytes_mod_order(&role_biguint.to_bytes_le());

        let commitment_fr = nullifier_fr * clearance_fr * role_fr;

        commitment_fr
            .into_bigint()
            .to_bytes_le()
            .to_vec()
    }

    /// Derives 32-byte nullifier deterministically from subject DID, Credential ID, and master seed bytes
    pub fn derive_nullifier(
        subject_did: &str,
        credential_id: &str,
        secret_seed_bytes: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"dZTA_NULLIFIER_DOMAIN_v1");
        hasher.update(subject_did.as_bytes());
        hasher.update(credential_id.as_bytes());
        hasher.update(secret_seed_bytes);
        hasher.finalize().into()
    }

    // =========================================================================
    // 2. Helper Utilities
    // =========================================================================

    /// Transforms any arbitrary string/identifier into a deterministic scalar string element.
    pub fn string_to_scalar(input: &str) -> String {
        if input.is_empty() {
            return "0".to_string();
        }

        if BigUint::from_str_radix(input, 10).is_ok() {
            return input.to_string();
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