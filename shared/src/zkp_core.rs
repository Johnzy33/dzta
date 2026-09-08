
// shared/src/zkp_core.rs
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use num_traits::Num;
use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{WalletError, WalletResult};

const BLS12_381_SCALAR_FIELD_PRIME: &str =
    "52435875175126190479447740508185965837690552500527637822603658699938581184513";

const WALLET_RECORD_MAGIC: &[u8; 5] = b"DZTA1";

pub fn encrypt_wallet_record(plaintext: &[u8], passphrase: &[u8]) -> WalletResult<Vec<u8>> {
    let key = Sha256::digest(passphrase);
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| WalletError::ExecutionFailed(format!("Failed to generate nonce: {e}")))?;

    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&nonce))
        .map_err(|e| WalletError::ExecutionFailed(format!("Failed to initialize encryption: {e}")))?;
    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = crypter
        .update(plaintext, &mut ciphertext)
        .map_err(|e| WalletError::ExecutionFailed(format!("Failed to encrypt wallet record: {e}")))?;
    count += crypter
        .finalize(&mut ciphertext[count..])
        .map_err(|e| WalletError::ExecutionFailed(format!("Failed to finalize encryption: {e}")))?;
    ciphertext.truncate(count);

    let mut tag = [0u8; 16];
    crypter
        .get_tag(&mut tag)
        .map_err(|e| WalletError::ExecutionFailed(format!("Failed to finalize authentication tag: {e}")))?;

    let mut envelope = Vec::with_capacity(WALLET_RECORD_MAGIC.len() + nonce.len() + ciphertext.len() + tag.len());
    envelope.extend_from_slice(WALLET_RECORD_MAGIC);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    envelope.extend_from_slice(&tag);
    Ok(envelope)
}

pub fn decrypt_wallet_record(envelope: &[u8], passphrase: &[u8]) -> WalletResult<Vec<u8>> {
    let minimum_length = WALLET_RECORD_MAGIC.len() + 12 + 16;
    if envelope.len() < minimum_length || !envelope.starts_with(WALLET_RECORD_MAGIC) {
        return Err(WalletError::ExecutionFailed("Invalid wallet record envelope".to_string()));
    }

    let nonce_start = WALLET_RECORD_MAGIC.len();
    let nonce_end = nonce_start + 12;
    let tag_start = envelope.len() - 16;
    let key = Sha256::digest(passphrase);
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&envelope[nonce_start..nonce_end]))
        .map_err(|e| WalletError::ExecutionFailed(format!("Failed to initialize decryption: {e}")))?;
    crypter
        .set_tag(&envelope[tag_start..])
        .map_err(|e| WalletError::ExecutionFailed(format!("Failed to set authentication tag: {e}")))?;

    let ciphertext = &envelope[nonce_end..tag_start];
    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
    let mut count = crypter
        .update(ciphertext, &mut plaintext)
        .map_err(|e| WalletError::ExecutionFailed(format!("Failed to decrypt wallet record: {e}")))?;
    count += crypter
        .finalize(&mut plaintext[count..])
        .map_err(|_| WalletError::ExecutionFailed("Wallet record authentication failed".to_string()))?;
    plaintext.truncate(count);
    Ok(plaintext)
}

/// Payload passed Host OS -> Gramine SGX Enclave via stdin.
/// Contains ONLY raw encrypted wallet records and key material.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EnclaveIngestionPayload {
    /// Raw encrypted store record as retrieved directly from Askar/SQLite storage on disk
    pub raw_wallet_ciphertext: Vec<u8>,
    /// Master key/passphrase used to decrypt the Askar storage record
    pub wallet_db_key: Option<Vec<u8>>,
    /// Credential identifier stored as Fabric/Askar metadata
    #[serde(default)]
    pub credential_id: Option<String>,
    /// Required clearance level demanded by the verifier (Public Input)
    pub required_clearance_level: u64,
    /// Holder's master seed for single-use nullifier derivation
    pub master_seed: Option<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub quote: String,
    pub enclave_public_key_pem: String,
    pub credential_key_id: String,
    pub required_clearance_level: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub encrypted_wallet_key: String,
    pub encrypted_master_seed: String,
    pub key_encryption_algorithm: String,
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
        Self::unseal_and_derive_witness_with_credential_id(raw_ciphertext, db_key, master_seed, None)
    }

    pub fn unseal_and_derive_witness_with_credential_id(
        raw_ciphertext: &[u8],
        db_key: &[u8],
        master_seed: &[u8; 32],
        credential_id: Option<&str>,
    ) -> WalletResult<DerivedEnclaveWitness> {
        let cleartext_bytes = match decrypt_wallet_record(raw_ciphertext, db_key) {
            Ok(cleartext) => cleartext,
            Err(_) => raw_ciphertext.to_vec(),
        };
        let subject = Self::parse_credential_subject(&cleartext_bytes, credential_id)
            .or_else(|_| {
                let legacy_cleartext = raw_ciphertext
                    .iter()
                    .zip(db_key.iter().cycle())
                    .map(|(&c, &k)| c ^ k)
                    .collect::<Vec<_>>();
                serde_json::from_slice(&legacy_cleartext).map_err(|e| {
                    WalletError::ExecutionFailed(format!(
                        "Failed to parse unsealed credential subject: {e}"
                    ))
                })
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
            user_role_scalar: Self::string_to_scalar(&subject.user_role_scalar),
            secret_nullifier,
            public_commitment,
        })
    }

    fn parse_credential_subject(
        raw_record: &[u8],
        credential_id: Option<&str>,
    ) -> WalletResult<DecryptedCredentialSubject> {
        if let Ok(subject) = serde_json::from_slice::<DecryptedCredentialSubject>(raw_record) {
            return Ok(subject);
        }

        let value: Value = serde_json::from_slice(raw_record).map_err(|e| {
            WalletError::ExecutionFailed(format!("Credential record is not valid JSON: {e}"))
        })?;
        let subject_value = value.get("credentialSubject").ok_or_else(|| {
            WalletError::ExecutionFailed("Credential record has no credentialSubject".to_string())
        })?;

        let subject_did = subject_value
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| WalletError::ExecutionFailed("Credential subject has no id".to_string()))?;
        let user_role_scalar = subject_value
            .get("userRoleId")
            .and_then(Value::as_str)
            .ok_or_else(|| WalletError::ExecutionFailed("Credential subject has no userRoleId".to_string()))?;
        let user_clearance_level = subject_value
            .get("clearanceLevel")
            .and_then(Value::as_u64)
            .ok_or_else(|| WalletError::ExecutionFailed("Credential subject has no clearanceLevel".to_string()))?;
        let credential_id = credential_id.ok_or_else(|| {
            WalletError::ExecutionFailed("Credential ID is required for W3C credential records".to_string())
        })?;

        Ok(DecryptedCredentialSubject {
            user_clearance_level,
            user_role_scalar: user_role_scalar.to_string(),
            subject_did: subject_did.to_string(),
            credential_id: credential_id.to_string(),
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
        let cleartext_bytes = if payload.wallet_db_key.as_ref().map_or(true, Vec::is_empty) {
            payload.raw_wallet_ciphertext.clone()
        } else {
            let wallet_db_key = payload.wallet_db_key.as_ref().ok_or_else(|| {
                WalletError::ExecutionFailed("wallet key missing".to_string())
            })?;
            serde_json::from_slice::<DecryptedCredentialSubject>(&payload.raw_wallet_ciphertext)
                .map(|_| payload.raw_wallet_ciphertext.clone())
                .unwrap_or_else(|_| {
                    payload
                        .raw_wallet_ciphertext
                        .iter()
                        .zip(wallet_db_key.iter().cycle())
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