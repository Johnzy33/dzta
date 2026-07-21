use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256};
use crate::models::ZKPWitness;
use serde_json::{json, Value};
use log::debug;
use crate::errors::WalletResult;

// const BN254_SCALAR_FIELD_PRIME: &str =
//     "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const BLS12_381_SCALAR_FIELD_PRIME: &str =
    "52435875175126190479447740508185965837690552500527637822603658699938581184513";


pub struct ZkpCore;

impl ZkpCore {
    /// Transforms any arbitrary UTF-8 string into a deterministic scalar element string.
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

    /// Prepares a witness payload for direct inclusion in execution circuits.
    pub fn compile_circom_inputs(witness: &ZKPWitness, constraints: Option<Value>) -> WalletResult<Value> {
        debug!("Compiling ZK witness parameters into scalar field inputs");

        let role_scalar = Self::string_to_scalar(&witness.user_role_id);
        let org_scalar = Self::string_to_scalar(&witness.org_id);
        let subject_scalar = Self::string_to_scalar(&witness.subject_did);

        let mut inputs = json!({
            "credentialIdHash": Self::string_to_scalar(&witness.credential_id),
            "schemaIdHash": Self::string_to_scalar(&witness.schema_id),
            "issuerDidHash": Self::string_to_scalar(&witness.issuer_did),
            "subjectDidHash": subject_scalar,
            "userRoleId": role_scalar,
            "orgId": org_scalar,
            "clearanceLevel": witness.clearance_level.to_string(),
            "timestamp": witness.timestamp.to_string(),
            "issuedAt": witness.issued_at.to_string(),
            "expiresAt": witness.expires_at.to_string(),
        });

        if let Some(c) = constraints {
            if let Some(obj) = inputs.as_object_mut() {
                obj.insert("constraints".to_string(), c);
            }
        }

        Ok(inputs)
    }
}