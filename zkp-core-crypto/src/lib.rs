#![no_std]

use ark_ff::PrimeField;
use ark_r1cs_std::cmp::CmpGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// RoleVerificationCircuit handles mathematical constraints inside the TEE isolation layer.
pub struct RoleVerificationCircuit<F: PrimeField> {
    // Private Witnesses (Hidden inside Enclave)
    pub user_role_id: Option<F>,
    pub secret_nullifier: Option<F>,
    pub user_clearance_level: Option<F>,

    // Public Inputs (Known to Verifier/Ledger)
    pub role_commitment: Option<F>,
    pub session_nonce: Option<F>,
    pub required_clearance_level: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RoleVerificationCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // 1. Allocate Private Witnesses
        let role_id_var = FpVar::new_witness(ark_relations::ns!(cs, "user_role_id"), || {
            self.user_role_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_var = FpVar::new_witness(ark_relations::ns!(cs, "secret_nullifier"), || {
            self.secret_nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let user_clearance_var =
            FpVar::new_witness(ark_relations::ns!(cs, "user_clearance_level"), || {
                self.user_clearance_level
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // 2. Allocate Public Inputs
        let commitment_var =
            FpVar::new_input(ark_relations::ns!(cs, "role_commitment"), || {
                self.role_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
        let nonce_var = FpVar::new_input(ark_relations::ns!(cs, "session_nonce"), || {
            self.session_nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let required_clearance_var =
            FpVar::new_input(ark_relations::ns!(cs, "required_clearance_level"), || {
                self.required_clearance_level
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // --- Constraint 1: Identity & Key Verification ---
        // Enforces: commitment == (user_role_id * secret_nullifier) + session_nonce
        let dynamic_hash = (&role_id_var * &nullifier_var) + &nonce_var;
        dynamic_hash.enforce_equal(&commitment_var)?;

        // --- Constraint 2: Zero-Knowledge Clearance Check ---
        // Enforces: user_clearance_level >= required_clearance_level
        
        let is_insufficient = user_clearance_var.is_cmp(
        &required_clearance_var, 
        core::cmp::Ordering::Less,
        true, // strict comparison
        )?;
        is_insufficient.enforce_equal(&Boolean::constant(false))?;

        Ok(())
    }
}