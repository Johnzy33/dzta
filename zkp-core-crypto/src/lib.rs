#![no_std]

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// RoleVerificationCircuit handles mathematical constraints inside the execution boundary.
/// Enforces range checking and role-bound nullifier verification (~37-40 constraints).
pub struct RoleVerificationCircuit<F: PrimeField> {
    // Private Witnesses
    pub user_clearance_level: Option<F>,
    pub user_role_scalar: Option<F>,
    pub secret_nullifier: Option<F>,

    // Public Inputs
    pub required_clearance_level: Option<F>,
    pub public_commitment: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RoleVerificationCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // 1. Allocate Private Witnesses (Order must match generate_keys setup binary!)
        let user_clearance = FpVar::new_witness(ark_relations::ns!(cs, "user_clearance"), || {
            self.user_clearance_level
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let role_scalar = FpVar::new_witness(ark_relations::ns!(cs, "role_scalar"), || {
            self.user_role_scalar
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier = FpVar::new_witness(ark_relations::ns!(cs, "nullifier"), || {
            self.secret_nullifier
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. Allocate Public Inputs (Order must match generate_keys setup binary!)
        let req_clearance = FpVar::new_input(ark_relations::ns!(cs, "req_clearance"), || {
            self.required_clearance_level
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let commitment = FpVar::new_input(ark_relations::ns!(cs, "commitment"), || {
            self.public_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 3. Dynamic Range Check: user_clearance - req_clearance
        let diff = &user_clearance - &req_clearance;

        // 4. Fast 8-Bit Range Check (Constrains valid differences to 0..255)
        let diff_bits = diff.to_bits_le()?;
        let truncated_diff = Boolean::le_bits_to_fp(&diff_bits[0..8])?;
        diff.enforce_equal(&truncated_diff)?;

        // 5. Role-bound Commitment Constraint: commitment == nullifier * user_clearance * role_scalar
        let expected_commitment = &nullifier * &user_clearance * &role_scalar;
        expected_commitment.enforce_equal(&commitment)?;

        Ok(())
    }
}