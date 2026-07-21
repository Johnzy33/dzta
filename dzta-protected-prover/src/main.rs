use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{Groth16, ProvingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use serde::Deserialize;
use std::io::{self, Read};

#[derive(Deserialize)]
struct ProverInputs {
    secret_seed: Vec<u8>, // Private Witness
    public_param: Vec<u8>, // Public Input
}

struct RoleVerificationCircuit {
    secret_seed: Option<Fr>,  // Private witness scalar field element
    public_param: Option<Fr>, // Public input scalar field element
}

impl ConstraintSynthesizer<Fr> for RoleVerificationCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // 1. Allocate the private witness (secret_seed) in the circuit R1CS table
        let secret_seed_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.secret_seed.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. Allocate the public input variable (public_param)
        let public_param_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.public_param.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 3. Mathematical relation / Non-Linear Constraint Equation:
        //    (secret_seed * secret_seed) + secret_seed == public_param
        //    This enforces that the prover holds a secret mathematical root 
        //    matching the public parameter without exposing secret_seed.
        let squared = &secret_seed_var * &secret_seed_var;
        let derived_param = squared + &secret_seed_var;

        // 4. Enforce R1CS constraint equality: derived_param == public_param
        derived_param.enforce_equal(&public_param_var)?;

        Ok(())
    }
}

fn main() -> io::Result<()> {
    // 1. Ingest JSON payload streamed via stdin
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    let inputs: ProverInputs = serde_json::from_str(&buffer)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // 2. Map raw input bytes into BLS12-381 Scalar Field elements (Fr)
    let secret_fr = Fr::from_le_bytes_mod_order(&inputs.secret_seed);
    let public_fr = Fr::from_le_bytes_mod_order(&inputs.public_param);

    // 3. Load pre-baked Proving Key
    let pk_bytes = include_bytes!("../assets/proving_key.bin");
    let proving_key = ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // 4. Seed isolated ChaCha20 RNG
    let seed: [u8; 32] = inputs.secret_seed.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "secret_seed must be exactly 32 bytes for RNG initialization",
        )
    })?;
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 5. Instantiate circuit with populated Fr scalar values
    let circuit = RoleVerificationCircuit {
        secret_seed: Some(secret_fr),
        public_param: Some(public_fr),
    };

    // 6. Generate Groth16 zero-knowledge proof
    let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
        circuit,
        &proving_key,
        &mut rng,
    )
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("ZKP Generation Failed: {:?}", e),
        )
    })?;

    // 7. Serialize proof output to hex over stdout
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    println!("{}", hex::encode(proof_bytes));
    Ok(())
}