// toxic-waste/src/bin/generate_keys.rs
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::CircuitSpecificSetupSNARK;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::fs::{create_dir_all, File};
use tracing::info;

// Import the canonical circuit definition from core crypto crate to ensure 
// witness and public input allocation order match the prover and TEE enclaves exactly.
use zkp_core_crypto::RoleVerificationCircuit;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing logger for console output
    tracing_subscriber::fmt::init();

    info!("------------------------------------------------------------------");
    info!("[ZKP Setup] Starting Groth16 Trusted Setup (Role Verification Circuit)");
    info!("------------------------------------------------------------------");

    // 1. Seeded RNG for deterministic setup
    let mut rng = ChaCha20Rng::seed_from_u64(0xDEADBEEF);

    // 2. Instantiate dummy circuit topology (all witness & input slots set to None)
    let circuit = RoleVerificationCircuit::<Fr> {
        user_clearance_level: None,
        user_role_scalar: None,
        secret_nullifier: None,
        required_clearance_level: None,
        public_commitment: None,
    };

    // 3. Perform Trusted Setup over BLS12-381 curve
    info!("[ZKP Setup] Computing CRS polynomials on BLS12-381 curve...");
    let (pk, vk) = Groth16::<Bls12_381>::setup(circuit, &mut rng)?;

    // 4. Ensure output directories exist
    create_dir_all("assets")?;
    create_dir_all("keys")?;

    // 5. Serialize and write Proving Key (Used by Prover / Mobile App / TEE Enclave)
    let pk_path = "assets/proving_key.bin";
    let mut pk_file = File::create(pk_path)?;
    pk.serialize_compressed(&mut pk_file)?;
    info!("[ZKP Setup] Proving Key successfully saved to: {}", pk_path);

    // 6. Serialize and write Verifying Key (Used by Envoy Wasm Filter / Edge Verifier)
    let vk_path = "keys/edge_verification_key.bin";
    let mut vk_file = File::create(vk_path)?;
    vk.serialize_compressed(&mut vk_file)?;
    info!("[ZKP Setup] Verifying Key successfully saved to: {}", vk_path);

    info!("------------------------------------------------------------------");
    info!("[ZKP Setup] Setup complete. Circuit optimized for low constraint R1CS.");
    info!("------------------------------------------------------------------");

    Ok(())
}