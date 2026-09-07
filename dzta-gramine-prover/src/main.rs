// // dzta-gramine-prover/src/main.rs
// mod attestation;

// use anyhow::{Context, Result};
// use ark_bls12_381::{Bls12_381, Fr};
// use ark_ff::PrimeField;
// use ark_groth16::{Groth16, ProvingKey};
// use ark_relations::gr1cs::{ConstraintSystem, ConstraintSynthesizer};
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// use attestation::GramineAttestationDriver;
// use shared::zkp_core::{ProverInputPayload, ProverOutputResponse};
// use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
// use num_bigint::BigUint;
// use num_traits::Num;
// use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
// use std::io::{self, Read, Write};
// use tracing::{info, Level};
// use tracing_subscriber::FmtSubscriber;
// use zeroize::Zeroize;

// use zkp_core_crypto::RoleVerificationCircuit;

// fn main() -> Result<()> {
//     // 1. Initialize Tracing Diagnostic Logging (strictly to stderr without ANSI colors)
//     let subscriber = FmtSubscriber::builder()
//         .with_max_level(Level::INFO)
//         .with_ansi(false)
//         .with_writer(io::stderr)
//         .finish();
//     tracing::subscriber::set_global_default(subscriber)?;

//     info!("------------------------------------------------------------------");
//     info!(" [Gramine Prover] Starting dZTA SGX/Direct Proving Enclave");
//     info!("------------------------------------------------------------------");

//     // 2. Read Ingestion JSON from Standard Input
//     let mut stdin_buffer = String::new();
//     io::stdin().read_to_string(&mut stdin_buffer)
//         .context("Failed to read JSON payload from stdin")?;

//     let mut payload: ProverInputPayload = serde_json::from_str(&stdin_buffer)
//         .context("Invalid ProverInputPayload JSON structure")?;

//     // 3. Map Cleartext Witness and Public Inputs to BLS12-381 Scalar Fields
//     let user_clearance_fr = Fr::from(payload.user_clearance_level);
    
//     let role_biguint = BigUint::from_str_radix(&payload.user_role_scalar, 10)
//         .context("Failed to parse user_role_scalar BigUint")?;
//     let role_scalar_fr = Fr::from_le_bytes_mod_order(&role_biguint.to_bytes_le());

//     let nullifier_fr = Fr::from_le_bytes_mod_order(&payload.secret_nullifier);
//     let req_clearance_fr = Fr::from(payload.required_clearance_level);
//     let commitment_fr = Fr::from_le_bytes_mod_order(&payload.public_commitment);

//     // 4. Load Pre-baked Proving Key
//     let pk_bytes = include_bytes!("../assets/proving_key.bin");
//     let proving_key = ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..])
//         .context("Failed to deserialize BLS12-381 Proving Key")?;

//     // 5. Seed ChaCha20 RNG from Private Secret Nullifier
//     let seed: [u8; 32] = payload.secret_nullifier.as_slice().try_into()
//         .map_err(|_| anyhow::anyhow!("secret_nullifier must be exactly 32 bytes"))?;
//     let mut rng = ChaCha20Rng::from_seed(seed);

//     // 6. Instantiate Workspace Canonical Circuit
//     let circuit = RoleVerificationCircuit {
//         user_clearance_level: Some(user_clearance_fr),
//         user_role_scalar: Some(role_scalar_fr),
//         secret_nullifier: Some(nullifier_fr),
//         required_clearance_level: Some(req_clearance_fr),
//         public_commitment: Some(commitment_fr),
//     };

//     // 6b. Explicitly validate R1CS constraint satisfaction before proof synthesis
//     let cs = ConstraintSystem::<Fr>::new_ref();
//     circuit.clone().generate_constraints(cs.clone())
//         .context("Failed to synthesize circuit constraints for validation")?;

//     if !cs.is_satisfied().context("Error evaluating constraint satisfaction")? {
//         anyhow::bail!("Circuit constraints not satisfied for provided witness (clearance level below required threshold)");
//     }

//     // 7. Synthesize Groth16 ZK Proof inside Gramine Enclave Boundary
//     info!("[Gramine Prover] Synthesizing Groth16 proof over BLS12-381...");
//     let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
//         circuit,
//         &proving_key,
//         &mut rng,
//     ).map_err(|e| anyhow::anyhow!("ZKP Generation Failed: {:?}", e))?;

//     // 8. Serialize Compressed Proof & Public Inputs
//     let mut proof_bytes = Vec::new();
//     proof.serialize_compressed(&mut proof_bytes)?;

//     let public_inputs: Vec<Fr> = vec![req_clearance_fr, commitment_fr];
//     let mut public_inputs_bytes = Vec::new();
//     public_inputs.serialize_compressed(&mut public_inputs_bytes)?;

//     // 9. Hardware SGX Attestation Quote Binding
//     GramineAttestationDriver::bind_user_report_data(&public_inputs_bytes)?;
//     let sgx_quote = GramineAttestationDriver::fetch_sgx_quote()?;

//     // 10. Construct Final Payload Output
//     let response = ProverOutputResponse {
//         x_dzta_proof: BASE64.encode(&proof_bytes),
//         x_dzta_public_inputs: BASE64.encode(&public_inputs_bytes),
//         sgx_dcap_quote_hex: sgx_quote.map(|q| hex::encode(q)),
//     };

//     // Clean up sensitive memory context
//     payload.zeroize();

//     info!("[Gramine Prover] Proof generation completed successfully.");

//     // Emit RAW JSON strictly to stdout
//     let json_output = serde_json::to_string(&response)?;
//     let mut stdout = io::stdout().lock();
//     writeln!(stdout, "{}", json_output)?;
//     stdout.flush()?;

//     Ok(())
// }


// dzta-gramine-prover/src/main.rs
mod attestation;

use anyhow::{Context, Result};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use attestation::GramineAttestationDriver;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use num_bigint::BigUint;
use num_traits::Num;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use shared::zkp_core::{EnclaveIngestionPayload, ProverOutputResponse, ZkpCore};
use std::io::{self, Read, Write};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use zeroize::Zeroize;

use zkp_core_crypto::RoleVerificationCircuit;

fn main() -> Result<()> {
    // 1. Initialize Tracing Diagnostic Logging (strictly to stderr without ANSI colors)
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .with_writer(io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("------------------------------------------------------------------");
    info!(" [Gramine Prover] Starting dZTA SGX/Direct Proving Enclave");
    info!("------------------------------------------------------------------");

    // 2. Read Ingestion JSON from Standard Input
    let mut stdin_buffer = String::new();
    io::stdin()
        .read_to_string(&mut stdin_buffer)
        .context("Failed to read JSON payload from stdin")?;

    let mut payload: EnclaveIngestionPayload = serde_json::from_str(&stdin_buffer)
        .context("Invalid EnclaveIngestionPayload JSON structure")?;

    // 3. Unseal encrypted wallet payload & derive ZKP witness inside TEE boundary
    // info!("[Gramine Prover] Unsealing encrypted payload & deriving witness inside enclave...");
    // let mut derived_witness = ZkpCore::unseal_and_derive_witness(
    //     &payload.raw_wallet_ciphertext,
    //     &payload.wallet_db_key,
    //     &payload.master_seed,
    // )
    // .map_err(|e| anyhow::anyhow!("Enclave unseal/witness derivation failed: {e}"))?;

    

    info!("[Gramine Prover] Unsealing encrypted payload & deriving witness inside enclave...");
    let mut derived_witness = match ZkpCore::unseal_and_derive_witness(
        &payload.raw_wallet_ciphertext,
        &payload.wallet_db_key,
        &payload.master_seed,
    ) {
        Ok(witness) => witness,
        Err(err) => {
            let mut err_stream = io::stderr().lock();
            let _ = writeln!(err_stream, "\n[CRITICAL UNSEAL ERROR] {err:#}\n");
            let _ = err_stream.flush();
            anyhow::bail!("Enclave unseal/witness derivation failed: {err:#}");
        }
    };

    // 4. Map derived witness & public inputs to BLS12-381 Scalar Fields
    let user_clearance_fr = Fr::from(derived_witness.clearance_level);

    let role_biguint = BigUint::from_str_radix(&derived_witness.user_role_scalar, 10)
        .context("Failed to parse user_role_scalar BigUint")?;
    let role_scalar_fr = Fr::from_le_bytes_mod_order(&role_biguint.to_bytes_le());

    let nullifier_fr = Fr::from_le_bytes_mod_order(&derived_witness.secret_nullifier);
    let req_clearance_fr = Fr::from(payload.required_clearance_level);
    let commitment_fr = Fr::from_le_bytes_mod_order(&derived_witness.public_commitment);

    // 5. Load Pre-baked Proving Key
    let pk_bytes = include_bytes!("../assets/proving_key.bin");
    let proving_key = ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..])
        .context("Failed to deserialize BLS12-381 Proving Key")?;

    // 6. Seed ChaCha20 RNG from derived secret nullifier
    let seed: [u8; 32] = derived_witness
        .secret_nullifier
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret_nullifier must be exactly 32 bytes"))?;
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 7. Instantiate Workspace Canonical Circuit
    let circuit = RoleVerificationCircuit {
        user_clearance_level: Some(user_clearance_fr),
        user_role_scalar: Some(role_scalar_fr),
        secret_nullifier: Some(nullifier_fr),
        required_clearance_level: Some(req_clearance_fr),
        public_commitment: Some(commitment_fr),
    };

    // 7b. Explicitly validate R1CS constraint satisfaction before proof synthesis
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .context("Failed to synthesize circuit constraints for validation")?;

    if !cs
        .is_satisfied()
        .context("Error evaluating constraint satisfaction")?
    {
        anyhow::bail!("Circuit constraints not satisfied for provided witness (clearance level below required threshold)");
    }

    // 8. Synthesize Groth16 ZK Proof inside Gramine Enclave Boundary
    info!("[Gramine Prover] Synthesizing Groth16 proof over BLS12-381...");
    let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
        circuit,
        &proving_key,
        &mut rng,
    )
    .map_err(|e| anyhow::anyhow!("ZKP Generation Failed: {:?}", e))?;

    // 9. Serialize Compressed Proof & Public Inputs
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;

    let public_inputs: Vec<Fr> = vec![req_clearance_fr, commitment_fr];
    let mut public_inputs_bytes = Vec::new();
    public_inputs.serialize_compressed(&mut public_inputs_bytes)?;

    // 10. Hardware SGX Attestation Quote Binding
    GramineAttestationDriver::bind_user_report_data(&public_inputs_bytes)?;
    let sgx_quote = GramineAttestationDriver::fetch_sgx_quote()?;

    // 11. Construct Final Payload Output
    let response = ProverOutputResponse {
        x_dzta_proof: BASE64.encode(&proof_bytes),
        x_dzta_public_inputs: BASE64.encode(&public_inputs_bytes),
        sgx_dcap_quote_hex: sgx_quote.map(|q| hex::encode(q)),
    };

    // Zeroize sensitive cleartext memory context
    derived_witness.zeroize();
    payload.zeroize();

    info!("[Gramine Prover] Proof generation completed successfully.");

    // Emit RAW JSON strictly to stdout
    let json_output = serde_json::to_string(&response)?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{}", json_output)?;
    stdout.flush()?;

    Ok(())
}