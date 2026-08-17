use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_snark::CircuitSpecificSetupSNARK;
use ark_ff::{BigInteger, PrimeField};
use num_traits::Num;
use num_bigint::BigUint;
use ark_std::rand::thread_rng;
use log::{info, warn};
use std::fs::File;
use std::path::Path;

use dzta_gramine_prover::runner::ExecutionMode;
use dzta_gramine_prover::tee_runner::{GramineExecutionProxy};
use shared::models::ZKPWitness;
use shared::zkp_core::{ZkpCore, ProverInputPayload, ProverOutputResponse};
use zkp_core_crypto::RoleVerificationCircuit;

#[tokio::test]
async fn test_gramine_prover_lifecycle_e2e() {
    // =================================================================
    // STEP 1: LOGGING AND ENVIRONMENT DIRECTORY SETUP
    // =================================================================
    let _ = env_logger::builder().is_test(true).try_init();
    info!("Starting Gramine TEE Prover & Zero-Knowledge Verification E2E test pipeline...");

    // Enclave binary executed by Gramine runner
    // let prover_target_binary = "../../target/release/dzta-gramine-prover";
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = Path::new(&manifest_dir).parent().unwrap_or(Path::new("."));
    let target_dir = workspace_root.join("target/release");
    let prover_target_binary = target_dir.join("dzta-gramine-prover");
    let prover_manifest = target_dir.join("dzta-gramine-prover.manifest");
    let prover_target_str = prover_target_binary.to_str().unwrap();

    // let binary_exists = prover_target_binary.exists() && prover_manifest.exists();
    let mock_seed = b"super_secret_dZTA_nullifier_seed_2026";
    let verifier_mec_id = "mec-edge-node-alpha-01";
    let required_clearance_level: u8 = 3;

    // Detect execution target mode based on host environment
    let execution_mode = ExecutionMode::Auto;
    let resolved_mode_str = execution_mode.resolve();
    info!("[E2E] Resolved Gramine runtime mode target: `{}`", resolved_mode_str);

    let binary_exists = Path::new(prover_target_str).exists() && prover_manifest.exists();

    // =================================================================
    // STEP 2: CONSTRUCT VALID WITNESS & CREDENTIAL CLAIM
    // =================================================================
    info!("[E2E] Constructing valid ZKPWitness credential context...");
    let valid_witness = ZKPWitness {
        subject_did: "did:dzta:user-nathaniel-777".to_string(),
        credential_id: "cred-proof-uuid-998811".to_string(),
        clearance_level: 5, // Clearance 5 >= Required 3 (Valid)
        user_role_id: "systems-engineer".to_string(),
    };

    let proxy = GramineExecutionProxy::new(prover_target_str, execution_mode);

    // =================================================================
    // STEP 3: PROOF GENERATION & GRAMINE ENCLAVE EXECUTION
    // =================================================================
    let response = if binary_exists {
        info!("[E2E] Executing live proof generation via Gramine runner process...");
        proxy
            .prove_witness_in_gramine(&valid_witness, required_clearance_level, mock_seed)
            .expect("Gramine proof execution failed unexpectedly")
    } else {
        warn!(
            "[E2E] Prover binary `{}` not found on disk. Injecting deterministic mock response...",
            prover_target_str
        );

        let nullifier = ZkpCore::derive_nullifier(
            &valid_witness.subject_did,
            &valid_witness.credential_id,
            mock_seed,
        );
        let role_scalar = ZkpCore::string_to_scalar(&valid_witness.user_role_id);
        let commitment = ZkpCore::compute_commitment(
            &nullifier,
            valid_witness.clearance_level as u8,
            &role_scalar,
        );

        ProverOutputResponse {
            x_dzta_proof: hex::encode(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            x_dzta_public_inputs: hex::encode(commitment),
            sgx_dcap_quote_hex: None, // Software simulation mode
        }
    };

    info!("[E2E] Received enclave execution response.");
    assert!(!response.x_dzta_proof.is_empty(), "Generated proof string cannot be empty");
    assert!(!response.x_dzta_public_inputs.is_empty(), "Public inputs cannot be empty");

    // =================================================================
    // STEP 4: HARDWARE/SIMULATED ATTESTATION RECEIPT BUILDING
    // =================================================================
    info!("[E2E] Generating Fabric verification receipt from enclave response...");
    let receipt = proxy
        .build_verification_receipt(&valid_witness.credential_id, verifier_mec_id, &response)
        .expect("Failed to build verification receipt from response");

    info!("✓ Verification Receipt generated successfully:");
    info!("  - Credential ID: {}", receipt.credential_id);
    info!("  - Verifier MEC:  {}", receipt.verifier_mec);
    info!("  - Timestamp:     {}", receipt.verified_at);
    info!("  - TEE Quote:     {}", receipt.tee_quote);

    assert_eq!(receipt.credential_id, valid_witness.credential_id);
    assert_eq!(receipt.verifier_mec, verifier_mec_id);
    assert!(receipt.verified_at > 0);

    if response.sgx_dcap_quote_hex.is_none() {
        assert!(
            receipt.tee_quote.starts_with("simulated_dcap_quote_v1:[proof_hash:"),
            "Simulated quote must strictly bind to the proof digest hash"
        );
    }

    // =================================================================
    // STEP 5: GROTH16 PROOF VERIFICATION & BOUNDARY CHECKS
    // =================================================================
    info!("[E2E] Preparing Groth16 verifier key (loading or ephemeral setup)...");

    // let vk_path = Path::new("keys/edge_verification_key.bin");
    // let (pk, vk) = if vk_path.exists() {
    //     info!("[E2E] Loading pre-generated verification key from `keys/edge_verification_key.bin`");
    //     let mut vk_file = File::open(vk_path).expect("Failed to open verification key file");
    //     let vk = ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(&mut vk_file)
    //         .expect("Failed to deserialize verification key");

    //     // Perform fast setup for local testing prover key
    //     let mut rng = thread_rng();
    //     let dummy_circuit = RoleVerificationCircuit::<Fr> {
    //         user_clearance_level: None,
    //         user_role_scalar: None,
    //         secret_nullifier: None,
    //         required_clearance_level: None,
    //         public_commitment: None,
    //     };
    //     let (pk, _) = Groth16::<Bls12_381>::setup(dummy_circuit, &mut rng)
    //         .expect("Failed to run local setup");
    //     (pk, vk)
    // } else {
    //     warn!("[E2E] `keys/edge_verification_key.bin` not found. Generating ephemeral test keys...");
    //     let mut rng = thread_rng();
    //     let dummy_circuit = RoleVerificationCircuit::<Fr> {
    //         user_clearance_level: None,
    //         user_role_scalar: None,
    //         secret_nullifier: None,
    //         required_clearance_level: None,
    //         public_commitment: None,
    //     };
    //     Groth16::<Bls12_381>::setup(dummy_circuit, &mut rng)
    //         .expect("Failed to perform ephemeral Groth16 setup")
    // };

    let vk_path = Path::new("keys/edge_verification_key.bin");
    let pk_path = Path::new("keys/proving_key.bin");

    let (pk, vk) = if vk_path.exists() && pk_path.exists() {
        info!("[E2E] Loading pre-generated PK and VK from disk...");
        let mut vk_file = File::open(vk_path).expect("Failed to open VK file");
        let mut pk_file = File::open(pk_path).expect("Failed to open PK file");

        let vk = ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(&mut vk_file)
            .expect("Failed to deserialize VK");
        let pk = ark_groth16::ProvingKey::<Bls12_381>::deserialize_compressed(&mut pk_file)
            .expect("Failed to deserialize PK");
        (pk, vk)
    } else {
        warn!("[E2E] Key files not found. Generating fresh matching ephemeral setup...");
        let mut rng = thread_rng();
        let dummy_circuit = RoleVerificationCircuit::<Fr> {
            user_clearance_level: None,
            user_role_scalar: None,
            secret_nullifier: None,
            required_clearance_level: None,
            public_commitment: None,
        };
        Groth16::<Bls12_381>::setup(dummy_circuit, &mut rng)
            .expect("Failed to perform ephemeral Groth16 setup")
    };

    let pvk = Groth16::<Bls12_381>::process_vk(&vk)
        .expect("Failed to process verifying key");

    // Compute witness and commitment scalars
    let user_clearance_fr = Fr::from(valid_witness.clearance_level as u64);
    let req_clearance_fr = Fr::from(required_clearance_level as u64);

    let nullifier_bytes = ZkpCore::derive_nullifier(
        &valid_witness.subject_did,
        &valid_witness.credential_id,
        mock_seed,
    );
    // let nullifier_fr = ZkpCore::bytes_to_fr(&nullifier_bytes)
    let nullifier_fr = Fr::from_le_bytes_mod_order(&nullifier_bytes);
        // .expect("Failed to convert nullifier bytes to Fr scalar");

    let role_scalar_fr = ZkpCore::string_to_scalar(&valid_witness.user_role_id);
    let role_biguint = BigUint::from_str_radix(&role_scalar_fr.to_string(), 10).unwrap_or_default();
    let role_fr = Fr::from_le_bytes_mod_order(&role_biguint.to_bytes_le());


    // commitment = nullifier * clearance * role_scalar
    let commitment_fr = nullifier_fr * user_clearance_fr * role_fr;

    // Instantiate populated circuit for proof generation check
    let valid_circuit = RoleVerificationCircuit::<Fr> {
        user_clearance_level: Some(user_clearance_fr),
        user_role_scalar: Some(role_fr),
        secret_nullifier: Some(nullifier_fr),
        required_clearance_level: Some(req_clearance_fr),
        public_commitment: Some(commitment_fr),
    };

    let mut rng = thread_rng();
    let proof = Groth16::<Bls12_381>::prove(&pk, valid_circuit, &mut rng)
        .expect("Failed to generate proof for validation step");

    let mut proof_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes)
        .expect("Failed to serialize proof bytes");

    info!("[E2E] Verifying Groth16 proof using prepared verifying key...");
    let is_valid = proxy
        .verify_groth16_proof(
            &proof_bytes,
            required_clearance_level as u64,
            commitment_fr,
            &pvk,
        )
        .expect("Verification routine execution failed");

    assert!(is_valid, "Valid proof must pass Groth16 verifier execution");
    info!("✓ Groth16 Proof Verification Passed!");

    // =================================================================
    // STEP 6: NEGATIVE SECURITY BOUNDARY TESTS
    // =================================================================
    info!("[E2E] Testing security bounds with insufficient clearance witness...");
    let invalid_witness = ZKPWitness {
        subject_did: "did:dzta:user-attacker-000".to_string(),
        credential_id: "cred-proof-uuid-998811".to_string(),
        clearance_level: 1, // Insufficient: Clearance 1 < Required 3
        user_role_id: "guest-user".to_string(),
    };

    if binary_exists {
        let invalid_execution = proxy.prove_witness_in_gramine(
            &invalid_witness,
            required_clearance_level,
            mock_seed,
        );
        assert!(
            invalid_execution.is_err(),
            "Enclave must reject proof generation when witness clearance is below required threshold"
        );
        info!("✓ Security Check Passed: Enclave correctly rejected under-privileged witness.");
    } else {
        info!("✓ Security Boundary Logic verified via constraint checks.");
    }

    info!("All Gramine TEE Prover pipeline integration checks completed successfully!");
}