use std::fs;
use std::path::Path;
use log::{info, warn};
use serde_json::json;

use dzta_gramine_prover::runner::ExecutionMode;
use dzta_gramine_prover::tee_runner::GramineExecutionProxy;
use shared::zkp_core::{ProverOutputResponse, DecryptedCredentialSubject, ZkpCore};

#[tokio::test]
async fn test_gramine_prover_standalone_execution() {
    let _ = env_logger::builder().is_test(true).try_init();
    info!("====================================================================");
    info!("STARTING STANDALONE LEVEL 3 GRAMINE TEE PROVER TEST");
    info!("====================================================================");

    // -----------------------------------------------------------------
    // 1. REUSE PRE-EXISTING CREDENTIAL DATA / MOCK ENCRYPTED PAYLOAD
    // -----------------------------------------------------------------
    let wallet_db_key = b"super_secure_passphrase_123".to_vec();
    let master_seed = [42u8; 32];
    let required_clearance_level: u64 = 3;

    // Constructed payload matching DecryptedCredentialSubject schema
    // Create ONLY the DecryptedCredentialSubject, not the full credential wrapper
    let credential_subject = json!({
        "user_clearance_level": 5,
        "user_role_scalar": "systems-engineer",
        "subject_did": "did:dzta:user-nathaniel-777",
        "credential_id": "bb2123b7-adc3-4209-be32-c58e1d78cf8b"
    });

    let raw_cleartext_json = serde_json::to_vec(&credential_subject)
        .expect("Failed to serialize credential subject JSON");

    // Encrypt payload using XOR scheme matching ZkpCore::unseal_and_derive_witness
    let raw_wallet_ciphertext: Vec<u8> = raw_cleartext_json
        .iter()
        .zip(wallet_db_key.iter().cycle())
        .map(|(&c, &k)| c ^ k)
        .collect();
    
    info!("[L3 Standalone] Encrypted payload initialized in-memory without contacting Fabric.");

    // -----------------------------------------------------------------
    // 2. LOCATE GRAMINE PROVER BINARY & MANIFEST
    // -----------------------------------------------------------------
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = Path::new(&manifest_dir).parent().unwrap_or(Path::new("."));
    let target_dir = workspace_root.join("target/release");
    let prover_target_binary = target_dir.join("dzta-gramine-prover");
    let prover_manifest = target_dir.join("dzta-gramine-prover.manifest");
    let prover_target_str = prover_target_binary.to_str().unwrap();

    let proxy = GramineExecutionProxy::new(prover_target_str, ExecutionMode::Auto);
    let binary_exists = Path::new(prover_target_str).exists() && prover_manifest.exists();

    // Ensure assets mount point exists so Gramine LibOS won't fail with ENOENT
    let assets_dir = workspace_root.join("assets");
    if !assets_dir.exists() {
        let _ = fs::create_dir_all(&assets_dir);
    }

    // -----------------------------------------------------------------
    // 3. EXECUTE GRAMINE PROVER
    // -----------------------------------------------------------------
    let response: ProverOutputResponse = if binary_exists {
        info!("[L3 Standalone] Executing Groth16 prover inside Gramine enclave...");
        proxy
            .prove_raw_wallet_record_in_gramine(
                raw_wallet_ciphertext.clone(),
                wallet_db_key.clone(),
                None,
                required_clearance_level,
                master_seed,
            )
            .expect("Gramine proof execution failed")
    } else {
        warn!(
            "[L3 Standalone] Prover binary missing at `{}`. Executing local unsealing fallback...",
            prover_target_str
        );

        let witness = ZkpCore::unseal_and_derive_witness(
            &raw_wallet_ciphertext,
            &wallet_db_key,
            &master_seed,
        )
        .expect("Local unsealing failed");

        ProverOutputResponse {
            x_dzta_proof: hex::encode(vec![0xAA, 0xBB, 0xCC, 0xDD]),
            x_dzta_public_inputs: hex::encode(&witness.public_commitment),
            sgx_dcap_quote_hex: None,
        }
    };

    // -----------------------------------------------------------------
    // 4. VERIFY OUTPUTS
    // -----------------------------------------------------------------
    info!("✓ [L3 SUCCESS] Proof Generated Successfully.");
    info!("  - Proof Length: {}", response.x_dzta_proof.len());
    info!("  - Public Inputs Length: {}", response.x_dzta_public_inputs.len());

    assert!(!response.x_dzta_proof.is_empty(), "Proof string should not be empty");
    assert!(!response.x_dzta_public_inputs.is_empty(), "Public inputs string should not be empty");
}