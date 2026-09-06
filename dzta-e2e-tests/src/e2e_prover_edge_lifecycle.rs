use std::path::Path;
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::Duration;

use log::{info, warn};
use dzta_gramine_prover::runner::ExecutionMode;
use dzta_gramine_prover::tee_runner::GramineExecutionProxy;
use shared::models::ZKPWitness;
use transport_engine::{ProofRequest, TransportConfig, TransportEngine, TransportError};

/// Manages active K8s port-forwarding processes and cleans them up automatically on drop.
pub struct K8sPortForwardGuard {
    ingress_child: Child,
    admin_child: Child,
}

impl K8sPortForwardGuard {
    pub fn start() -> Self {
        info!("[E2E] Spawning kubectl port-forward for Envoy Ingress (10000) and Admin (9901)...");

        let ingress_child = Command::new("kubectl")
            .args(&[
                "port-forward",
                "-n",
                "dzta-edge",
                "deployment/dzta-mec-edge-ingress",
                "10000:10000",
            ])
            .spawn()
            .expect("Failed to start kubectl port-forward for port 10000");

        let admin_child = Command::new("kubectl")
            .args(&[
                "port-forward",
                "-n",
                "dzta-edge",
                "deployment/dzta-mec-edge-ingress",
                "9901:9901",
            ])
            .spawn()
            .expect("Failed to start kubectl port-forward for port 9901");

        // Allow TCP tunnels to bind locally
        sleep(Duration::from_secs(2));

        Self {
            ingress_child,
            admin_child,
        }
    }
}

impl Drop for K8sPortForwardGuard {
    fn drop(&mut self) {
        info!("[E2E] Cleaning up active port-forward processes...");
        let _ = self.ingress_child.kill();
        let _ = self.admin_child.kill();
    }
}

#[tokio::test]
async fn test_end_to_end_gramine_prover_to_envoy_ingress() {
    let _ = env_logger::builder().is_test(true).try_init();
    info!("Starting Gramine Prover to Envoy Ingress E2E Integration Pipeline...");

    // -----------------------------------------------------------------
    // STEP 1: INITIALIZE TCP TUNNELS TO ENVOY INGRESS
    // -----------------------------------------------------------------
    let _pf_guard = K8sPortForwardGuard::start();

    // -----------------------------------------------------------------
    // STEP 2: VERIFY ENCLAVE PROVER BINARY PATHS & PREPARE WITNESS
    // -----------------------------------------------------------------
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = Path::new(&manifest_dir).parent().unwrap_or(Path::new("."));
    let target_dir = workspace_root.join("target/release");
    let prover_target_binary = target_dir.join("dzta-gramine-prover");
    let prover_manifest = target_dir.join("dzta-gramine-prover.manifest");
    let prover_target_str = prover_target_binary.to_str().unwrap();

    let mock_seed = b"super_secret_dZTA_nullifier_seed_2026";
    let required_clearance_level: u8 = 3;
    let execution_mode = ExecutionMode::Auto;

    let valid_witness = ZKPWitness {
        subject_did: "did:dzta:user-nathaniel-777".to_string(),
        credential_id: "0630519c-7de6-40c0-8cc0-ee180a9a197f".to_string(),
        clearance_level: 5,
        user_role_id: "systems-engineer".to_string(),
    };

    let proxy = GramineExecutionProxy::new(prover_target_str, execution_mode);
    let binary_exists = Path::new(prover_target_str).exists() && prover_manifest.exists();

    // -----------------------------------------------------------------
    // STEP 3: EXECUTE ENCLAVE PROVER
    // -----------------------------------------------------------------
    // dzta-gramine-prover outputs a ProverOutputResponse JSON to stdout with
    // pre-encoded Base64 strings for x_dzta_proof and x_dzta_public_inputs.
    let response = if binary_exists {
        info!("[E2E] Executing live proof generation via Gramine runner process...");
        proxy
            .prove_witness_in_gramine(&valid_witness, required_clearance_level, mock_seed)
            .expect("Gramine proof execution failed unexpectedly")
    } else {
        warn!(
            "[E2E] Prover binary `{}` not found. Compile the release binary first.",
            prover_target_str
        );
        panic!("Prover binary must be pre-compiled to execute end-to-end Wasm validation test.");
    };

    info!("[E2E] Received enclave execution response.");
    info!("[E2E] Base64 Proof Len: {}", response.x_dzta_proof.len());
    info!("[E2E] Base64 Public Inputs Len: {}", response.x_dzta_public_inputs.len());

    if let Some(ref quote) = response.sgx_dcap_quote_hex {
        info!("[E2E] SGX DCAP Quote attached (Hex Len: {})", quote.len());
    }

    // -----------------------------------------------------------------
    // STEP 4: TRANSMIT PRE-ENCODED BASE64 PROOF TO ENVOY INGRESS
    // -----------------------------------------------------------------
    let config = TransportConfig::new("http://127.0.0.1:10000");
    let engine = TransportEngine::new(config).expect("Valid TransportConfig");

    let request = ProofRequest::new(
        "verify_enclave_attestation",
        "edge-device-node-01",
        "edge-cluster-alpha",
    )
    .with_proof(
        response.x_dzta_proof.clone(),        // Direct Base64 proof string from enclave
        response.x_dzta_public_inputs.clone(), // Direct Base64 public inputs string from enclave
    )
    .with_revocation_id(&valid_witness.credential_id);

    // -----------------------------------------------------------------
    // STEP 5: SUBMIT PAYLOAD TO ENVOY WASM FILTER
    // -----------------------------------------------------------------
    info!("[E2E] Submitting ZKP payload through Envoy Ingress Wasm Filter...");
    match engine.submit_proof_request(&request).await {
        Ok(envelope) => {
            info!("✓ [E2E SUCCESS] Envoy Ingress Accepted Proof: {:?}", envelope);
            assert_eq!(envelope.status, "accepted");
        }
        Err(TransportError::Rejected { status, body }) => {
            panic!(
                "❌ [E2E FAILURE] Envoy Wasm Filter rejected proof. HTTP {}: {}",
                status, body
            );
        }
        Err(err) => panic!("❌ [E2E NETWORK FAILURE] Network transport failed: {:?}", err),
    }
}