use shared::zkp_core::ProverOutputResponse;
use transport_engine::{ProofRequest, TransportConfig, TransportEngine, TransportError};

#[tokio::test]
async fn test_end_to_end_prover_to_envoy_ingress() {
    // 1. Output from dzta-gramine-prover stdout execution
    let prover_output = ProverOutputResponse {
        x_dzta_proof: "dGVzdC1wcm9vZi1ieXRlcw==".to_string(),
        x_dzta_public_inputs: "dGVzdC1wdWJsaWMtaW5wdXRzLWJ5dGVz".to_string(),
        sgx_dcap_quote_hex: None,
    };

    // 2. Instantiate transport engine pointing to Envoy Ingress (port 10000)
    let config = TransportConfig::new("http://127.0.0.1:10000");
    let engine = TransportEngine::new(config).expect("valid config");

    // 3. Construct edge proof request with proof payload and revocation ID
    let request = ProofRequest::new(
        "verify_enclave_attestation",
        "edge-device-node-01",
        "edge-cluster-alpha",
    )
    .with_proof(
        prover_output.x_dzta_proof.clone(),
        prover_output.x_dzta_public_inputs.clone(),
    )
    .with_revocation_id("cred-uuid-9876");

    // 4. Dispatch request through Envoy Wasm proxy filter
    match engine.submit_proof_request(&request).await {
        Ok(envelope) => {
            println!("Layer 4 Ingress Accepted Proof: {:?}", envelope);
        }
        Err(TransportError::Rejected { status, body }) => {
            println!("Gateway responded with status {}: {}", status, body);
            assert!(
                status == 403 || status == 400,
                "Unexpected HTTP rejection status"
            );
        }
        Err(err) => panic!("Network transport failed completely: {:?}", err),
    }
}