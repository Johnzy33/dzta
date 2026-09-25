use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dzta_attestation_broker::{
    create_router, AppState, ProvisionDatakeyRequest,
    ProvisioningDataKeyResponse, UnwrapDatakeyRequest, UnwrapDatakeyResponse, VaultDatakeyEngine,
};
use reqwest::StatusCode;
use rsa::{oaep::Oaep, pkcs8::EncodePublicKey, RsaPrivateKey};
use sha2_10::Sha256 as RsaSha256;
use std::{fs, path::Path, sync::Arc};
use tokio::net::TcpListener;
use shared::vault_client::build_vault_client;
#[tokio::test]
async fn test_axum_broker_http_datakey_endpoints() {
    let secret_key_name =
        std::env::var("DZTA_SECRET_RELEASE_KEY").unwrap_or_else(|_| "dzta-key".into());

    let http_client = build_vault_client().expect("Failed to build vault HTTP client");

    let datakey_engine = Arc::new(
        VaultDatakeyEngine::from_env(&secret_key_name)
            .expect("Failed to initialize VaultDatakeyEngine from environment"),
    );

    // Build application router directly using production code
    let app = create_router(AppState { datakey_engine });

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind random local port");
    let server_addr = listener.local_addr().unwrap();


    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Broker HTTP server crashed");
    });

    let base_url = format!("http://{}", server_addr);
    let key_file_path = Path::new("target/debug/wallet_http_test.key.enc");

    if key_file_path.exists() {
        let _ = fs::remove_file(key_file_path);
    }

    // --- PHASE 1: Provisioning ---
    let mut rng = rand::thread_rng();
    let enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let enclave_pub_pem = enclave_priv_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let provision_req = ProvisionDatakeyRequest {
        enclave_public_key: enclave_pub_pem.clone(),
    };

    let response = http_client
        .post(format!("{}/v1/datakey/provision", base_url))
        .json(&provision_req)
        .send()
        .await
        .expect("Provision request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let provision_res: ProvisioningDataKeyResponse = response
        .json()
        .await
        .expect("Failed to parse provision response");

    fs::write(key_file_path, &provision_res.wallet_ciphertext).unwrap();

    let raw_encrypted_dek = BASE64
        .decode(&provision_res.encrypted_wallet_key_for_enclave)
        .unwrap();
    let initial_unwrapped_dek = enclave_priv_key
        .decrypt(Oaep::new::<RsaSha256>(), &raw_encrypted_dek)
        .expect("Enclave failed to decrypt initial DEK");

    assert_eq!(initial_unwrapped_dek.len(), 32);

    // --- PHASE 2: Unwrapping ---
    let wallet_ciphertext = fs::read_to_string(key_file_path).unwrap();
    let session_enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let session_enclave_pub_pem = session_enclave_priv_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let unwrap_req = UnwrapDatakeyRequest {
        quote: BASE64.encode("mock_sgx_quote_bytes"),
        enclave_public_key: session_enclave_pub_pem,
        required_clearance_level: 1,
        wallet_ciphertext: wallet_ciphertext,
        seed_ciphertext: provision_res.seed_ciphertext,
    };

    let response = http_client
        .post(format!("{}/v1/datakey/unwrap", base_url))
        .json(&unwrap_req)
        .send()
        .await
        .expect("Unwrap request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let unwrap_res: UnwrapDatakeyResponse = response
        .json()
        .await
        .expect("Failed to parse unwrap response");

    let session_encrypted_dek = BASE64
        .decode(&unwrap_res.encrypted_wallet_key_for_enclave)
        .unwrap();
    let session_unwrapped_dek = session_enclave_priv_key
        .decrypt(Oaep::new::<RsaSha256>(), &session_encrypted_dek)
        .expect("Session enclave failed to decrypt DEK");

    assert_eq!(initial_unwrapped_dek, session_unwrapped_dek);

    // let _ = fs::remove_file(key_file_path);
}