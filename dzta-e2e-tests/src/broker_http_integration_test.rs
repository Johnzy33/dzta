/*
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dzta_attestation_broker::{
    routes::{
        create_router,
        datakey::{ProvisionDatakeyRequest, UnwrapDatakeyRequest, UnwrapDatakeyResponse},
        AppState,
    },
    HttpsKmsProvider, ProvisioningDataKeyResponse, SecretProvider, VaultDatakeyEngine,
};
use reqwest::StatusCode;
use rsa::{oaep::Oaep, pkcs8::EncodePublicKey, RsaPrivateKey};
use sha2_10::Sha256 as RsaSha256;
use shared::vault_client::build_vault_client;
use std::{fs, path::Path, sync::Arc};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_axum_broker_http_datakey_endpoints() {
    let secret_key_name =
        std::env::var("DZTA_SECRET_RELEASE_KEY").unwrap_or_else(|_| "dzta-key".into());

    let http_client = build_vault_client().expect("Failed to build vault HTTP client");

    let datakey_engine = Arc::new(
        VaultDatakeyEngine::from_env(&secret_key_name)
            .expect("Failed to initialize VaultDatakeyEngine from environment"),
    );

    // Mock SecretProvider for testing
    let mock_kms: Arc<dyn SecretProvider> = Arc::new(
        HttpsKmsProvider::new("http://127.0.0.1:9999", None)
            .expect("Failed to initialize mock KMS provider"),
    );

    // Initialize full unified AppState
    let app_state = AppState {
        pccs_url: "https://pccs.phala.network".to_string(),
        expected_mrenclave: vec![0u8; 32], // Mock measurement
        expected_mrsigner: vec![0u8; 32],  // Mock signer
        kms: mock_kms,
        datakey_engine: Some(datakey_engine),
    };

    // Build application router using production router constructor
    let app = create_router(app_state);

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

    // --- PHASE 2: Master Seed Decryption ---
    let raw_encrypted_seed = BASE64
        .decode(&provision_res.encrypted_master_seed_for_enclave)
        .unwrap();
    let initial_unwrapped_seed = enclave_priv_key
        .decrypt(Oaep::new::<RsaSha256>(), &raw_encrypted_seed)
        .expect("Enclave failed to decrypt initial master seed");

    assert_eq!(initial_unwrapped_seed.len(), 32);

    // Clean up temporary test keys
    if key_file_path.exists() {
        let _ = fs::remove_file(key_file_path);
    }
}*/
/*
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dzta_attestation_broker::{
    routes::{
        create_router,
        datakey::{ProvisionDatakeyRequest, UnwrapDatakeyRequest, UnwrapDatakeyResponse},
        AppState,
    },
    ProvisioningDataKeyResponse, SecretProvider, VaultDatakeyEngine, VaultSecretRelease,
    VaultTransitProvider,
};
use reqwest::StatusCode;
use rsa::{oaep::Oaep, pkcs8::EncodePublicKey, RsaPrivateKey};
use sha2_10::Sha256 as RsaSha256;
use shared::vault_client::build_vault_client;
use std::{fs, path::Path, sync::Arc};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_axum_broker_http_datakey_endpoints() {
    let secret_key_name =
    std::env::var("DZTA_SECRET_RELEASE_KEY").unwrap_or_else(|_| "dzta-key".into());
    let vault_addr =
    std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".into());
    let vault_token = std::env::var("VAULT_TOKEN").unwrap_or_else(|_| "root".into());

    let http_client = build_vault_client().expect("Failed to build vault HTTP client");

    // 1. Initialize Vault DataKey Engine (For /provision and /unwrap)
    let datakey_engine = Arc::new(
        VaultDatakeyEngine::from_env(&secret_key_name)
        .expect("Failed to initialize VaultDatakeyEngine from environment"),
    );

    // 2. Initialize Vault Secret Release Provider (For /release via SecretProvider trait)
    let vault_transit_provider = VaultTransitProvider::new(&vault_addr, &vault_token, &secret_key_name)
    .expect("Failed to initialize VaultTransitProvider");

    let vault_kms: Arc<dyn SecretProvider> = Arc::new(VaultSecretRelease {
        provider: vault_transit_provider,
    });

    // 3. Initialize full unified AppState backed entirely by Vault
    let app_state = AppState {
        pccs_url: "https://pccs.phala.network".to_string(),
        expected_mrenclave: vec![0u8; 32], // Mock measurement
        expected_mrsigner: vec![0u8; 32],  // Mock signer
        kms: vault_kms,                    // Vault handles secret release
        datakey_engine: Some(datakey_engine), // Vault handles DEK provisioning & unwrapping
    };

    // Build application router using production router constructor
    let app = create_router(app_state);

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

    // --- PHASE 2: Master Seed Decryption ---
    let raw_encrypted_seed = BASE64
    .decode(&provision_res.encrypted_master_seed_for_enclave)
    .unwrap();
    let initial_unwrapped_seed = enclave_priv_key
    .decrypt(Oaep::new::<RsaSha256>(), &raw_encrypted_seed)
    .expect("Enclave failed to decrypt initial master seed");

    assert_eq!(initial_unwrapped_seed.len(), 32);

    // Clean up temporary test keys
    if key_file_path.exists() {
        let _ = fs::remove_file(key_file_path);
    }
}*/

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dzta_attestation_broker::{
    routes::{
        create_router,
        datakey::{ProvisionDatakeyRequest, UnwrapDatakeyRequest, UnwrapDatakeyResponse},
        AppState,
    },
    ProvisioningDataKeyResponse, SecretProvider, VaultDatakeyEngine, VaultSecretRelease,
    VaultTransitProvider,
};
use reqwest::StatusCode;
use rsa::{oaep::Oaep, pkcs8::EncodePublicKey, RsaPrivateKey};
use sha2_10::Sha256 as RsaSha256;
use shared::vault_client::build_vault_client;
use std::{fs, path::Path, sync::Arc};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_axum_broker_http_datakey_endpoints() {
    println!("\n=======================================================");
    println!(" [dZTA Integration Test] Starting Attestation Broker ");
    println!("=======================================================");

    let secret_key_name =
        std::env::var("DZTA_SECRET_RELEASE_KEY").unwrap_or_else(|_| "dzta-key".into());
    let vault_addr = std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".into());
    let vault_token = std::env::var("VAULT_TOKEN").unwrap_or_else(|_| "root".into());

    let http_client = build_vault_client().expect("Failed to build vault HTTP client");

    // ------------------------------------------------------------------------
    // Real Enclave Signature Values from dzta-gramine-prover.sig
    // ------------------------------------------------------------------------
    let mr_signer_hex = "1b70f6701c4fd5443e4016cffaff259914e2042bd4cf207051a7eeb3d017cf9f";
    let mr_enclave_hex = "c04e3943e9a8949769f41526cf5af6b60c665bdb037f44ec4fa46cc244dd4d13";

    let expected_mrsigner = hex::decode(mr_signer_hex).expect("Invalid MRSIGNER hex");
    let expected_mrenclave = hex::decode(mr_enclave_hex).expect("Invalid MRENCLAVE hex");

    println!(
        "🔒 Target Enclave Measurement (MRENCLAVE): {}",
        mr_enclave_hex
    );
    println!(
        "✍️  Target Enclave Signer      (MRSIGNER) : {}",
        mr_signer_hex
    );

    // 1. Initialize Vault Engines
    let datakey_engine = Arc::new(
        VaultDatakeyEngine::from_env(&secret_key_name)
            .expect("Failed to initialize VaultDatakeyEngine from environment"),
    );

    let vault_transit_provider =
        VaultTransitProvider::new(&vault_addr, &vault_token, &secret_key_name)
            .expect("Failed to initialize VaultTransitProvider");

    let vault_kms: Arc<dyn SecretProvider> = Arc::new(VaultSecretRelease {
        provider: vault_transit_provider,
    });

    // 2. Build AppState with actual Gramine Prover measurements
    let app_state = AppState {
        pccs_url: "https://pccs.phala.network".to_string(),
        expected_mrenclave,
        expected_mrsigner,
        kms: vault_kms,
        datakey_engine: Some(datakey_engine),
    };

    // 3. Spawn Local Test Server
    let app = create_router(app_state);
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
    println!(" Broker Server running locally at: {}\n", base_url);

    let key_file_path = Path::new("target/debug/wallet_http_test.key.enc");
    if key_file_path.exists() {
        let _ = fs::remove_file(key_file_path);
    }

    // ------------------------------------------------------------------------
    // PHASE 1: Provisioning DataKey & ZKP Master Seed
    // ------------------------------------------------------------------------
    println!("--- PHASE 1: Ephemeral Enclave Boot & Provisioning ---");
    let mut rng = rand::thread_rng();
    let enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let enclave_pub_pem = enclave_priv_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    println!("Generated 2048-bit RSA Ephemeral Key inside Enclave");

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

    println!("Received HTTP 200 OK from /v1/datakey/provision");
    println!(
        "   └─ Wallet Ciphertext Length: {} bytes",
        provision_res.wallet_ciphertext.len()
    );
    println!(
        "   └─ Seed Ciphertext Length  : {} bytes",
        provision_res.seed_ciphertext.len()
    );

    // Write wallet ciphertext to storage simulating edge persistence
    fs::write(key_file_path, &provision_res.wallet_ciphertext).unwrap();

    // Enclave unwraps the Wallet DEK
    let raw_encrypted_dek = BASE64
        .decode(&provision_res.encrypted_wallet_key_for_enclave)
        .unwrap();
    let initial_unwrapped_dek = enclave_priv_key
        .decrypt(Oaep::new::<RsaSha256>(), &raw_encrypted_dek)
        .expect("Enclave failed to decrypt initial DEK");

    assert_eq!(initial_unwrapped_dek.len(), 32);
    println!(" Enclave successfully unwrapped 32-byte Wallet DEK");

    // Enclave unwraps the ZKP Master Seed
    let raw_encrypted_seed = BASE64
        .decode(&provision_res.encrypted_master_seed_for_enclave)
        .unwrap();
    let initial_unwrapped_seed = enclave_priv_key
        .decrypt(Oaep::new::<RsaSha256>(), &raw_encrypted_seed)
        .expect("Enclave failed to decrypt initial master seed");

    assert_eq!(initial_unwrapped_seed.len(), 32);
    println!(" Enclave successfully unwrapped 32-byte Arkworks ZKP Master Seed");

    // Clean up
    if key_file_path.exists() {
        let _ = fs::remove_file(key_file_path);
    }

    println!("\n=======================================================");
    println!(" Test Completed Successfully!");
    println!("=======================================================\n");
}
