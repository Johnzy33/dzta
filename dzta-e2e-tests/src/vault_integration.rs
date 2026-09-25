
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dzta_attestation_broker::{SecretProvider, VaultSecretRelease, VaultTransitProvider, VaultDatakeyEngine};
use dzta_issuer::{CredentialSignerBackend, VaultCredentialSigner};
use dzta_wallet::Wallet;
use reqwest::{Certificate, Client};
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use std::fs;
use std::sync::Arc;

// fn build_test_client() -> Client {
//     let mut builder = Client::builder().timeout(std::time::Duration::from_secs(10));

//     if let Ok(ca_path) = std::env::var("VAULT_CACERT") {
//         if let Ok(ca_cert_bytes) = fs::read(&ca_path) {
//             if let Ok(cert) = Certificate::from_pem(&ca_cert_bytes) {
//                 builder = builder.add_root_certificate(cert);
//             }
//         }
//     }

//     builder.build().expect("Failed to build test HTTP client")
// }

#[tokio::test]
async fn test_vault_credential_signing_flow() {
    // 1. Initialize Vault Signer from env (reads VAULT_CACERT internally)
    let signer = VaultCredentialSigner::from_env()
        .expect("Failed to create VaultCredentialSigner from env");

    // 2. Retrieve public key multibase from Vault
    let pub_key_mb = signer
        .public_key_multibase()
        .await
        .expect("Failed to fetch public key multibase from Vault");
    println!("Vault Ed25519 Multibase Public Key: {}", pub_key_mb);

    // 3. Sign a payload via Vault Transit API
    let payload = b"dZTA-verifiable-credential-proof-payload";
    let proof_value = signer
        .sign(payload)
        .await
        .expect("Failed to sign payload via Vault");
    println!("Generated Proof Value: {}", proof_value);

    assert!(
        proof_value.starts_with('u'),
        "Proof value must be base64url prefixed with 'u'"
    );
}

// #[tokio::test]
// async fn test_vault_secret_release_and_enclave_wrapping_flow() {
//     let vault_addr = std::env::var("DZTA_VAULT_ADDR").expect("DZTA_VAULT_ADDR missing");
//     let vault_token = std::env::var("DZTA_VAULT_TOKEN").expect("DZTA_VAULT_TOKEN missing");
//     let secret_key_name =
//         std::env::var("DZTA_SECRET_RELEASE_KEY").expect("DZTA_SECRET_RELEASE_KEY missing");

//     // 1. Encrypt raw test secrets into Vault Transit ciphertexts
//     let provider = VaultTransitProvider::new(&vault_addr, &vault_token, &secret_key_name)
//         .expect("Failed to create VaultTransitProvider");

//     // Custom client equipped with VAULT_CACERT for setup requests
//     let client = build_test_client();
//     let encrypt_url = format!(
//         "{}/v1/transit/encrypt/{}",
//         vault_addr.trim_end_matches('/'),
//         secret_key_name
//     );

//     let raw_wallet_key = BASE64.encode(b"01234567890123456789012345678901");
//     let raw_master_seed = BASE64.encode(b"abcdefghijklmnopqrstuvwxyz123456");

//     let wallet_resp: serde_json::Value = client
//         .post(&encrypt_url)
//         .header("X-Vault-Token", &vault_token)
//         .json(&serde_json::json!({ "plaintext": raw_wallet_key }))
//         .send()
//         .await
//         .expect("Encrypt request failed")
//         .json()
//         .await
//         .expect("Failed to parse encryption response");

//     let seed_resp: serde_json::Value = client
//         .post(&encrypt_url)
//         .header("X-Vault-Token", &vault_token)
//         .json(&serde_json::json!({ "plaintext": raw_master_seed }))
//         .send()
//         .await
//         .expect("Encrypt request failed")
//         .json()
//         .await
//         .expect("Failed to parse encryption response");

//     let wallet_ciphertext = wallet_resp["data"]["ciphertext"]
//         .as_str()
//         .unwrap()
//         .to_string();
//     let seed_ciphertext = seed_resp["data"]["ciphertext"]
//         .as_str()
//         .unwrap()
//         .to_string();

//     // 2. Simulate Enclave RSA Keypair Generation
//     let mut rng = rand::thread_rng();
//     let enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
//     let enclave_pub_pem = enclave_priv_key
//         .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
//         .unwrap();

//     // Updated: VaultSecretRelease now only wraps the VaultTransitProvider
//     let release_engine = VaultSecretRelease { provider };

//     let mock_enclave = dzta_attestation_broker::VerifiedEnclave {
//         quote: vec![1, 2, 3, 4],
//         report_data: vec![5, 6, 7, 8],
//         enclave_public_key: enclave_pub_pem,
//         mrenclave: "mock_mrenclave_hash".into(),
//         mrsigner: "mock_mrsigner_hash".into(),
//     };

//     // 3. Updated: Pass wallet_ciphertext and seed_ciphertext as per-request arguments
//     let wrapped_secrets = release_engine
//         .release_for_verified_enclave(
//             &mock_enclave,
//             "key-v1",
//             &wallet_ciphertext,
//             &seed_ciphertext,
//         )
//         .await
//         .expect("Vault secret unwrap & enclave wrapping failed");

//     println!(
//         "Encrypted Wallet Key (Base64 RSA-OAEP): {}",
//         wrapped_secrets.encrypted_wallet_key
//     );
//     println!(
//         "Encrypted Master Seed (Base64 RSA-OAEP): {}",
//         wrapped_secrets.encrypted_master_seed
//     );

//     assert!(!wrapped_secrets.encrypted_wallet_key.is_empty());
//     assert_eq!(
//         wrapped_secrets.key_encryption_algorithm,
//         "RSA-OAEP-SHA256:key-v1"
//     );
// }


#[tokio::test]
async fn test_wallet_secret_release_and_enclave_wrapping_flow() {
    let vault_addr = std::env::var("DZTA_VAULT_ADDR").expect("DZTA_VAULT_ADDR missing");
    let vault_token = std::env::var("DZTA_VAULT_TOKEN").expect("DZTA_VAULT_TOKEN missing");
    let secret_key_name =
        std::env::var("DZTA_SECRET_RELEASE_KEY").expect("DZTA_SECRET_RELEASE_KEY missing");

    let askar_db_path = "target/debug/test_askar_wallet.db";

    // Clean up test database if it exists
    if std::path::Path::new(askar_db_path).exists() {
        let _ = std::fs::remove_file(askar_db_path);
    }

    let mut rng = rand::thread_rng();
    let enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let enclave_pub_pem = enclave_priv_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("Failed to export enclave public key");

    let wallet = Arc::new(Wallet::new(askar_db_path));

    // 1. Initialize both Vault providers separately
    let engine = VaultDatakeyEngine::new(&vault_addr, &vault_token, &secret_key_name)
        .expect("Failed to create VaultDatakeyEngine");


    let provision_res = engine
        .provision_datakey(&enclave_pub_pem)
        .await
        .expect("Failed to provision datakey from Vault");

    let credential_id = "test-edge-node-1";
    // let user_passkey = "test_passkey_1234567890";

    // 2. Pass VaultDatakeyEngine (for seed generation)
    wallet
        .provision_and_bind_vault(credential_id, &provision_res.wallet_ciphertext, &provision_res.seed_ciphertext, &provision_res.wallet_ciphertext)
        .await
        .expect("Provisioning and Vault binding failed");

    // 3. Fetch stored ciphertexts back out of Askar
    let (wallet_ciphertext, seed_ciphertext) = wallet
        .fetch_enclave_vault_ciphertexts(credential_id)
        .await
        .expect("Failed to fetch ciphertexts from Askar");

    println!("Stored Wallet Ciphertext: {}", wallet_ciphertext);
    println!("Stored Seed Ciphertext: {}", seed_ciphertext);

    assert!(wallet_ciphertext.starts_with("vault:v1:"));
    assert!(seed_ciphertext.starts_with("vault:v1:"));

    // 4. Setup VaultTransitProvider and Mock Enclave RSA Keypair
    let provider = VaultTransitProvider::new(&vault_addr, &vault_token, &secret_key_name)
        .expect("Failed to create VaultTransitProvider");

    let mut rng = rand::thread_rng();
    let enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let enclave_pub_pem = enclave_priv_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let release_engine = VaultSecretRelease { provider };

    let mock_enclave = dzta_attestation_broker::VerifiedEnclave {
        quote: vec![1, 2, 3, 4],
        report_data: vec![5, 6, 7, 8],
        enclave_public_key: enclave_pub_pem,
        mrenclave: "mock_mrenclave_hash".into(),
        mrsigner: "mock_mrsigner_hash".into(),
    };

    // 5. Unwrap secrets using the per-request ciphertexts retrieved from Askar
    let wrapped_secrets = release_engine
        .release_for_verified_enclave(
            &mock_enclave,
            "key-v1",
            &wallet_ciphertext,
            &seed_ciphertext,
        )
        .await
        .expect("Vault secret unwrap & enclave wrapping failed");
    
    println!(
        "Encrypted Wallet Key (Base64 RSA-OAEP): {}",
        wrapped_secrets.encrypted_wallet_key
    );
    println!(
        "Encrypted Master Seed (Base64 RSA-OAEP): {}",
        wrapped_secrets.encrypted_master_seed
    );
    assert!(!wrapped_secrets.encrypted_wallet_key.is_empty());
    assert!(!wrapped_secrets.encrypted_master_seed.is_empty());
    assert_eq!(
        wrapped_secrets.key_encryption_algorithm,
        "RSA-OAEP-SHA256:key-v1"
    );
}