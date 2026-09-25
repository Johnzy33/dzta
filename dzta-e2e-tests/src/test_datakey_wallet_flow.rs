use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dzta_attestation_broker::VaultDatakeyEngine;
use rsa::oaep::Oaep;
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use reqwest::{Certificate, Client};
use sha2_10::Sha256 as RsaSha256;
use std::fs;
use std::path::Path;
use shared::vault_client::*;


#[tokio::test]
async fn test_laptop_option_a_datakey_workflow() {
    let vault_addr = std::env::var("DZTA_VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".into());
    let vault_token = std::env::var("DZTA_VAULT_TOKEN").unwrap_or_else(|_| "root".into());
    let secret_key_name = std::env::var("DZTA_SECRET_RELEASE_KEY").unwrap_or_else(|_| "dzta-key".into());

    let engine = VaultDatakeyEngine::new(&vault_addr, &vault_token, &secret_key_name)
        .expect("Failed to create VaultDatakeyEngine");
    let key_file_dir = Path::new("target/debug");
    let key_file_path = key_file_dir.join("wallet.key.enc");

    if !key_file_dir.exists() {
        fs::create_dir_all(key_file_dir).expect("Failed to create target/debug directory structure");
    }

    // Clean up disk state before running test
    if key_file_path.exists() {
        let _ = fs::remove_file(&key_file_path);
    }

    // ------------------------------------------------------------------------
    // PHASE 1: INITIAL LAPTOP PROVISIONING (NO PASSCODES)
    // ------------------------------------------------------------------------
    
    // 1. Enclave generates session RSA Keypair in hardware isolated memory
    let mut rng = rand::thread_rng();
    let enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let enclave_pub_pem = enclave_priv_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("Failed to export enclave public key");

    // 2. Broker calls Vault Datakey generation
    let provision_res = engine
        .provision_datakey(&enclave_pub_pem)
        .await
        .expect("Failed to provision datakey from Vault");

    // 3. User Laptop saves encrypted DEK ciphertext blob to disk
    fs::write(&key_file_path, &provision_res.wallet_ciphertext)
        .expect("Failed to write wallet.key.enc to disk");

    // 4. Enclave decrypts the initial DEK inside enclave memory
    let raw_encrypted_dek = BASE64
        .decode(&provision_res.encrypted_wallet_key_for_enclave)
        .expect("Failed to b64 decode encrypted DEK");
    
    let initial_unwrapped_dek = enclave_priv_key
        .decrypt(Oaep::new::<RsaSha256>(), &raw_encrypted_dek)
        .expect("Enclave failed to decrypt initial DEK");

    assert_eq!(initial_unwrapped_dek.len(), 32, "DEK must be 256 bits");
    println!("✓ Phase 1 complete: Laptop provisioned. Ciphertext saved to disk.");

    // ------------------------------------------------------------------------
    // PHASE 2: SUBSEQUENT LOGIN / ZKP PROOF GENERATION SESSION
    // ------------------------------------------------------------------------

    // 1. User triggers login. Host OS reads `wallet.key.enc` from disk
    let stored_ciphertext = fs::read_to_string(&key_file_path)
        .expect("Failed to read wallet.key.enc from disk");

    // 2. Enclave creates a fresh RSA keypair for this new session
    let session_enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let session_enclave_pub_pem = session_enclave_priv_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    // 3. Enclave passes quote & stored_ciphertext to Broker.
    // Broker unwraps via Vault & wraps for `session_enclave_pub_pem`
    let session_encrypted_dek_b64 = engine
        .unwrap_datakey_for_enclave(&stored_ciphertext, &session_enclave_pub_pem)
        .await
        .expect("Failed to unwrap datakey for session enclave");

    // 4. Enclave unwraps DEK in isolated memory & verifies it matches original key
    let session_encrypted_dek = BASE64.decode(&session_encrypted_dek_b64).unwrap();
    let session_unwrapped_dek = session_enclave_priv_key
        .decrypt(Oaep::new::<RsaSha256>(), &session_encrypted_dek)
        .expect("Enclave failed to decrypt DEK for active session");

    assert_eq!(
        initial_unwrapped_dek, session_unwrapped_dek,
        "Unwrapped session DEK must match initial provisioning DEK"
    );

    println!("✓ Phase 2 complete: Askar wallet unlocked inside enclave memory without human passcodes.");

    // Clean up created test file after successful test execution
    // let _ = fs::remove_file(&key_file_path);
}