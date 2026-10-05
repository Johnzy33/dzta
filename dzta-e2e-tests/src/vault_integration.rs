
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dzta_attestation_broker::{
    SecretProvider, VaultDatakeyEngine, VaultSecretRelease, VaultTransitProvider,
};
use dzta_issuer::{CredentialSignerBackend, VaultCredentialSigner};
use dzta_wallet::Wallet;
use rsa::oaep::Oaep;
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use sha2_10::Sha256;
use std::sync::Arc;

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

    // 1. Initialize Datakey Engine & Provision Datakey from Vault
    let engine = VaultDatakeyEngine::new(&vault_addr, &vault_token, &secret_key_name)
    .expect("Failed to create VaultDatakeyEngine");

    let provision_res = engine
    .provision_datakey(&enclave_pub_pem)
    .await
    .expect("Failed to provision datakey from Vault");

    let credential_id = "test-edge-node-1";

    // 2. Decrypt the wrapped wallet key using the Enclave RSA Private Key
    let raw_wallet_key_bytes = enclave_priv_key
    .decrypt(
        Oaep::new::<Sha256>(),
             &BASE64
             .decode(&provision_res.encrypted_wallet_key_for_enclave)
             .expect("Failed to decode base64 enclave wallet key"),
    )
    .expect("Failed to decrypt enclave wallet key with RSA-OAEP");

    // let raw_wallet_key = String::from_utf8(raw_wallet_key_bytes)
    // .expect("Decrypted wallet key is not valid UTF-8");

    let raw_wallet_key = hex::encode(&raw_wallet_key_bytes);

    // 3. Provision Askar DB using the unwrapped raw_wallet_key & store Vault ciphertexts
    wallet
    .provision_and_bind_vault(
        credential_id,
        &provision_res.wallet_ciphertext,
        &provision_res.seed_ciphertext,
        &raw_wallet_key,
    )
    .await
    .expect("Provisioning and Vault binding failed");

    // 4. Fetch stored ciphertexts back out of Askar
    let (wallet_ciphertext, seed_ciphertext) = wallet
    .fetch_enclave_vault_ciphertexts(credential_id)
    .await
    .expect("Failed to fetch ciphertexts from Askar");

    println!("Stored Wallet Ciphertext: {}", wallet_ciphertext);
    println!("Stored Seed Ciphertext: {}", seed_ciphertext);

    assert!(wallet_ciphertext.starts_with("vault:v1:"));
    assert!(seed_ciphertext.starts_with("vault:v1:"));

    // 5. Setup Secret Release Engine and Verified Enclave struct
    let provider = VaultTransitProvider::new(&vault_addr, &vault_token, &secret_key_name)
    .expect("Failed to create VaultTransitProvider");

    let release_engine = VaultSecretRelease { provider };

    let mock_enclave = dzta_attestation_broker::VerifiedEnclave {
        quote: vec![1, 2, 3, 4],
        report_data: vec![5, 6, 7, 8],
        enclave_public_key: enclave_pub_pem,
        mrenclave: "mock_mrenclave_hash".into(),
        mrsigner: "mock_mrsigner_hash".into(),
    };

    // 6. Release secrets for verified enclave
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
