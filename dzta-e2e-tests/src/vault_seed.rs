use dzta_attestation_broker::{SecretProvider, VaultSecretRelease, VaultTransitProvider, VaultDatakeyEngine};
use shared::vault_client::VaultSeed;
#[tokio::test]
async fn test_live_vault_random_seed_generation() {
    let vault_addr = std::env::var("DZTA_VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".into());
    let vault_token = std::env::var("DZTA_VAULT_TOKEN").unwrap_or_else(|_| "root".into());
    let secret_key_name = std::env::var("DZTA_SECRET_RELEASE_KEY").unwrap_or_else(|_| "key-v1".into());

    let engine = VaultDatakeyEngine::new(&vault_addr, &vault_token, &secret_key_name).unwrap();

    // Call live Vault endpoint
    let seed1 = engine.generate_vault_random_seed().await.unwrap();
    let seed2 = engine.generate_vault_random_seed().await.unwrap();

    // Print raw byte length and hex string representation
    println!("\n================ VAULT GENERATED SEED ================");
    println!("Byte length : {} bytes", seed1.len());
    println!("Hex payload : {}", hex::encode(seed1.as_slice()));
    println!("Raw bytes   : {:?}", seed1.as_slice());
    println!("======================================================\n");

    // Verify entropy
    assert_eq!(seed1.len(), 32);
    assert_eq!(seed2.len(), 32);
    assert_ne!(seed1.as_slice(), seed2.as_slice(), "Subsequent calls to Vault must yield different entropy");
}