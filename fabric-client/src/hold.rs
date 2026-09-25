impl Wallet {
    /// Internal initializer called once a valid passkey is available (either during initial binding or subsequent unsealing).
    pub async fn initialize(&self, pass_key: &str) -> WalletResult<()> {
        if let Some(parent) = std::path::Path::new(&self.askar_store_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WalletError::StorageError(format!("Directory provisioning failed: {}", e)))?;
        }

        use aries_askar::storage::KdfMethod;
        let key_method = StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()));
        let db_uri = if self.askar_store_path.starts_with("file:") || self.askar_store_path.contains("://") {
            self.askar_store_path.clone()
        } else {
            format!("sqlite://{}", self.askar_store_path)
        };

        let path = std::path::Path::new(&self.askar_store_path);
        let store = if path.exists() {
            Store::open(&db_uri, Some(key_method), pass_key.to_string().into(), None).await
        } else {
            Store::provision(&db_uri, key_method, pass_key.to_string().into(), None, false).await
        }
        .map_err(|e| WalletError::StorageError(format!("Askar initialization failed: {}", e)))?;

        *self.askar_store.write().await = Some(store);
        *self.askar_passphrase.write().await = Some(pass_key.to_string());
        Ok(())
    }

    /// Onboarding / Provisioning Phase:
    /// Receives the unsealed passkey alongside the Vault ciphertexts, initializes Askar with that passkey,
    /// and persists the ciphertexts into the `enclave_secrets` table.
    pub async fn provision_and_bind_vault(
        &self,
        credential_id: &str,
        wallet_ciphertext: &str,
        seed_ciphertext: &str,
        unsealed_wallet_passkey: &str,
    ) -> WalletResult<()> {
        // 1. First, initialize/provision the SQLite database using the raw passkey
        self.initialize(unsealed_wallet_passkey).await?;

        // 2. Persist the Vault ciphertexts inside the now-open database
        self.store_enclave_vault_ciphertexts(
            credential_id,
            wallet_ciphertext,
            seed_ciphertext,
        )
        .await?;

        Ok(())
    }

    /// Cold Boot Unsealing Phase:
    /// Unlocks the existing Askar database using the passkey unsealed from Vault Transit.
    pub async fn unlock_with_vault_passkey(&self, unsealed_passkey: &str) -> WalletResult<()> {
        self.initialize(unsealed_passkey).await
    }
}



use shared::{WalletError, WalletResult, VaultEncryptor};
use dzta_wallet::Wallet;
use zeroize::Zeroizing;

/// Complete Enclave Unlocking Pipeline
pub async fn unlock_wallet_from_enclave(
    wallet: &Wallet,
    vault_client: &(impl VaultEncryptor + ?Sized),
    credential_id: &str,
) -> WalletResult<()> {
    // 1. Fetch encrypted Vault ciphertexts stored under "enclave_secrets" in Askar
    let (wallet_ciphertext, _seed_ciphertext) = wallet
        .fetch_enclave_vault_ciphertexts(credential_id)
        .await?;

    // 2. Decrypt wallet_ciphertext using Vault Transit to recover the raw passkey
    // Wraps the returned bytes in Zeroizing memory to wipe host RAM on drop
    let decrypted_bytes: Vec<u8> = vault_client
        .decrypt(&wallet_ciphertext)
        .await
        .map_err(|e| WalletError::StorageError(format!("Vault decryption failed: {e}")))?;

    let unsealed_passkey = Zeroizing::new(
        String::from_utf8(decrypted_bytes)
            .map_err(|e| WalletError::StorageError(format!("Invalid UTF-8 passkey: {e}")))?
    );

    // 3. Unlock local Askar SQLite database using the decrypted passkey
    wallet.unlock_with_vault_passkey(&unsealed_passkey).await?;

    // At this scope boundary, `unsealed_passkey` goes out of scope and gets zeroized in RAM
    Ok(())
}

impl Wallet {
    /// Opens or provisions the underlying Askar SQLite store using the unsealed passkey decrypted from Vault.
    pub async fn unlock_with_vault_passkey(&self, unsealed_passkey: &str) -> WalletResult<()> {
        if let Some(parent) = std::path::Path::new(&self.askar_store_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WalletError::StorageError(format!("Directory creation failed: {e}")))?;
        }

        use aries_askar::storage::KdfMethod;
        let key_method = StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()));
        let db_uri = if self.askar_store_path.starts_with("file:") || self.askar_store_path.contains("://") {
            self.askar_store_path.clone()
        } else {
            format!("sqlite://{}", self.askar_store_path)
        };

        let path = std::path::Path::new(&self.askar_store_path);
        let store = if path.exists() {
            Store::open(&db_uri, Some(key_method), unsealed_passkey.to_string().into(), None).await
        } else {
            Store::provision(&db_uri, key_method, unsealed_passkey.to_string().into(), None, false).await
        }
        .map_err(|e| WalletError::StorageError(format!("Askar unlock failed: {e}")))?;

        *self.askar_store.write().await = Some(store);
        *self.askar_passphrase.write().await = Some(unsealed_passkey.to_string());
        Ok(())
    }
}

// Attestation Broker returns Vault ciphertexts + unsealed wallet key for initial setup
let (wallet_ciphertext, seed_ciphertext, raw_wallet_key) = broker.provision_device().await?;

// Wallet initializes Askar DB with raw_wallet_key and stores the ciphertexts
wallet.provision_and_bind_vault(
    &credential_id,
    &wallet_ciphertext,
    &seed_ciphertext,
    &raw_wallet_key,
).await?;