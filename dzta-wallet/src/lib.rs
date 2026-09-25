//dzta-wallet/src/lib.rs
use aries_askar::{entry::EntryTag, Store, StoreKeyMethod};
use getrandom;
use log::error;
use serde_json::Value;
use shared::{encrypt_wallet_record, CredentialAttributes, WalletError, WalletResult, VaultEncryptor};
use std::sync::Arc;
use zeroize::Zeroizing;
// use shared::zkp_core::VaultEncryptor;

// use shared::errors::{WalletError, WalletResult};

pub use shared::{CredentialAttributes as WalletCredentialAttributes, StoredCredential};

/// Private local credential storage. This crate has no Fabric dependency.
pub struct Wallet {
    pub askar_store_path: String,
    pub askar_store: Arc<tokio::sync::RwLock<Option<Store>>>,
    askar_passphrase: Arc<tokio::sync::RwLock<Option<String>>>,
}

impl Wallet {
    pub fn new(askar_store_path: impl Into<String>) -> Self {
        Self {
            askar_store_path: askar_store_path.into(),
            askar_store: Arc::new(tokio::sync::RwLock::new(None)),
            askar_passphrase: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

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

    pub async fn get_askar_passphrase(&self) -> WalletResult<Vec<u8>> {
        self.askar_passphrase.read().await.as_ref().map(|pass| pass.as_bytes().to_vec())
            .ok_or_else(|| WalletError::StorageError("Askar store passphrase not cached".into()))
    }

    pub async fn fetch_raw_encrypted_record(&self, credential_id: &str) -> WalletResult<Vec<u8>> {
        let store = self.store().await?;
        let mut session = store.session(None).await.map_err(storage_error)?;
        let entry = session.fetch("credentials", credential_id, false).await.map_err(storage_error)?
            .ok_or_else(|| WalletError::CredentialNotFound(credential_id.to_string()))?;
        Ok(entry.value.to_vec())
    }

    pub async fn store_credential(&self, credential_id: &str, credential_data: &Value) -> WalletResult<()> {
        let store = self.store().await?;
        let encrypted = encrypt_wallet_record(credential_data.to_string().as_bytes(), &self.get_askar_passphrase().await?)
            .map_err(|e| WalletError::StorageError(e.to_string()))?;
        let mut session = store.session(None).await.map_err(storage_error)?;
        let tags = vec![
            EntryTag::Plaintext("stored_at".into(), chrono::Utc::now().to_rfc3339()),
            EntryTag::Plaintext("revoked".into(), "false".into()),
        ];
        session.insert("credentials", credential_id, &encrypted, Some(&tags), None).await.map_err(storage_error)?;
        session.commit().await.map_err(storage_error)?;
        Ok(())
    }

    pub async fn get_credential(&self, credential_id: &str) -> WalletResult<Value> {
        let store = self.store().await?;
        let mut session = store.session(None).await.map_err(storage_error)?;
        let entry = session.fetch("credentials", credential_id, false).await.map_err(storage_error)?
            .ok_or_else(|| WalletError::CredentialNotFound(credential_id.to_string()))?;
        let cleartext = shared::zkp_core::decrypt_wallet_record(&entry.value, &self.get_askar_passphrase().await?)
            .map_err(|e| WalletError::StorageError(e.to_string()))?;
        serde_json::from_slice(&cleartext).map_err(WalletError::SerializationError)
    }

    pub async fn get_or_create_zkp_secret_seed(&self) -> WalletResult<Vec<u8>> {
        let store = self.store().await?;
        let mut session = store.session(None).await.map_err(storage_error)?;
        if let Some(entry) = session.fetch("keys", "master_zkp_seed", false).await.map_err(storage_error)? {
            return Ok(entry.value.to_vec());
        }
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| WalletError::StorageError(format!("RNG generation failed: {}", e)))?;
        session.insert("keys", "master_zkp_seed", &seed, None, None).await.map_err(storage_error)?;
        session.commit().await.map_err(storage_error)?;
        Ok(seed.to_vec())
    }

    pub async fn store_enclave_vault_ciphertexts(
        &self,
        credential_id: &str,
        wallet_key_ciphertext: &str,
        master_seed_ciphertext: &str,
    ) -> WalletResult<()> {
        let store = self.store().await?;
        let mut session = store.session(None).await.map_err(storage_error)?;

        let record_payload = serde_json::json!({
            "credential_id": credential_id,
            "wallet_key_ciphertext": wallet_key_ciphertext,
            "master_seed_ciphertext": master_seed_ciphertext,
            "created_at": chrono::Utc::now().timestamp(),
        });

        let payload_bytes = serde_json::to_vec(&record_payload)
            .map_err(WalletError::SerializationError)?;

        // Store directly in Askar under category "enclave_secrets"
        session
            .insert("enclave_secrets", credential_id, &payload_bytes, None, None)
            .await
            .map_err(storage_error)?;

        session.commit().await.map_err(storage_error)?;
        Ok(())
    }

    pub async fn fetch_enclave_vault_ciphertexts(
        &self,
        credential_id: &str,
    ) -> WalletResult<(String, String)> {
        let store = self.store().await?;
        let mut session = store.session(None).await.map_err(storage_error)?;

        let entry = session
            .fetch("enclave_secrets", credential_id, false)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| WalletError::StorageError(format!("No enclave secrets found for credential: {}", credential_id)))?;

        let val: serde_json::Value = serde_json::from_slice(&entry.value)
            .map_err(WalletError::SerializationError)?;

        let wallet_key_ciphertext = val["wallet_key_ciphertext"]
            .as_str()
            .ok_or_else(|| WalletError::StorageError("Invalid wallet_key_ciphertext in Askar".into()))?
            .to_string();

        let master_seed_ciphertext = val["master_seed_ciphertext"]
            .as_str()
            .ok_or_else(|| WalletError::StorageError("Invalid master_seed_ciphertext in Askar".into()))?
            .to_string();

        Ok((wallet_key_ciphertext, master_seed_ciphertext))
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

    
    pub async fn extract_proofable_fields(&self, credential_id: &str) -> WalletResult<CredentialAttributes> {
        let credential = self.get_credential(credential_id).await?;
        let subject = credential.get("credentialSubject")
            .ok_or_else(|| WalletError::InvalidWitness("Missing credentialSubject".into()))?;
        Ok(CredentialAttributes {
            user_role_id: subject.get("userRoleId").and_then(Value::as_str)
                .ok_or_else(|| WalletError::InvalidWitness("Missing userRoleId".into()))?.into(),
            org_id: subject.get("orgId").and_then(Value::as_str)
                .ok_or_else(|| WalletError::InvalidWitness("Missing orgId".into()))?.into(),
            clearance_level: subject.get("clearanceLevel").and_then(Value::as_u64)
                .ok_or_else(|| WalletError::InvalidWitness("Missing clearanceLevel".into()))?,
            timestamp: subject.get("timestamp").and_then(Value::as_i64)
                .ok_or_else(|| WalletError::InvalidWitness("Missing timestamp".into()))?,
        })
    }

    pub async fn mark_credential_revoked(&self, credential_id: &str) -> WalletResult<()> {
        let store = self.store().await?;
        let mut session = store.session(None).await.map_err(storage_error)?;
        let entry = session.fetch("credentials", credential_id, false).await.map_err(storage_error)?
            .ok_or_else(|| WalletError::CredentialNotFound(credential_id.to_string()))?;
        let tags = vec![
            EntryTag::Plaintext("revoked".into(), "true".into()),
            EntryTag::Plaintext("revoked_at".into(), chrono::Utc::now().to_rfc3339()),
        ];
        session.replace("credentials", credential_id, &entry.value, Some(&tags), None).await.map_err(storage_error)?;
        session.commit().await.map_err(storage_error)?;
        Ok(())
    }

    async fn store(&self) -> WalletResult<Store> {
        self.askar_store.read().await.clone()
            .ok_or_else(|| WalletError::StorageError("Askar store not initialized".into()))
    }
}

fn storage_error(error: impl std::fmt::Display) -> WalletError {
    error!("Askar operation failed: {}", error);
    WalletError::StorageError(error.to_string())
}
