use chrono::Utc;
use fabric_client::{FabricClient, SchemaEngine};
use serde_json::json;
use shared::{
    CredentialAttributes, DIDDocument, IssuedCredential, SchemaAttribute, WalletError,
    WalletResult,
};
use uuid::Uuid;
use std::sync::Arc;

mod signer;
pub use signer::{CredentialSignerBackend, LocalCredentialSigner, VaultCredentialSigner};

/// Issuer workflow that creates credential payloads and anchors public metadata on Fabric.
pub struct Issuer {
    pub fabric: FabricClient,
    pub signer: Arc<dyn CredentialSignerBackend>,
}

impl Issuer {
    pub fn new<S>(fabric: FabricClient, signer: S) -> Self
    where
        S: CredentialSignerBackend + 'static,
    {
        Self { fabric, signer: Arc::new(signer) }
    }

    /// Register an issuer or subject DID on the Fabric ledger.
    pub async fn register_did(
        &self,
        did: &str,
        issuer_did: &str,
        public_key: &str,
    ) -> WalletResult<String> {
        self.fabric.register_did(did, issuer_did, public_key).await
    }

    pub async fn register_signing_did(&self, issuer_did: &str) -> WalletResult<String> {
        let public_key = self.signer.public_key_multibase().await?;
        self.fabric.register_did(issuer_did, issuer_did, &public_key).await
    }

    /// Resolve any DID from the Fabric ledger. This is also available directly
    /// through FabricClient for holders and verifiers.
    pub async fn resolve_did(&self, did: &str) -> WalletResult<DIDDocument> {
        self.fabric.resolve_did(did).await
    }

    /// List the DIDs registered by an issuer.
    pub async fn query_dids_by_issuer(
        &self,
        issuer_did: &str,
    ) -> WalletResult<Vec<DIDDocument>> {
        self.fabric.query_dids_by_issuer(issuer_did).await
    }

    pub async fn register_schema(
        &self,
        issuer_did: &str,
        name: &str,
        version: &str,
        attributes: &[SchemaAttribute],
    ) -> WalletResult<String> {
        let schema_id = Uuid::new_v4().to_string();
        self.fabric.register_schema(&schema_id, issuer_did, name, version, attributes).await?;
        Ok(schema_id)
    }

    pub async fn create_credential(
        &self,
        schema_id: &str,
        issuer_did: &str,
        subject_did: &str,
        attributes: &CredentialAttributes,
        expires_at_unix: i64,
    ) -> WalletResult<IssuedCredential> {
        if issuer_did.trim().is_empty() || subject_did.trim().is_empty() {
            return Err(WalletError::ConfigError(
                "Issuer DID and subject DID are required".into(),
            ));
        }
        if expires_at_unix <= Utc::now().timestamp() {
            return Err(WalletError::ConfigError(
                "Credential expiration must be in the future".into(),
            ));
        }
        let credential_id = Uuid::new_v4().to_string();
        let schema = self.fabric.get_schema(schema_id).await?;
        let subject = json!({
            "id": subject_did,
            "userRoleId": attributes.user_role_id,
            "orgId": attributes.org_id,
            "clearanceLevel": attributes.clearance_level,
            "timestamp": attributes.timestamp,
        });
        SchemaEngine::validate_fields(&schema, &subject)?;
        let issued_at = Utc::now();
        let expires_at = chrono::DateTime::<Utc>::from_timestamp(expires_at_unix, 0)
            .ok_or_else(|| WalletError::ConfigError("Invalid expiration timestamp".into()))?;
        let mut credential_data = json!({
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
            "type": ["VerifiableCredential"],
            "issuer": issuer_did,
            "issuanceDate": issued_at.to_rfc3339(),
            "expirationDate": expires_at.to_rfc3339(),
            "credentialSubject": subject,
        });
        let proof_options = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": issued_at.to_rfc3339(),
            "proofPurpose": "assertionMethod",
            "verificationMethod": format!("{}#key-1", issuer_did),
        });
        let signing_input = serde_jcs::to_vec(&json!({
            "credential": credential_data,
            "proof": proof_options,
        })).map_err(|e| WalletError::SigningError(format!("JCS canonicalization failed: {}", e)))?;
        let signature = self.signer.sign(&signing_input).await?;
        credential_data["proof"] = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": issued_at.to_rfc3339(),
            "proofPurpose": "assertionMethod",
            "verificationMethod": format!("{}#key-1", issuer_did),
            "proofValue": signature,
        });
        self.fabric.record_credential_metadata(&credential_id, schema_id, issuer_did, subject_did, expires_at_unix).await?;
        Ok(IssuedCredential {
            credential_id,
            schema_id: schema_id.into(),
            issuer_did: issuer_did.into(),
            subject_did: subject_did.into(),
            credential_data,
            issued_at,
            expires_at: Some(expires_at),
        })
    }

    pub async fn revoke_credential(&self, credential_id: &str) -> WalletResult<()> {
        self.fabric.revoke_credential(credential_id).await?;
        Ok(())
    }
}

pub use shared::{CredentialAttributes as IssuerCredentialAttributes, SchemaAttribute as IssuerSchemaAttribute};