// src/witness_generator.rs
use crate::errors::{WalletError, WalletResult};
use crate::models::*;
use crate::credential_manager::CredentialManager;
use serde_json::{json, Value};
use log::{info, debug};

pub struct ZKPWitnessGenerator {
    credential_manager: std::sync::Arc<CredentialManager>,
}

impl ZKPWitnessGenerator {
    /// Initialize witness generator
    pub fn new(credential_manager: std::sync::Arc<CredentialManager>) -> Self {
        info!("Initializing ZKP witness generator");

        ZKPWitnessGenerator {
            credential_manager,
        }
    }

    /// Generate ZKP witness from credential
    pub async fn generate_witness(&self, credential_id: &str) -> WalletResult<ZKPWitness> {
        debug!("Generating ZKP witness for credential: {}", credential_id);

        // Verify credential is active (not revoked, not expired)
        self.credential_manager
            .verify_credential_active(credential_id)
            .await?;

        // Retrieve credential metadata from Fabric
        let metadata = self
            .credential_manager
            .fabric_client
            .get_credential_metadata(credential_id)
            .await?;

        // Extract proofable fields from credential
        let attributes = self
            .credential_manager
            .extract_proofable_fields(credential_id)
            .await?;

        // Construct witness
        let witness = ZKPWitness {
            credential_id: metadata.credential_id.clone(),
            schema_id: metadata.schema_id.clone(),
            issuer_did: metadata.issuer_did.clone(),
            subject_did: metadata.subject_did.clone(),
            user_role_id: attributes.user_role_id,
            org_id: attributes.org_id,
            clearance_level: attributes.clearance_level,
            timestamp: attributes.timestamp,
            issued_at: metadata.issued_at,
            expires_at: metadata.expires_at,
        };

        info!("ZKP witness generated for credential: {}", credential_id);
        Ok(witness)
    }

    /// Generate witness and export as Circom JSON input
    pub async fn generate_circom_input(
        &self,
        credential_id: &str,
    ) -> WalletResult<Value> {
        let witness = self.generate_witness(credential_id).await?;
        Ok(witness.to_circom_input())
    }

    /// Generate witness with additional constraints (for range proofs, etc.)
    pub async fn generate_witness_with_constraints(
        &self,
        credential_id: &str,
        constraints: WitnessConstraints,
    ) -> WalletResult<Value> {
        let witness = self.generate_witness(credential_id).await?;

        // Apply constraints and return enriched witness
        let mut circom_input = witness.to_circom_input();

        // Add constraint flags
        circom_input["constraints"] = json!({
            "minClearanceLevel": constraints.min_clearance_level,
            "maxClearanceLevel": constraints.max_clearance_level,
            "allowedOrgs": constraints.allowed_orgs,
            "timeWindow": {
                "start": constraints.time_window_start,
                "end": constraints.time_window_end,
            },
        });

        Ok(circom_input)
    }

    /// Batch generate witnesses for multiple credentials
    pub async fn generate_batch_witnesses(
        &self,
        credential_ids: &[&str],
    ) -> WalletResult<Vec<ZKPWitness>> {
        let mut witnesses = Vec::new();

        for cred_id in credential_ids {
            match self.generate_witness(cred_id).await {
                Ok(witness) => witnesses.push(witness),
                Err(e) => {
                    debug!("Failed to generate witness for {}: {}", cred_id, e);
                    // Continue on error
                }
            }
        }

        Ok(witnesses)
    }

    /// Export witness to file (for Circom input)
    pub async fn export_witness_to_file(
        &self,
        credential_id: &str,
        output_path: &str,
    ) -> WalletResult<()> {
        let witness = self.generate_witness(credential_id).await?;
        let circom_input = witness.to_circom_input();

        let json_str = serde_json::to_string_pretty(&circom_input)
            .map_err(|e| WalletError::SerializationError(e))?;

        std::fs::write(output_path, json_str)
            .map_err(|e| WalletError::Unknown(format!("Failed to write witness file: {}", e)))?;

        info!("Witness exported to: {}", output_path);
        Ok(())
    }

    /// Validate witness format before sending to Circom
    pub fn validate_witness(&self, witness: &ZKPWitness) -> WalletResult<()> {
        if witness.credential_id.is_empty() {
            return Err(WalletError::InvalidWitness(
                "credential_id cannot be empty".to_string(),
            ));
        }

        if witness.user_role_id.is_empty() {
            return Err(WalletError::InvalidWitness(
                "user_role_id cannot be empty".to_string(),
            ));
        }

        if witness.org_id.is_empty() {
            return Err(WalletError::InvalidWitness(
                "org_id cannot be empty".to_string(),
            ));
        }

        if witness.timestamp <= 0 {
            return Err(WalletError::InvalidWitness(
                "timestamp must be positive".to_string(),
            ));
        }

        Ok(())
    }
}

/// Constraints for witness generation (optional)
#[derive(Debug, Clone)]
pub struct WitnessConstraints {
    pub min_clearance_level: u32,
    pub max_clearance_level: u32,
    pub allowed_orgs: Vec<String>,
    pub time_window_start: i64,
    pub time_window_end: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_validation() {
        let valid_witness = ZKPWitness {
            credential_id: "cred123".to_string(),
            schema_id: "schema456".to_string(),
            issuer_did: "did:example:issuer".to_string(),
            subject_did: "did:example:subject".to_string(),
            user_role_id: "admin".to_string(),
            org_id: "org789".to_string(),
            clearance_level: 5,
            timestamp: 1688000000,
            issued_at: 1688000000,
            expires_at: 1720000000,
        };

        let generator = ZKPWitnessGenerator::new(std::sync::Arc::new(
            CredentialManager::new(
                // Mock fabric client (would need actual setup in tests)
                unimplemented!(),
                "/tmp/askar",
            ),
        ));

        assert!(generator.validate_witness(&valid_witness).is_ok());
    }

    #[test]
    fn test_witness_to_circom_input() {
        let witness = ZKPWitness {
            credential_id: "cred123".to_string(),
            schema_id: "schema456".to_string(),
            issuer_did: "did:example:issuer".to_string(),
            subject_did: "did:example:subject".to_string(),
            user_role_id: "admin".to_string(),
            org_id: "org789".to_string(),
            clearance_level: 5,
            timestamp: 1688000000,
            issued_at: 1688000000,
            expires_at: 1720000000,
        };

        let circom_input = witness.to_circom_input();
        assert_eq!(
            circom_input["userRoleId"].as_str().unwrap(),
            "admin"
        );
        assert_eq!(circom_input["clearanceLevel"].as_u64().unwrap(), 5);
    }
}
