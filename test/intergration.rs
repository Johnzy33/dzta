#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::models::{CredentialAttributes, SchemaAttribute};
    // Adjust this import depending on how you instantiate your FabricClient in tests
    use crate::fabric_client::FabricClient; 

    async fn setup_test_manager() -> CredentialManager {
        // Use an in-memory SQLite database or a temporary test file path for Askar
        let test_db_path = "file:memdb1?mode=memory&cache=shared";
        
        // Initialize your Fabric client (adjust constructor arguments as needed for your codebase)
        let fabric_client = FabricClient::new_mock(); 
        
        CredentialManager::new(fabric_client, test_db_path)
    }

    #[tokio::test]
    async fn test_credential_lifecycle_flow() {
        // 1. Setup the Manager
        let manager = setup_test_manager().await;
        let pass_key = "super_secure_master_password_123";

        // 2. Initialize the secure Askar storage
        let init_result = manager.initialize_askar_store(pass_key).await;
        assert!(init_result.is_ok(), "Failed to initialize Askar store: {:?}", init_result.err());

        // 3. Define schema parameters and register it
        let schema_attrs = vec![
            SchemaAttribute { name: "user_role_id".to_string(), attribute_type: "string".to_string() },
            SchemaAttribute { name: "org_id".to_string(), attribute_type: "string".to_string() },
            SchemaAttribute { name: "clearance_level".to_string(), attribute_type: "integer".to_string() },
        ];
        
        let schema_id = manager
            .register_schema("did:example:issuer", "EmployeeClearance", "1.0.0", &schema_attrs)
            .await
            .expect("Failed to register schema");
        
        assert!(!schema_id.is_empty());

        // 4. Create a fresh credential for a subject
        let attributes = CredentialAttributes {
            user_role_id: "systems_architect".to_string(),
            org_id: "morg_01_alpha".to_string(),
            clearance_level: 4,
            timestamp: chrono::Utc::now().timestamp(),
        };
        
        // Expires 1 hour from now
        let expiry_unix = chrono::Utc::now().timestamp() + 3600; 

        let created_vc = manager
            .create_credential(
                &schema_id,
                "did:example:issuer",
                "did:example:subject",
                &attributes,
                expiry_unix,
            )
            .await
            .expect("Failed to create credential");

        let target_cred_id = created_vc.credential_id.clone();
        assert!(created_vc.stored_in_askar);

        // 5. Retrieve and verify the credential from secure store
        let retrieved_vc = manager
            .get_credential(&target_cred_id)
            .await
            .expect("Failed to retrieve credential");

        assert_eq!(retrieved_vc.credential_id, target_cred_id);
        assert_eq!(retrieved_vc.schema_id, schema_id);
        
        // Validate internal structural payload extracted matches original values
        let extracted_fields = manager
            .extract_proofable_fields(&target_cred_id)
            .await
            .expect("Failed to extract proof fields");

        assert_eq!(extracted_fields.user_role_id, "systems_architect");
        assert_eq!(extracted_fields.clearance_level, 4);

        // 6. Verify that the credential shows up as active/valid
        let is_active = manager
            .verify_credential_active(&target_cred_id)
            .await
            .expect("Error during active status verification");
        
        assert!(is_active, "Credential should be active right after creation");

        // 7. Revoke the credential and verify it reflects accurately
        let revocation_result = manager.revoke_credential(&target_cred_id).await;
        assert!(revocation_result.is_ok());

        // The metadata query should show revoked flag true now
        let askar_metadata = manager
            .get_credential_metadata_from_askar(&target_cred_id)
            .await
            .expect("Failed to read updated metadata");

        assert_eq!(askar_metadata.get("revoked").unwrap().as_bool(), Some(true));

        // Verifying an active status now should explicitly fail out with a RevocationError
        let verify_after_revoke = manager.verify_credential_active(&target_cred_id).await;
        assert!(verify_after_revoke.is_err(), "Verification should fail for a revoked token");
    }
}