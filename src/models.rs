// src/models.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// DID Document (from Fabric chaincode)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    pub did: String,
    pub issuer_did: String,
    pub public_key: String,
    pub created: i64,
    pub updated: i64,
    pub active: bool,
}

/// Credential Metadata (from Fabric chaincode)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub credential_id: String,
    pub schema_id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
    pub zkp_supported: bool,
    pub proofable_fields: Vec<String>,
}

/// Credential Schema (from Fabric chaincode)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSchema {
    pub schema_id: String,
    pub issuer_did: String,
    pub name: String,
    pub version: String,
    pub attributes: Vec<SchemaAttribute>,
    pub created: i64,
}

/// Schema Attribute Definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaAttribute {
    pub name: String,
    #[serde(rename = "type")]
    pub attr_type: String, // "string", "integer", "timestamp"
    pub predicate: bool,   // Can be used in ZKP predicate
}

/// Helper module for serializing/deserializing DateTime<Utc> as a unix timestamp.
mod datetime_utc {
    use chrono::DateTime;
    use chrono::TimeZone;
    use chrono::Utc;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(dt.timestamp())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ts = i64::deserialize(deserializer)?;
        // Construct DateTime<Utc> directly from seconds
        Ok(Utc.timestamp_opt(ts, 0).unwrap())
    }
}

mod option_datetime_utc {
    use chrono::DateTime;
    use chrono::TimeZone;
    use chrono::Utc;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(dt) => serializer.serialize_some(&dt.timestamp()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<i64>::deserialize(deserializer)?;
        match opt {
            Some(ts) => {
                // Construct DateTime<Utc> directly from seconds
                Ok(Some(Utc.timestamp_opt(ts, 0).single().unwrap()))
            }
            None => Ok(None),
        }
    }
}

/// VCX Credential (stored in Askar)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: String,
    pub schema_id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub credential_data: serde_json::Value, // Raw VC JSON-LD
    #[serde(with = "datetime_utc")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "option_datetime_utc")]
    pub expires_at: Option<DateTime<Utc>>,
    pub stored_in_askar: bool,
}

/// Credential Attributes (specific fields to be proven)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAttributes {
    pub user_role_id: String,
    pub org_id: String,
    pub clearance_level: u32,
    pub timestamp: i64,
}

/// ZKP Witness — Input for Circom circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKPWitness {
    pub credential_id: String,
    pub schema_id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub user_role_id: String,
    pub org_id: String,
    pub clearance_level: u32,
    pub timestamp: i64,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl ZKPWitness {
    /// Convert witness to Circom-compatible JSON
    pub fn to_circom_input(&self) -> serde_json::Value {
        serde_json::json!({
            "credentialId": self.credential_id,
            "schemaId": self.schema_id,
            "issuerDid": self.issuer_did,
            "subjectDid": self.subject_did,
            "userRoleId": self.user_role_id,
            "orgId": self.org_id,
            "clearanceLevel": self.clearance_level,
            "timestamp": self.timestamp,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
        })
    }
}

/// Invocation payload for Fabric chaincode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaincodeInvocation {
    pub function: String,
    pub args: Vec<String>,
}

/// Chaincode response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaincodeResponse {
    pub status: u32,
    pub payload: Vec<u8>,
    pub message: String,
}
