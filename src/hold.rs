use async_trait::async_trait;
use std::fmt::Debug;


use anoncreds_types::data_types::{
    identifiers::{cred_def_id::CredentialDefinitionId, schema_id::SchemaId, rev_reg_def_id::RevocationRegistryDefinitionId},
    ledger::{cred_def::CredentialDefinition, schema::Schema, rev_reg_def::RevocationRegistryDefinition, rev_reg_delta::RevocationRegistryDelta},
};
use aries_vcx_wallet::wallet::base_wallet::BaseWallet;
use did_parser_nom::Did;


use aries_vcx_ledger::errors::error::VcxLedgerError;

#[derive(Debug)]
pub struct FabricLedgerBillboard;

#[async_trait]
impl aries_vcx_ledger::ledger::base_ledger::AnoncredsLedgerWrite for FabricLedgerBillboard {
    async fn publish_schema(
        &self,
        _wallet: &impl BaseWallet,
        schema_json: Schema,
        _submitter_did: &Did,
        _endorser_did: Option<&Did>,
    ) -> Result<(), VcxLedgerError> { // Fixed Error Type here
        println!("\n[Billboard Notification] -> A new ID template has been pinned to the board!");
        println!("The Schema ID registered is: {}", schema_json.id);
        println!("Attributes defined: {:?}", schema_json.attr_names);
        Ok(())
    }

    async fn publish_cred_def(
        &self,
        _wallet: &impl BaseWallet,
        cred_def_json: CredentialDefinition,
        _submitter_did: &Did,
    ) -> Result<(), VcxLedgerError> { // Fixed Error Type here
        println!("\n[Billboard Notification] -> The Commander's official signature stamp has been registered!");
        println!("Credential Definition ID registered: {}", cred_def_json.id);
        Ok(())
    }

    async fn publish_rev_reg_def(
        &self,
        _wallet: &impl BaseWallet,
        _rev_reg_def: RevocationRegistryDefinition,
        _submitter_did: &Did,
    ) -> Result<(), VcxLedgerError> { // Fixed Error Type here
        Ok(())
    }

    async fn publish_rev_reg_delta(
        &self,
        _wallet: &impl BaseWallet,
        _rev_reg_id: &RevocationRegistryDefinitionId,
        _rev_reg_entry_json: RevocationRegistryDelta,
        _submitter_did: &Did,
    ) -> Result<(), VcxLedgerError> { // Fixed Error Type here
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=============================================================");
    println!("=== STEP 1: INITIALIZING THE BASE COMMANDER / LEDGER PATH ===");
    println!("=============================================================");

    println!("-> SUCCESS: Billboard trait methods are aligned perfectly.");
    println!("=============================================================");

    Ok(())
}