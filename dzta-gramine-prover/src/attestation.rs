// dzta-gramine-prover/src/attestation.rs
use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use tracing::{info, warn};

pub struct GramineAttestationDriver;

impl GramineAttestationDriver {
    const ATTESTATION_TYPE_PATH: &'static str = "/dev/attestation/attestation_type";
    const USER_REPORT_DATA_PATH: &'static str = "/dev/attestation/user_report_data";
    const QUOTE_PATH: &'static str = "/dev/attestation/quote";

    /// Checks if Gramine is currently running inside an active Intel SGX enclave hardware environment.
    pub fn is_sgx_hardware_active() -> bool {
        Path::new(Self::ATTESTATION_TYPE_PATH).exists()
    }

    /// Writes arbitrary data (up to 64 bytes, e.g., proof hash or public commitment) 
    /// to `/dev/attestation/user_report_data` to bind the ZKP execution to the SGX report.
    pub fn bind_user_report_data(data: &[u8]) -> Result<()> {
        if !Self::is_sgx_hardware_active() {
            warn!("[Gramine SGX] Running in Direct/Software mode; skipping hardware attestation binding.");
            return Ok(());
        }

        info!("[Gramine SGX] Writing report data into SGX enclave hardware boundary...");
        let mut report_file = OpenOptions::new()
            .write(true)
            .open(Self::USER_REPORT_DATA_PATH)
            .context("Failed to open Gramine user_report_data device")?;

        let mut padded = [0u8; 64];
        let len = data.len().min(64);
        padded[..len].copy_from_slice(&data[..len]);

        report_file.write_all(&padded)?;
        info!("[Gramine SGX] User report data successfully bound.");
        Ok(())
    }

    /// Retrieves the generated Intel SGX DCAP Quote from `/dev/attestation/quote`.
    pub fn fetch_sgx_quote() -> Result<Option<Vec<u8>>> {
        if !Self::is_sgx_hardware_active() {
            return Ok(None);
        }

        info!("[Gramine SGX] Reading DCAP quote from /dev/attestation/quote...");
        let mut quote_file = File::open(Self::QUOTE_PATH)
            .context("Failed to open Gramine quote device")?;
        
        let mut quote_bytes = Vec::new();
        quote_file.read_to_end(&mut quote_bytes)?;

        info!("[Gramine SGX] Extracted DCAP Quote (Size: {} bytes).", quote_bytes.len());
        Ok(Some(quote_bytes))
    }
}