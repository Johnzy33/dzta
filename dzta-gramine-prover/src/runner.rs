use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::{error, info, warn};
use zeroize::Zeroize;
use shared::zkp_core::{ProverInputPayload, ProverOutputResponse};

/// Gramine runtime execution target mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Executes under `gramine-direct` (development/software simulation)
    Direct,
    /// Executes under `gramine-sgx` (hardware-backed enclave mode)
    Sgx,
    /// Automatically detects SGX device availability
    Auto,
}

impl ExecutionMode {
    pub fn resolve(self) -> &'static str {
        match self {
            ExecutionMode::Direct => "gramine-direct",
            ExecutionMode::Sgx => "gramine-sgx",
            ExecutionMode::Auto => {
                if Path::new("/dev/attestation/attestation_type").exists()
                    || Path::new("/dev/sgx_enclave").exists()
                    || Path::new("/dev/sgx/enclave").exists()
                {
                    info!("[Gramine Mode] Hardware SGX environment detected. Using `gramine-sgx`.");
                    "gramine-sgx"
                } else {
                    warn!("[Gramine Mode] No SGX hardware device found. Falling back to `gramine-direct`.");
                    "gramine-direct"
                }
            }
        }
    }
}

pub struct GramineProverRunner {
    target_path: String,
    mode: ExecutionMode,
}

impl GramineProverRunner {
    pub fn new(target_path: impl Into<String>, mode: ExecutionMode) -> Self {
        Self {
            target_path: target_path.into(),
            mode,
        }
    }

    /// Spawns `gramine-direct` or `gramine-sgx`, streams payload to stdin, and returns output envelope
    pub fn execute_proof(&self, payload: &ProverInputPayload) -> Result<ProverOutputResponse> {
        let runner_binary = self.mode.resolve();
        info!("[Runner] Spawning `{}` for target: {}", runner_binary, self.target_path);

        // Parse the target executable path and its parent directory
        let target_file_path = Path::new(&self.target_path);
        let working_dir = target_file_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let binary_name = target_file_path
            .file_name()
            .unwrap_or_else(|| target_file_path.as_os_str());

        // 1. Spawn process with current_dir set to target/release/
        let mut child = Command::new(runner_binary)
            .arg(binary_name) // Gramine expects the target binary name in its working directory
            .current_dir(working_dir) // Sets CWD to target/release/
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("Failed to spawn `{runner_binary}` executable. Ensure Gramine is installed in PATH."))?;

        // 2. Serialize payload to JSON and write to child stdin
        let payload_json = serde_json::to_vec(payload)
            .context("Failed to serialize ProverInputPayload to JSON")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&payload_json)
                .context("Failed to write JSON payload into Gramine process stdin")?;
        } else {
            anyhow::bail!("Failed to open stdin handle on Gramine process");
        }

        // 3. Wait for execution to complete
        let output = child.wait_with_output()
            .context("Failed while waiting for Gramine process execution")?;

        if !output.status.success() {
            error!("[Runner] Gramine process exited with error code: {:?}", output.status.code());
            anyhow::bail!("Gramine execution failed with exit status: {}", output.status);
        }

        // 4. Parse stdout into ProverOutputResponse by extracting the JSON line
        let stdout_str = String::from_utf8(output.stdout)
            .context("Gramine stdout produced invalid UTF-8 string")?;

        info!("[Runner Debug] Raw stdout (length {}): {:?}", stdout_str.len(), stdout_str);

        let json_line = stdout_str
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with('{') && line.ends_with('}'))
            .ok_or_else(|| anyhow::anyhow!("No valid JSON object found in Gramine stdout:\n{}", stdout_str))?;

        let response: ProverOutputResponse = serde_json::from_str(json_line)
            .context("Failed to parse ProverOutputResponse JSON from Gramine stdout")?;

        info!("[Runner] Proof and public inputs successfully received from enclave.");
        Ok(response)
    }
}