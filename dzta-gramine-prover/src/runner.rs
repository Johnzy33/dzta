// dzta-gramine-prover/src/runner.rs
use anyhow::{Context, Result};
use shared::zkp_core::{AttestationRequest, AttestationResponse, EnclaveIngestionPayload, ProverOutputResponse};
use std::io::{BufRead, BufReader};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::{error, info, warn};

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
    pub fn is_hardware_backed(self) -> bool {
        matches!(self.resolve(), "gramine-sgx")
    }

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

    pub fn is_hardware_backed(&self) -> bool {
        self.mode.is_hardware_backed()
    }

    pub fn execute_confidential_proof(
        &self,
        payload: &EnclaveIngestionPayload,
        broker_url: &str,
    ) -> Result<ProverOutputResponse> {
        let runner_binary = self.mode.resolve();
        let target_file_path = Path::new(&self.target_path);
        let working_dir = target_file_path.parent().unwrap_or_else(|| Path::new("."));
        let binary_name = target_file_path.file_name().unwrap_or_else(|| target_file_path.as_os_str());
        let mut child = Command::new(runner_binary)
            .arg(binary_name)
            .current_dir(working_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to spawn `{runner_binary}` executable"))?;

        let mut stdin = child.stdin.take().context("Failed to open enclave stdin")?;
        let mut stdout = BufReader::new(child.stdout.take().context("Failed to open enclave stdout")?);
        let initial = serde_json::to_string(payload)?;
        writeln!(stdin, "{initial}")?;
        stdin.flush()?;

        let mut request_line = String::new();
        stdout.read_line(&mut request_line)?;
        let request: AttestationRequest = serde_json::from_str(request_line.trim())
            .context("Enclave did not produce an attestation request")?;
        let response = reqwest::blocking::Client::new()
            .post(broker_url)
            .json(&request)
            .send()
            .context("Failed to contact dZTA attestation broker")?
            .error_for_status()
            .context("Attestation broker rejected the enclave")?
            .json::<AttestationResponse>()
            .context("Invalid attestation broker response")?;
        writeln!(stdin, "{}", serde_json::to_string(&response)?)?;
        stdin.flush()?;

        let mut output_line = String::new();
        stdout.read_line(&mut output_line)?;
        drop(stdin);
        let output = child.wait_with_output().context("Failed waiting for enclave")?;
        if !output.status.success() {
            anyhow::bail!("Confidential Gramine execution failed: {}", String::from_utf8_lossy(&output.stderr));
        }
        serde_json::from_str(output_line.trim()).context("Invalid proof response from enclave")
    }

    /// Spawns `gramine-direct` or `gramine-sgx`, streams raw encrypted ingestion payload to stdin, and returns output envelope
    pub fn execute_proof(&self, payload: &EnclaveIngestionPayload) -> Result<ProverOutputResponse> {
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
            // .stderr(Stdio::inherit())
            .stderr(Stdio::piped()) // <-- Change from inherit() to piped()
            .spawn()
            .with_context(|| format!("Failed to spawn `{runner_binary}` executable. Ensure Gramine is installed in PATH."))?;

        // 2. Serialize encrypted ingestion payload to JSON and write to child stdin
        let payload_json = serde_json::to_vec(payload)
            .context("Failed to serialize EnclaveIngestionPayload to JSON")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&payload_json)
                .context("Failed to write JSON payload into Gramine process stdin")?;
        } else {
            anyhow::bail!("Failed to open stdin handle on Gramine process");
        }

        // 3. Wait for execution to complete
        // let output = child.wait_with_output()
        //     .context("Failed while waiting for Gramine process execution")?;

        // if !output.status.success() {
        //     error!("[Runner] Gramine process exited with error code: {:?}", output.status.code());
        //     anyhow::bail!("Gramine execution failed with exit status: {}", output.status);
        // }

        // 3. Wait for execution to complete
        let output = child.wait_with_output()
            .context("Failed while waiting for Gramine process execution")?;

        if !output.status.success() {
            // Read what the enclave actually complained about
            let enclave_stderr = String::from_utf8_lossy(&output.stderr);
            
            error!("[Runner] Gramine process exited with error code: {:?}", output.status.code());
            error!("[Runner] Enclave Panic/Stderr output:\n{}", enclave_stderr);
            
            anyhow::bail!(
                "Gramine execution failed with exit status: {}\nEnclave Error Log:\n{}", 
                output.status, 
                enclave_stderr
            );
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