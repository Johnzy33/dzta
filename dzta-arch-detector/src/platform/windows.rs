use crate::{CPUARCH, VENDOR};
use std::process::Command;

#[derive(Debug)]
pub struct WindowsQueryResult {
    pub arch: CPUARCH,
    pub vendor: VENDOR,
}

pub fn detect() -> Option<WindowsQueryResult> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance -Query 'SELECT Architecture, Manufacturer FROM Win32_Processor' | ConvertTo-Json",
        ])
        .output();

    match output {
        Ok(x) if x.status.success() => {
            let json_str = String::from_utf8_lossy(&x.stdout);

            let raw_arch = extract_json_field(&json_str, "Architecture")
                .and_then(|val| val.parse::<u16>().ok())
                .unwrap_or(99);

            let manufacturer = extract_json_field(&json_str, "Manufacturer").unwrap_or_default();

            let arch = CPUARCH::from(raw_arch);

            let vendor = match manufacturer.to_lowercase().as_str() {
                m if m.contains("intel") => VENDOR::INTEL,
                m if m.contains("amd") || m.contains("advanced micro devices") => VENDOR::AMD,
                _ => VENDOR::UNKNOWN,
            };

            Some(WindowsQueryResult { arch, vendor })
        }
        _ => None,
    }
}

/// Helper to extract primitive fields from simple flat JSON strings
pub fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\":", field);
    let line = json.lines().find(|l| l.contains(&key))?;
    let val = line.split(':').nth(1)?.trim();

    Some(
        val.trim_matches(|c| c == ',' || c == '"' || c == ' ')
            .to_string(),
    )
}
