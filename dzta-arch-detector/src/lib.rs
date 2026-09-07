use std::{env::consts::OS, process::Command};


#[derive(Debug, PartialEq)]
pub enum VENDOR {
    INTEL,
    AMD,
    MSERIES,
    UNKNOWN,
}

#[derive(Debug, PartialEq)]
pub enum CPUARCH {
    ARM,
    X86,
    UNKNOWN,
}

impl From<u16> for CPUARCH {
    fn from(value: u16) -> Self {
        match value {
            0 | 9 => CPUARCH::X86,  // 0 = x86 (32-bit), 9 = x64 (64-bit)
            5 | 12 => CPUARCH::ARM, // 5 = ARM, 12 = ARM64
            _ => CPUARCH::UNKNOWN,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum OS {
    WINDOWS,
    LINUX,
    MACOS,
    ANDROID,
    UNKNOWN,
}

#[derive(Debug)]
pub struct PlatformInfo {
    pub operating_system: OS,
    pub vendor: VENDOR,
    pub architecture: CPUARCH,
}

#[derive(Debug)]
pub struct WindowsQueryResult {
    pub arch: CPUARCH,
    pub vendor: VENDOR,
}

impl PlatformInfo {
    pub fn new() -> Self {
        PlatformInfo {
            operating_system: OS::UNKNOWN,
            vendor: VENDOR::UNKNOWN,
            architecture: CPUARCH::UNKNOWN,
        }
    }

    pub fn detect_windows() -> Option<WindowsQueryResult> {
        // WQL syntax fix: Removed trailing comma after Manufacturer
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

                let manufacturer =
                    extract_json_field(&json_str, "Manufacturer").unwrap_or_default();

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
}

/// Simple helper to extract JSON primitive fields without external crates
fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\":", field);
    let line = json.lines().find(|l| l.contains(&key))?;
    let val = line.split(':').nth(1)?.trim();

    Some(
        val.trim_matches(|c| c == ',' || c == '"' || c == ' ')
            .to_string(),
    )
}

// fn main() {
//     let info = PlatformInfo::new();
//     println!("{:#?}", info);
// }
