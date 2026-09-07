use std::{fs, process::Command};

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

#[derive(Debug)]
pub struct LinuxQueryResult {
    pub arch: CPUARCH,
    pub vendor: VENDOR,
}

#[derive(Debug)]
pub struct MacOSQueryResult {
    pub arch: CPUARCH,
    pub vendor: VENDOR,
}

#[derive(Debug)]
pub struct AndroidQueryResult {
    pub arch: CPUARCH,
    pub vendor: VENDOR,
}

impl From<MacOSQueryResult> for PlatformInfo {
    fn from(value: MacOSQueryResult) -> Self {
        PlatformInfo {
            operating_system: OS::MACOS,
            vendor: value.vendor,
            architecture: value.arch,
        }
    }
}

impl From<WindowsQueryResult> for PlatformInfo {
    fn from(value: WindowsQueryResult) -> Self {
        PlatformInfo {
            operating_system: OS::WINDOWS,
            vendor: value.vendor,
            architecture: value.arch,
        }
    }
}

impl From<LinuxQueryResult> for PlatformInfo {
    fn from(value: LinuxQueryResult) -> Self {
        PlatformInfo {
            operating_system: OS::LINUX,
            vendor: value.vendor,
            architecture: value.arch,
        }
    }
}

impl From<AndroidQueryResult> for PlatformInfo {
    fn from(value: AndroidQueryResult) -> Self {
        PlatformInfo {
            operating_system: OS::LINUX,
            vendor: value.vendor,
            architecture: value.arch,
        }
    }
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

impl PlatformInfo {
    pub fn new() -> Self {
        if let Some(result) = Self::detect_windows() {
            return result.into();
        }

        if let Some(result) = Self::detect_linux() {
            return result.into();
        }

        if let Some(result) = Self::detect_macos() {
            return result.into();
        }

        if let Some(result) = Self::detect_android() {
            return result.into();
        }

        PlatformInfo {
            operating_system: OS::UNKNOWN,
            vendor: VENDOR::UNKNOWN,
            architecture: CPUARCH::UNKNOWN,
        }
    }

    pub fn detect_windows() -> Option<WindowsQueryResult> {
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

    pub fn detect_linux() -> Option<LinuxQueryResult> {
        let content = fs::read_to_string("/proc/cpuinfo").ok()?;

        let mut vendor = VENDOR::UNKNOWN;

        // 1. Detect Vendor from /proc/cpuinfo
        for line in content.lines() {
            // Check x86/x86_64 key
            if line.starts_with("vendor_id") {
                if let Some((_, value)) = line.split_once(':') {
                    let v = value.trim().to_lowercase();
                    if v.contains("intel") {
                        vendor = VENDOR::INTEL;
                        break;
                    } else if v.contains("amd") || v.contains("authenticamd") {
                        vendor = VENDOR::AMD;
                        break;
                    }
                }
            }
            // Check ARM key (ARM chips use 'CPU implementer' or 'model name')
            else if line.starts_with("CPU implementer") || line.starts_with("model name") {
                if let Some((_, value)) = line.split_once(':') {
                    let v = value.trim().to_lowercase();
                    if v.contains("intel") {
                        vendor = VENDOR::INTEL;
                        break;
                    } else if v.contains("amd") {
                        vendor = VENDOR::AMD;
                        break;
                    }
                }
            }
        }

        // 2. Detect Architecture via `uname -m`
        let arch_output = Command::new("uname").arg("-m").output();
        let arch = match arch_output {
            Ok(out) if out.status.success() => {
                let machine = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
                match machine.as_str() {
                    "x86_64" | "i686" | "i386" => CPUARCH::X86,
                    "aarch64" | "armv7l" | "armv8l" | "arm" => CPUARCH::ARM,
                    _ => CPUARCH::UNKNOWN,
                }
            }
            _ => CPUARCH::UNKNOWN,
        };

        Some(LinuxQueryResult { arch, vendor })
    }

    pub fn detect_macos() -> Option<MacOSQueryResult> {
        // 1. Detect Architecture via `uname -m`
        let arch_output = Command::new("uname").arg("-m").output();
        let arch = match arch_output {
            Ok(out) if out.status.success() => {
                let machine = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
                match machine.as_str() {
                    "x86_64" | "i686" | "i386" => CPUARCH::X86,
                    "arm64" | "aarch64" | "armv7l" | "armv8l" | "arm" => CPUARCH::ARM,
                    _ => CPUARCH::UNKNOWN,
                }
            }
            _ => return None, // Fail fast if uname is not available or fails
        };

        // 2. Detect Vendor via `sysctl -n machdep.cpu.brand_string`
        let vendor_output = Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output();

        let vendor = match vendor_output {
            Ok(out) if out.status.success() => {
                let v = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();

                if v.contains("intel") {
                    VENDOR::INTEL
                } else if v.contains("amd") {
                    VENDOR::AMD
                } else if v.is_empty() && arch == CPUARCH::ARM {
                    // On Apple Silicon (M1/M2/M3/M4), `machdep.cpu.brand_string` returns an empty string or fails
                    VENDOR::MSERIES
                } else {
                    VENDOR::UNKNOWN
                }
            }
            _ => {
                // Fallback for Apple Silicon when the key doesn't exist
                if arch == CPUARCH::ARM {
                    VENDOR::MSERIES
                } else {
                    VENDOR::UNKNOWN
                }
            }
        };

        Some(MacOSQueryResult { arch, vendor })
    }

    pub fn detect_android() -> Option<AndroidQueryResult> {
        // 1. Detect Architecture via `uname -m`
        let arch_output = Command::new("uname").arg("-m").output();
        let arch = match arch_output {
            Ok(out) if out.status.success() => {
                let machine = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
                match machine.as_str() {
                    "aarch64" | "armv7l" | "armv8l" | "arm" => CPUARCH::ARM,
                    "x86_64" | "i686" | "i386" => CPUARCH::X86,
                    _ => CPUARCH::UNKNOWN,
                }
            }
            _ => return None, // Fail fast if uname fails
        };

        // 2. Detect SoC / Vendor via `getprop ro.hardware` or /proc/cpuinfo
        let mut vendor = VENDOR::UNKNOWN;

        let prop_output = Command::new("getprop").arg("ro.hardware").output();
        if let Ok(out) = prop_output {
            if out.status.success() {
                let hardware = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
                if hardware.contains("intel") {
                    vendor = VENDOR::INTEL;
                } else if hardware.contains("amd") {
                    vendor = VENDOR::AMD;
                }
            }
        }

        // Fallback to /proc/cpuinfo if getprop didn't yield a known vendor
        if vendor == VENDOR::UNKNOWN {
            if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
                for line in content.lines() {
                    if line.starts_with("vendor_id") || line.starts_with("Hardware") {
                        if let Some((_, value)) = line.split_once(':') {
                            let v = value.trim().to_lowercase();
                            if v.contains("intel") {
                                vendor = VENDOR::INTEL;
                                break;
                            } else if v.contains("amd") || v.contains("authenticamd") {
                                vendor = VENDOR::AMD;
                                break;
                            }
                        }
                    }
                }
            }
        }

        Some(AndroidQueryResult { arch, vendor })
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
