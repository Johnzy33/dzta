use crate::{CPUARCH, VENDOR};
use std::{fs, process::Command};

#[derive(Debug)]
pub struct LinuxQueryResult {
    pub arch: CPUARCH,
    pub vendor: VENDOR,
}

pub fn detect() -> Option<LinuxQueryResult> {
    let content = fs::read_to_string("/proc/cpuinfo").ok()?;
    let mut vendor = VENDOR::UNKNOWN;

    for line in content.lines() {
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
        } else if line.starts_with("CPU implementer") || line.starts_with("model name") {
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