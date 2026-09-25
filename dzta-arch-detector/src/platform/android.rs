use crate::{CPUARCH, VENDOR};
use std::{fs, process::Command};

#[derive(Debug)]
pub struct AndroidQueryResult {
    pub arch: CPUARCH,
    pub vendor: VENDOR,
}

pub fn detect() -> Option<AndroidQueryResult> {
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
        _ => return None,
    };

    let mut vendor = VENDOR::UNKNOWN;

    if let Ok(out) = Command::new("getprop").arg("ro.hardware").output() {
        if out.status.success() {
            let hardware = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
            if hardware.contains("intel") {
                vendor = VENDOR::INTEL;
            } else if hardware.contains("amd") {
                vendor = VENDOR::AMD;
            }
        }
    }

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