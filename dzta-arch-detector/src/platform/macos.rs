use crate::{CPUARCH, VENDOR};
use std::process::Command;

#[derive(Debug)]
pub struct MacOSQueryResult {
    pub arch: CPUARCH,
    pub vendor: VENDOR,
}

pub fn detect() -> Option<MacOSQueryResult> {
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
        _ => return None,
    };

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
                VENDOR::MSERIES
            } else {
                VENDOR::UNKNOWN
            }
        }
        _ => {
            if arch == CPUARCH::ARM {
                VENDOR::MSERIES
            } else {
                VENDOR::UNKNOWN
            }
        }
    };

    Some(MacOSQueryResult { arch, vendor })
}