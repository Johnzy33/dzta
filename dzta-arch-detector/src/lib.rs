use libloading::{Library, Symbol};
use std::path::Path;
use tracing::{error, info, warn};
pub mod platform;

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

#[derive(Debug, PartialEq, Eq)]
pub enum Enclave {
    /// Intel Software Guard Extensions
    Sgx,
    /// AMD Secure Encrypted Virtualization
    Sev,
    /// ARM TrustZone / Confidential Compute Architecture
    TrustZone,
    /// No supported enclave hardware detected or software simulation only
    None,
}

#[repr(u32)]
enum EnclaveType {
    Sgx = 0x00000001,
    Sgx2 = 0x00000002,
    Vbs = 0x00000010,
}

#[derive(Debug)]
pub struct PlatformInfo {
    pub operating_system: OS,
    pub vendor: VENDOR,
    pub architecture: CPUARCH,
}

impl From<u16> for CPUARCH {
    fn from(value: u16) -> Self {
        match value {
            0 | 9 => CPUARCH::X86,  // 0 = x86, 9 = x64
            5 | 12 => CPUARCH::ARM, // 5 = ARM, 12 = ARM64
            _ => CPUARCH::UNKNOWN,
        }
    }
}

impl From<platform::windows::WindowsQueryResult> for PlatformInfo {
    fn from(res: platform::windows::WindowsQueryResult) -> Self {
        PlatformInfo {
            operating_system: OS::WINDOWS,
            vendor: res.vendor,
            architecture: res.arch,
        }
    }
}

impl From<platform::linux::LinuxQueryResult> for PlatformInfo {
    fn from(res: platform::linux::LinuxQueryResult) -> Self {
        PlatformInfo {
            operating_system: OS::LINUX,
            vendor: res.vendor,
            architecture: res.arch,
        }
    }
}

impl From<platform::macos::MacOSQueryResult> for PlatformInfo {
    fn from(res: platform::macos::MacOSQueryResult) -> Self {
        PlatformInfo {
            operating_system: OS::MACOS,
            vendor: res.vendor,
            architecture: res.arch,
        }
    }
}

impl From<platform::android::AndroidQueryResult> for PlatformInfo {
    fn from(res: platform::android::AndroidQueryResult) -> Self {
        PlatformInfo {
            operating_system: OS::ANDROID,
            vendor: res.vendor,
            architecture: res.arch,
        }
    }
}

impl PlatformInfo {
    pub fn new() -> Self {
        if let Some(res) = platform::windows::detect() {
            return res.into();
        }

        if let Some(res) = platform::linux::detect() {
            return res.into();
        }

        if let Some(res) = platform::macos::detect() {
            return res.into();
        }

        if let Some(res) = platform::android::detect() {
            return res.into();
        }

        PlatformInfo {
            operating_system: OS::UNKNOWN,
            vendor: VENDOR::UNKNOWN,
            architecture: CPUARCH::UNKNOWN,
        }
    }

    pub fn detect_enclave(&self) -> Enclave {
        match (&self.operating_system, &self.vendor, &self.architecture) {
            // Intel SGX Check
            (_, VENDOR::INTEL, CPUARCH::X86) => {
                // Gramine / Linux SGX driver paths
                let sgx_linux = Path::new("/dev/sgx_enclave").exists()
                    || Path::new("/dev/sgx/enclave").exists()
                    || Path::new("/dev/isgx").exists()
                    || Path::new("/dev/attestation/attestation_type").exists();

                if self.operating_system == OS::WINDOWS {
                    info!("[Enclave Detection] Detecting enclave for windows.");
                    unsafe {
                        info!("[Enclave Detection] Loading kernel32.dll");
                        let lib = match Library::new(r"C:\Windows\System32\kernel32.dll") {
                            Err(e) => {
                                error!(
                                    "[Enclave Detection] Unable to load kernel32.dll. Error: {}",
                                    e
                                );
                                return Enclave::None;
                            }
                            Ok(lib) => lib,
                        };

                        let is_enclave_type_supported: Symbol<extern "system" fn(u32) -> bool> =
                            match lib.get(b"IsEnclaveTypeSupported") {
                                Err(e) => {
                                    error!(
                                        "[Enclave Detection] IsEnclaveTypeSupported function not found in kernel32.dll. Error: {}",
                                        e
                                    );
                                    return Enclave::None;
                                }
                                Ok(fx) => fx,
                            };

                        let sgx_windows = is_enclave_type_supported(EnclaveType::Sgx as u32);

                        if sgx_windows {
                            info!("[Enclave Detection] Intel SGX hardware support verified.");
                            return Enclave::Sgx;
                        }
                    }
                }

                if sgx_linux {
                    info!("[Enclave Detection] Intel SGX hardware support verified.");
                    Enclave::Sgx
                } else {
                    warn!(
                        "[Enclave Detection] Intel CPU detected, but SGX device node not found or disabled in BIOS."
                    );
                    Enclave::None
                }
            }

            // AMD SEV Check
            (_, VENDOR::AMD, CPUARCH::X86) => {
                let sev_device =
                    Path::new("/dev/sev").exists() || Path::new("/dev/sev-guest").exists();

                if sev_device {
                    info!("[Enclave Detection] AMD SEV hardware support verified.");
                    Enclave::Sev
                } else {
                    warn!("[Enclave Detection] AMD CPU detected, but /dev/sev node not present.");
                    Enclave::None
                }
            }

            // ARM TrustZone Check
            (_, _, CPUARCH::ARM) => {
                let trustzone_device = Path::new("/dev/tzdriver").exists()
                    || Path::new("/dev/tee0").exists()
                    || Path::new("/dev/teepriv0").exists();

                if trustzone_device {
                    info!("[Enclave Detection] ARM TrustZone / TEE hardware support verified.");
                    Enclave::TrustZone
                } else {
                    warn!(
                        "[Enclave Detection] ARM CPU detected, but TEE/TrustZone interface not exposed."
                    );
                    Enclave::None
                }
            }

            _ => {
                info!(
                    "[Enclave Detection] No known enclave support for this vendor/architecture combination."
                );
                Enclave::None
            }
        }
    }
}
