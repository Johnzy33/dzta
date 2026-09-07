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
}
