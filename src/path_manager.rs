#[cfg(target_os = "linux")]
pub const DATA_PUBLIC_KEY: &str = "/var/lib/nuntium/kyber1024_public.hex";
#[cfg(target_os = "linux")]
pub const DATA_SECRET_KEY: &str = "/var/lib/nuntium/kyber1024_secret.hex";
#[cfg(target_os = "linux")]
pub const CONFIG_FILE: &str = "/etc/nuntium/nuntium.conf";

#[cfg(target_os = "windows")]
pub const DATA_PUBLIC_KEY: &str = "C:\\ProgramData\\nuntium\\kyber1024_public.hex";
#[cfg(target_os = "windows")]
pub const DATA_SECRET_KEY: &str = "C:\\ProgramData\\nuntium\\kyber1024_secret.hex";
#[cfg(target_os = "windows")]
pub const CONFIG_FILE: &str = "C:\\ProgramData\\nuntium\\nuntium.conf";
