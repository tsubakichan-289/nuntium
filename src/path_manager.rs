#[cfg(all(unix, not(target_os = "macos")))]
pub static DATA_PUBLIC_KEY: &str = "/var/lib/nuntium/kyber1024_public.hex";

#[cfg(target_os = "macos")]
pub static DATA_PUBLIC_KEY: &str = "/usr/local/var/nuntium/kyber1024_public.hex";

#[cfg(windows)]
pub static DATA_PUBLIC_KEY: &str = r"C:\ProgramData\nuntium\kyber1024_public.hex";

#[cfg(all(unix, not(target_os = "macos")))]
pub static DATA_SECRET_KEY: &str = "/var/lib/nuntium/kyber1024_secret.hex";

#[cfg(target_os = "macos")]
pub static DATA_SECRET_KEY: &str = "/usr/local/var/nuntium/kyber1024_secret.hex";

#[cfg(windows)]
pub static DATA_SECRET_KEY: &str = r"C:\ProgramData\nuntium\kyber1024_secret.hex";

#[cfg(all(unix, not(target_os = "macos")))]
pub static CONFIG_FILE: &str = "/etc/nuntium/nuntium.conf";

#[cfg(target_os = "macos")]
pub static CONFIG_FILE: &str = "/usr/local/etc/nuntium/nuntium.conf";

#[cfg(windows)]
pub static CONFIG_FILE: &str = r"C:\ProgramData\nuntium\nuntium.conf";
