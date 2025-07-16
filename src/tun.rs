use std::io;
use std::process::Command;
use std::net::Ipv6Addr;

pub fn create_tun(name: &str, ipv6_addr: Ipv6Addr) -> io::Result<()> {
    // TUN デバイスの作成
    let output = Command::new("ip")
        .args(["tuntap", "add", name, "mode", "tun"])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "TUN デバイスの作成に失敗しました"));
    }

    // IPv6 アドレスの割り当て（/64 など必要に応じて調整）
    let output = Command::new("ip")
        .args([
            "-6", "addr", "add",
            &format!("{}/64", ipv6_addr),
            "dev", name,
        ])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "IPv6 アドレスの設定に失敗しました"));
    }

    // デバイスを up にする
    let output = Command::new("ip")
        .args(["link", "set", name, "up"])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "TUN デバイスの起動に失敗しました"));
    }

    println!("✅ TUN デバイス {} を作成し、IPv6 {} を割り当てました", name, ipv6_addr);

    Ok(())
}
