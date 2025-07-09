use nuntium::config::read_server_ip;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn read_ip_from_config_file() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("nuntium.conf");
    {
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "192.0.2.1").unwrap();
    }
    std::env::set_var("NUNTIUM_CONF", &file_path);
    let ip = read_server_ip();
    assert_eq!(ip, Some("192.0.2.1".to_string()));
    std::env::remove_var("NUNTIUM_CONF");
}

#[test]
fn read_ip_missing_file() {
    std::env::set_var("NUNTIUM_CONF", "/nonexistent/nuntium.conf");
    let ip = read_server_ip();
    assert!(ip.is_none());
    std::env::remove_var("NUNTIUM_CONF");
}
