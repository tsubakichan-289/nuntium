use nuntium::config::{load_config, read_server_ip, read_server_port};
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn read_ip_from_config_file() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("nuntium.conf");
    {
        let mut file = File::create(&file_path).unwrap();
        let json = r#"{"ip":"192.0.2.1","port":9000,"ttl_seconds":3600,"max_keys":1000}"#;
        file.write_all(json.as_bytes()).unwrap();
    }
    std::env::set_var("NUNTIUM_CONF", &file_path);
    let cfg = load_config().unwrap();
    assert_eq!(cfg.ip.to_string(), "192.0.2.1");
    assert_eq!(cfg.port, 9000);
    assert_eq!(cfg.ttl_seconds, 3600);
    assert_eq!(cfg.max_keys, 1000);
    let ip = read_server_ip();
    let port = read_server_port();
    assert_eq!(ip, Some("192.0.2.1".to_string()));
    assert_eq!(port, Some(9000));
    std::env::remove_var("NUNTIUM_CONF");
}

#[test]
fn read_ip_missing_file() {
    std::env::set_var("NUNTIUM_CONF", "/nonexistent/nuntium.conf");
    let ip = read_server_ip();
    let port = read_server_port();
    assert!(ip.is_none());
    assert!(port.is_none());
    std::env::remove_var("NUNTIUM_CONF");
}
