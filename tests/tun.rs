#[cfg(target_os = "linux")]
use std::net::Ipv6Addr;

#[cfg(target_os = "linux")]
fn ip_args(addr: Ipv6Addr, dev: &str) -> Vec<String> {
    vec![
        "-6".to_string(),
        "addr".to_string(),
        "add".to_string(),
        format!("{}/7", addr),
        "dev".to_string(),
        dev.to_string(),
    ]
}

#[cfg(target_os = "linux")]
#[test]
fn ip_args_use_prefix_7() {
    let addr = Ipv6Addr::new(0x4000, 0, 0, 0, 0, 0, 0, 1);
    let args = ip_args(addr, "test0");
    assert_eq!(
        args,
        vec![
            "-6".to_string(),
            "addr".to_string(),
            "add".to_string(),
            format!("{}/7", addr),
            "dev".to_string(),
            "test0".to_string()
        ]
    );
}
