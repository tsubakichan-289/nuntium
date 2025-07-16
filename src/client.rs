use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket, Ipv6Addr};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::PublicKey;

use crate::tun;

pub fn run_client(ip: IpAddr, port: u16, public_key: kyber1024::PublicKey, ipv6_addr: Ipv6Addr,) -> io::Result<()> {
    let local_bind = if ip.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(local_bind)?;

    let remote = SocketAddr::new(ip, port);
    socket.connect(remote)?;

    let mut payload = Vec::with_capacity(1584 + 16);
    payload.extend_from_slice(public_key.as_bytes());
    payload.extend_from_slice(&ipv6_addr.octets());

	println!("Sending {} bytes", payload.len()); 

    socket.send(&payload)?;

    println!(
        "Sent {} bytes to {}:{}", 
        payload.len(), ip, port
    );

	tun::create_tun("tun0", ipv6_addr)?;

    Ok(())
}
