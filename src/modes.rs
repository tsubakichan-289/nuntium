use pqcrypto_traits::kem::PublicKey as _;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket, SocketAddr};
use std::thread;

use crate::tundev::TunDevice;

use crate::{crypto::Aes256GcmHelper, ipv6::make_ipv6_from_pubkey, pqc};

pub fn run_client() -> std::io::Result<()> {
    let (pk, _sk) = pqc::generate_keypair();
    let addr = make_ipv6_from_pubkey(pk.as_bytes());
    println!("Client IPv6: {}", addr);

    let mut stream = TcpStream::connect("127.0.0.1:9000")?;

    // send client pk
    stream.write_all(pk.as_bytes())?;

    // receive server pk
    let mut server_pk_bytes = vec![0u8; pqc::PUBLIC_KEY_LEN];
    stream.read_exact(&mut server_pk_bytes)?;
    let server_pk = pqc::public_key_from_bytes(&server_pk_bytes);

    // encapsulate
    let (ct, shared) = pqc::encapsulate(&server_pk);
    stream.write_all(&ct)?;
    println!("Client shared secret established");
    let mut aes = Aes256GcmHelper::new(&shared);

    // send encrypted packet
    let msg = b"ping";
    let (ct_out, nonce_out) = aes.encrypt(msg);
    stream.write_all(&nonce_out)?;
    stream.write_all(&(ct_out.len() as u16).to_be_bytes())?;
    stream.write_all(&ct_out)?;

    // receive response
    let mut nonce = [0u8; 12];
    stream.read_exact(&mut nonce)?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut enc = vec![0u8; len];
    stream.read_exact(&mut enc)?;
    let plain = aes.decrypt(&nonce, &enc).expect("decrypt");
    println!("Client received: {}", String::from_utf8_lossy(&plain));

    Ok(())
}

pub fn run_server() -> std::io::Result<()> {
    let (pk, sk) = pqc::generate_keypair();
    let addr = make_ipv6_from_pubkey(pk.as_bytes());
    println!("Server IPv6: {}", addr);

    let listener = TcpListener::bind("0.0.0.0:9000")?;
    let (mut stream, _) = listener.accept()?;

    // receive client pk
    let mut client_pk_bytes = vec![0u8; pqc::PUBLIC_KEY_LEN];
    stream.read_exact(&mut client_pk_bytes)?;
    let client_pk = pqc::public_key_from_bytes(&client_pk_bytes);
    let client_addr = make_ipv6_from_pubkey(client_pk.as_bytes());
    println!("Client IPv6: {}", client_addr);

    // send server pk
    stream.write_all(pk.as_bytes())?;

    // receive ciphertext from client
    let mut ct = vec![0u8; pqc::CIPHERTEXT_LEN];
    stream.read_exact(&mut ct)?;

    let shared = pqc::decapsulate(&ct, &sk);
    println!("Server shared secret established");
    let mut aes = Aes256GcmHelper::new(&shared);

    // receive encrypted packet
    let mut nonce = [0u8; 12];
    stream.read_exact(&mut nonce)?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut enc = vec![0u8; len];
    stream.read_exact(&mut enc)?;
    let plain = aes.decrypt(&nonce, &enc).expect("decrypt");
    println!("Server received: {}", String::from_utf8_lossy(&plain));

    // reply
    let reply = b"pong";
    let (ct_out, nonce_out) = aes.encrypt(reply);
    stream.write_all(&nonce_out)?;
    stream.write_all(&(ct_out.len() as u16).to_be_bytes())?;
    stream.write_all(&ct_out)?;

    Ok(())
}

pub fn run_server_tun() -> std::io::Result<()> {
    let (pk, sk) = pqc::generate_keypair();
    let addr = make_ipv6_from_pubkey(pk.as_bytes());
    println!("Server IPv6: {}", addr);

    let socket = UdpSocket::bind("0.0.0.0:9001")?;
    let mut clients: HashMap<SocketAddr, Aes256GcmHelper> = HashMap::new();

    let mut buf = [0u8; 2048];
    loop {
        let (len, src) = socket.recv_from(&mut buf)?;

        if !clients.contains_key(&src) {
            if len == pqc::PUBLIC_KEY_LEN {
                socket.send_to(pk.as_bytes(), src)?;
            } else if len == pqc::CIPHERTEXT_LEN {
                let shared = pqc::decapsulate(&buf[..len], &sk);
                clients.insert(src, Aes256GcmHelper::new(&shared));
                println!("New client registered: {src}");
            }
            continue;
        }

        if len < 14 {
            continue;
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buf[..12]);
        let l = u16::from_be_bytes([buf[12], buf[13]]) as usize;
        if len < 14 + l {
            continue;
        }

        // forward encrypted packet to all other clients
        for (&addr, _) in clients.iter() {
            if addr != src {
                socket.send_to(&buf[..len], addr)?;
            }
        }
    }
}

pub fn run_client_tun() -> std::io::Result<()> {
    let (pk, _sk) = pqc::generate_keypair();
    let addr = make_ipv6_from_pubkey(pk.as_bytes());
    println!("Client IPv6: {}", addr);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("127.0.0.1:9001")?;

    socket.send(pk.as_bytes())?;
    let mut buf = vec![0u8; pqc::PUBLIC_KEY_LEN];
    socket.recv(&mut buf)?;
    let server_pk = pqc::public_key_from_bytes(&buf);
    let (ct, shared) = pqc::encapsulate(&server_pk);
    socket.send(&ct)?;
    let aes_send = Aes256GcmHelper::new(&shared);
    let aes_recv = Aes256GcmHelper::new(&shared);

    let tun = TunDevice::create("nuntun")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let tun = std::sync::Arc::new(std::sync::Mutex::new(tun));

    let sock_clone = socket.try_clone()?;
    let tun_clone = std::sync::Arc::clone(&tun);
    thread::spawn(move || {
        let mut recv_buf = [0u8; 2048];
        let mut aes = aes_send; // encryption
        loop {
            let n = tun_clone
                .lock()
                .expect("lock tun")
                .read(&mut recv_buf)
                .expect("read tun");
            let (ct, nonce) = aes.encrypt(&recv_buf[..n]);
            let mut msg = Vec::with_capacity(14 + ct.len());
            msg.extend_from_slice(&nonce);
            msg.extend_from_slice(&(ct.len() as u16).to_be_bytes());
            msg.extend_from_slice(&ct);
            sock_clone.send(&msg).expect("send packet");
        }
    });

    let mut recv_buf = [0u8; 2048];
    let aes = aes_recv; // decryption
    loop {
        let n = socket.recv(&mut recv_buf)?;
        if n < 14 {
            continue;
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&recv_buf[..12]);
        let l = u16::from_be_bytes([recv_buf[12], recv_buf[13]]) as usize;
        if n < 14 + l {
            continue;
        }
        if let Some(plain) = aes.decrypt(&nonce, &recv_buf[14..14 + l]) {
            tun
                .lock()
                .expect("lock tun")
                .write(&plain)?;
        }
    }
}
