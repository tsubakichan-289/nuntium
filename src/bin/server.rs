use pqcrypto_traits::kem::PublicKey as _;
use std::net::{TcpListener};
use std::io::{Read, Write};
use nuntium::{pqc, crypto::Aes256GcmHelper, ipv6::make_ipv6_from_pubkey};

fn main() -> std::io::Result<()> {
    let (pk, sk) = pqc::generate_keypair();
    let addr = make_ipv6_from_pubkey(pk.as_bytes());
    println!("Server IPv6: {}", addr);

    let listener = TcpListener::bind("0.0.0.0:9000")?;
    let (mut stream, _) = listener.accept()?;

    // receive client pk
    let mut client_pk_bytes = vec![0u8; pqc::PUBLIC_KEY_LEN];
    stream.read_exact(&mut client_pk_bytes)?;
    let client_pk = pqc::public_key_from_bytes(&client_pk_bytes);
    let _client_addr = make_ipv6_from_pubkey(client_pk.as_bytes());
    println!("Client IPv6: {}", _client_addr);

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
