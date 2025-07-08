use pqcrypto_traits::kem::PublicKey as _;
use std::net::TcpStream;
use std::io::{Read, Write};
use nuntium::{pqc, crypto::Aes256GcmHelper, ipv6::make_ipv6_from_pubkey};

fn main() -> std::io::Result<()> {
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
