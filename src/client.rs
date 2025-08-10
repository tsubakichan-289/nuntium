use crate::command::Message;
use crate::config::load_config;
use crate::crypto_pool::{CryptoJob, CryptoPool};
use crate::ipv6::{get_kyber_key, ipv6_from_public_key};
use crate::message_io::{receive_message, send_message};
use crate::packet::parse_ipv6_packet;
use crate::shared_keys::{
    create_cache, get_key as cache_get, insert_key as cache_insert, SharedKeysCache,
};
use crate::tun::{create_tun, TunDevice, MTU};
use crate::tun_writer::TunWriter;

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};

use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender, TryRecvError};
#[cfg(unix)]
use nix::poll::{poll, PollFd, PollFlags};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::net::{Ipv6Addr, TcpStream, UdpSocket};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, BorrowedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tun::Configuration;

use log::{error, info};

fn spawn_receive_loop(
    mut stream: TcpStream,
    tx: Sender<Message>,
    tun: TunWriter,
    public_keys: SharedKeysCache,
    shared_secrets: Arc<Mutex<HashMap<Ipv6Addr, kyber1024::SharedSecret>>>,
    my_secret_key: kyber1024::SecretKey,
    crypto: CryptoPool,
) {
    std::thread::spawn(move || {
        let (resp_tx, resp_rx) = unbounded();
        let mut next_id = 0u64;
        let mut next_to_tun = 0u64;
        let mut inflight = 0usize;
        let mut buffer = BTreeMap::<u64, Option<Vec<u8>>>::new();
        const MAX_INFLIGHT: usize = 256;

        fn handle_resp(
            resp: (u64, Result<Vec<u8>, aes_gcm::aead::Error>),
            buffer: &mut BTreeMap<u64, Option<Vec<u8>>>,
            next: &mut u64,
            tun: &TunWriter,
        ) {
            let (id, res) = resp;
            match res {
                Ok(pkt) => {
                    buffer.insert(id, Some(pkt));
                }
                Err(e) => {
                    error!("❌ Failed to decrypt: {:?}", e);
                    buffer.insert(id, None);
                }
            }
            while let Some(opt) = buffer.remove(next) {
                if let Some(packet) = opt {
                    let len = packet.len();
                    if let Err(e) = tun.send(packet) {
                        error!("❌ Failed to send to TUN: {}", e);
                    } else {
                        info!("📦 Wrote to TUN: {} bytes", len);
                    }
                }
                *next += 1;
            }
        }

        loop {
            while inflight >= MAX_INFLIGHT {
                match resp_rx.recv() {
                    Ok(r) => {
                        inflight -= 1;
                        handle_resp(r, &mut buffer, &mut next_to_tun, &tun);
                    }
                    Err(_) => return,
                }
            }

            match receive_message(&mut stream) {
                Ok(msg) => match msg {
                    Message::ReceiveEncryptedData {
                        source,
                        ciphertext,
                        encrypted_payload,
                    } => {
                        info!("🔐 Received encrypted data: {}", source);

                        let ss = match ciphertext {
                            Some(ct_bytes) => {
                                info!(
                                    "🧩 Ciphertext provided; decapsulating and caching shared key: {}",
                                    source
                                );
                                let ct = kyber1024::Ciphertext::from_bytes(&ct_bytes)
                                    .expect("Invalid ciphertext");
                                let ss = kyber1024::decapsulate(&ct, &my_secret_key);
                                shared_secrets.lock().unwrap().insert(source, ss);
                                ss
                            }
                            None => {
                                info!("🔒 No ciphertext; using cached shared key: {}", source);
                                match shared_secrets.lock().unwrap().get(&source) {
                                    Some(cached) => *cached,
                                    None => {
                                        error!("❌ Shared key not cached: {}", source);
                                        continue;
                                    }
                                }
                            }
                        };

                        let id = next_id;
                        next_id += 1;
                        inflight += 1;

                        if let Err(e) = crypto.submit(CryptoJob::Decrypt {
                            packet_id: id,
                            key: ss.as_bytes().to_vec(),
                            data: encrypted_payload,
                            resp: resp_tx.clone(),
                        }) {
                            error!("❌ Failed to submit decrypt job: {}", e);
                            inflight -= 1;
                        }
                    }
                    Message::KeyResponse {
                        target_address,
                        result,
                    } => {
                        if let Ok(ref pk) = result {
                            cache_insert(&public_keys, target_address, pk.clone());
                        }
                        if let Err(e) = tx.send(Message::KeyResponse {
                            target_address,
                            result,
                        }) {
                            error!("❌ Failed to forward message: {}", e);
                        }
                    }

                    Message::RegisterResponse { .. } => {
                        if let Err(e) = tx.send(msg.clone()) {
                            error!("❌ Failed to forward message: {}", e);
                        }
                    }

                    _ => {
                        info!("📥 Irrelevant message: {:?}", msg);
                    }
                },
                Err(e) => {
                    error!("❌ Failed to receive message: {}", e);
                    break;
                }
            }

            loop {
                match resp_rx.try_recv() {
                    Ok(r) => {
                        inflight -= 1;
                        handle_resp(r, &mut buffer, &mut next_to_tun, &tun);
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
        }
    });
}

fn spawn_udp_receive_loop(
    socket: UdpSocket,
    tun: TunWriter,
    shared_secrets: Arc<Mutex<HashMap<Ipv6Addr, kyber1024::SharedSecret>>>,
    my_secret_key: kyber1024::SecretKey,
    crypto: CryptoPool,
) {
    std::thread::spawn(move || {
        let (resp_tx, resp_rx) = unbounded();
        let mut next_id = 0u64;
        let mut next_to_tun = 0u64;
        let mut inflight = 0usize;
        let mut buffer = BTreeMap::<u64, Option<Vec<u8>>>::new();
        const MAX_INFLIGHT: usize = 256;

        fn handle_resp(
            resp: (u64, Result<Vec<u8>, aes_gcm::aead::Error>),
            buffer: &mut BTreeMap<u64, Option<Vec<u8>>>,
            next: &mut u64,
            tun: &TunWriter,
        ) {
            let (id, res) = resp;
            match res {
                Ok(pkt) => {
                    buffer.insert(id, Some(pkt));
                }
                Err(e) => {
                    error!("❌ Failed to decrypt: {:?}", e);
                    buffer.insert(id, None);
                }
            }
            while let Some(opt) = buffer.remove(next) {
                if let Some(packet) = opt {
                    let len = packet.len();
                    if let Err(e) = tun.send(packet) {
                        error!("❌ Failed to send to TUN: {}", e);
                    } else {
                        info!("📦 Wrote to TUN: {} bytes", len);
                    }
                }
                *next += 1;
            }
        }

        let mut buf = [0u8; 65535];
        loop {
            while inflight >= MAX_INFLIGHT {
                match resp_rx.recv() {
                    Ok(r) => {
                        inflight -= 1;
                        handle_resp(r, &mut buffer, &mut next_to_tun, &tun);
                    }
                    Err(_) => return,
                }
            }

            match socket.recv(&mut buf) {
                Ok(size) => {
                    if let Ok(Message::ReceiveEncryptedData {
                        source,
                        ciphertext,
                        encrypted_payload,
                    }) = crate::message_io::deserialize_message(&buf[..size])
                    {
                        info!("🔐 Received encrypted data via UDP: {}", source);
                        let ss = match ciphertext {
                            Some(ct_bytes) => {
                                info!(
                                    "🧩 Ciphertext provided; decapsulating and caching shared key: {}",
                                    source
                                );
                                let ct = kyber1024::Ciphertext::from_bytes(&ct_bytes)
                                    .expect("Invalid ciphertext");
                                let ss = kyber1024::decapsulate(&ct, &my_secret_key);
                                shared_secrets.lock().unwrap().insert(source, ss);
                                ss
                            }
                            None => {
                                info!("🔒 No ciphertext; using cached shared key: {}", source);
                                match shared_secrets.lock().unwrap().get(&source) {
                                    Some(cached) => *cached,
                                    None => {
                                        error!("❌ Shared key not cached: {}", source);
                                        continue;
                                    }
                                }
                            }
                        };

                        let id = next_id;
                        next_id += 1;
                        inflight += 1;

                        if let Err(e) = crypto.submit(CryptoJob::Decrypt {
                            packet_id: id,
                            key: ss.as_bytes().to_vec(),
                            data: encrypted_payload,
                            resp: resp_tx.clone(),
                        }) {
                            error!("❌ Failed to submit decrypt job: {}", e);
                            inflight -= 1;
                        }
                    } else {
                        error!("❌ Failed to deserialize UDP message");
                    }
                }
                Err(e) => {
                    error!("❌ Failed to receive UDP message: {}", e);
                    break;
                }
            }

            loop {
                match resp_rx.try_recv() {
                    Ok(r) => {
                        inflight -= 1;
                        handle_resp(r, &mut buffer, &mut next_to_tun, &tun);
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
        }
    });
}

#[cfg(unix)]
fn process_tun_packets(
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    udp: &UdpSocket,
    public_keys: SharedKeysCache,
    shared_secrets: Arc<Mutex<HashMap<Ipv6Addr, kyber1024::SharedSecret>>>,
    mut tun: TunDevice,
    crypto: CryptoPool,
) -> Result<(), String> {
    let mut buf = [0u8; MTU];
    let (resp_tx, resp_rx) = unbounded();
    let mut next_id = 0u64;
    let mut next_to_send = 0u64;
    let mut inflight = 0usize;
    let mut meta = BTreeMap::<u64, (Ipv6Addr, Ipv6Addr, Option<Vec<u8>>, bool)>::new();
    let mut ready = BTreeMap::<u64, Option<(Message, bool)>>::new();
    const MAX_INFLIGHT: usize = 256;

    #[allow(clippy::type_complexity)]
    fn handle_resp(
        resp: (u64, Result<Vec<u8>, aes_gcm::aead::Error>),
        meta: &mut BTreeMap<u64, (Ipv6Addr, Ipv6Addr, Option<Vec<u8>>, bool)>,
        ready: &mut BTreeMap<u64, Option<(Message, bool)>>,
        next: &mut u64,
        udp: &UdpSocket,
    ) -> Result<(), String> {
        let (id, res) = resp;
        match res {
            Ok(payload) => {
                if let Some((src, dst, ct, first)) = meta.remove(&id) {
                    let msg = Message::SendEncryptedData {
                        source: src,
                        destination: dst,
                        ciphertext: ct.clone(),
                        encrypted_payload: payload,
                    };
                    ready.insert(id, Some((msg, first)));
                } else {
                    ready.insert(id, None);
                }
            }
            Err(e) => {
                error!("❌ Failed to encrypt: {:?}", e);
                meta.remove(&id);
                ready.insert(id, None);
            }
        }

        while let Some(opt) = ready.remove(next) {
            if let Some((msg, first)) = opt {
                let dst = match &msg {
                    Message::SendEncryptedData { destination, .. } => *destination,
                    _ => Ipv6Addr::UNSPECIFIED,
                };
                let bytes = crate::message_io::serialize_message(&msg)
                    .map_err(|e| format!("serialize failed: {}", e))?;
                udp.send(&bytes)
                    .map_err(|e| format!("Failed to send UDP: {}", e))?;
                info!(
                    "🔐 Sent encrypted_payload: {} (with ciphertext: {})",
                    dst, first
                );
            }
            *next += 1;
        }
        Ok(())
    }

    loop {
        while inflight >= MAX_INFLIGHT {
            match resp_rx.recv() {
                Ok(r) => {
                    inflight -= 1;
                    handle_resp(r, &mut meta, &mut ready, &mut next_to_send, udp)?;
                }
                Err(_) => return Err("crypto response channel closed".into()),
            }
        }

        let fd = tun.as_raw_fd();
        let mut fds = [PollFd::new(
            unsafe { BorrowedFd::borrow_raw(fd) },
            PollFlags::POLLIN,
        )];
        match poll(&mut fds, 1000u16) {
            Ok(0) => {}
            Ok(_) => {
                if let Some(revents) = fds[0].revents() {
                    if revents.contains(PollFlags::POLLIN) {
                        let n = tun
                            .read(&mut buf)
                            .map_err(|e| format!("TUN read failed: {}", e))?;
                        if let Some(parsed) = parse_ipv6_packet(&buf[..n]) {
                            if parsed.dst.is_multicast() {
                                continue;
                            }

                            info!("📦 IPv6: {} → {}", parsed.src, parsed.dst);

                            let peer_pk = get_dst_public_key(&public_keys, rx, stream, parsed.dst)?;
                            let peer_pk = kyber1024::PublicKey::from_bytes(&peer_pk)
                                .map_err(|_| "Invalid public key".to_string())?;

                            let (shared_secret, ciphertext, first_time) = {
                                let mut cache = shared_secrets.lock().unwrap();
                                if let Some(ss) = cache.get(&parsed.dst) {
                                    info!("🔒 Shared key found in cache: {}", parsed.dst);
                                    (*ss, None, false)
                                } else {
                                    info!("🔒 Caching shared key: {}", parsed.dst);
                                    let (ss, ct) = kyber1024::encapsulate(&peer_pk);
                                    cache.insert(parsed.dst, ss);
                                    (ss, Some(ct), true)
                                }
                            };

                            let id = next_id;
                            next_id += 1;
                            inflight += 1;
                            meta.insert(
                                id,
                                (
                                    parsed.src,
                                    parsed.dst,
                                    ciphertext.map(|c| c.as_bytes().to_vec()),
                                    first_time,
                                ),
                            );

                            if let Err(e) = crypto.submit(CryptoJob::Encrypt {
                                packet_id: id,
                                key: shared_secret.as_bytes().to_vec(),
                                data: buf[..n].to_vec(),
                                resp: resp_tx.clone(),
                            }) {
                                meta.remove(&id);
                                return Err(format!("failed to submit encrypt job: {}", e));
                            }
                        }
                    }
                }
            }
            Err(e) => return Err(format!("poll failed: {}", e)),
        }

        loop {
            match resp_rx.try_recv() {
                Ok(r) => {
                    inflight -= 1;
                    handle_resp(r, &mut meta, &mut ready, &mut next_to_send, udp)?;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err("crypto response channel closed".into());
                }
            }
        }
    }
}

#[cfg(windows)]
fn process_tun_packets(
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    udp: &UdpSocket,
    public_keys: SharedKeysCache,
    shared_secrets: Arc<Mutex<HashMap<Ipv6Addr, kyber1024::SharedSecret>>>,
    mut tun: TunDevice,
    crypto: CryptoPool,
) -> Result<(), String> {
    let mut buf = [0u8; MTU];
    let (resp_tx, resp_rx) = unbounded();
    let mut next_id = 0u64;
    let mut next_to_send = 0u64;
    let mut inflight = 0usize;
    let mut meta = BTreeMap::<u64, (Ipv6Addr, Ipv6Addr, Option<Vec<u8>>, bool)>::new();
    let mut ready = BTreeMap::<u64, Option<(Message, bool)>>::new();
    const MAX_INFLIGHT: usize = 256;

    #[allow(clippy::type_complexity)]
    fn handle_resp(
        resp: (u64, Result<Vec<u8>, aes_gcm::aead::Error>),
        meta: &mut BTreeMap<u64, (Ipv6Addr, Ipv6Addr, Option<Vec<u8>>, bool)>,
        ready: &mut BTreeMap<u64, Option<(Message, bool)>>,
        next: &mut u64,
        udp: &UdpSocket,
    ) -> Result<(), String> {
        let (id, res) = resp;
        match res {
            Ok(payload) => {
                if let Some((src, dst, ct, first)) = meta.remove(&id) {
                    let msg = Message::SendEncryptedData {
                        source: src,
                        destination: dst,
                        ciphertext: ct.clone(),
                        encrypted_payload: payload,
                    };
                    ready.insert(id, Some((msg, first)));
                } else {
                    ready.insert(id, None);
                }
            }
            Err(e) => {
                error!("❌ Failed to encrypt: {:?}", e);
                meta.remove(&id);
                ready.insert(id, None);
            }
        }

        while let Some(opt) = ready.remove(next) {
            if let Some((msg, first)) = opt {
                let dst = match &msg {
                    Message::SendEncryptedData { destination, .. } => *destination,
                    _ => Ipv6Addr::UNSPECIFIED,
                };
                let bytes = crate::message_io::serialize_message(&msg)
                    .map_err(|e| format!("serialize failed: {}", e))?;
                udp.send(&bytes)
                    .map_err(|e| format!("Failed to send UDP: {}", e))?;
                info!(
                    "🔐 Sent encrypted_payload: {} (with ciphertext: {})",
                    dst, first
                );
            }
            *next += 1;
        }
        Ok(())
    }

    loop {
        while inflight >= MAX_INFLIGHT {
            match resp_rx.recv() {
                Ok(r) => {
                    inflight -= 1;
                    handle_resp(r, &mut meta, &mut ready, &mut next_to_send, udp)?;
                }
                Err(_) => return Err("crypto response channel closed".into()),
            }
        }

        let n = tun
            .read(&mut buf)
            .map_err(|e| format!("TUN read failed: {}", e))?;
        if let Some(parsed) = parse_ipv6_packet(&buf[..n]) {
            if parsed.dst.is_multicast() {
                continue;
            }

            info!("📦 IPv6: {} → {}", parsed.src, parsed.dst);

            let peer_pk = get_dst_public_key(&public_keys, rx, stream, parsed.dst)?;
            let peer_pk = kyber1024::PublicKey::from_bytes(&peer_pk)
                .map_err(|_| "Invalid public key".to_string())?;

            let (shared_secret, ciphertext, first_time) = {
                let mut cache = shared_secrets.lock().unwrap();
                if let Some(ss) = cache.get(&parsed.dst) {
                    info!("🔒 Shared key found in cache: {}", parsed.dst);
                    (*ss, None, false)
                } else {
                    info!("🔒 Caching shared key: {}", parsed.dst);
                    let (ss, ct) = kyber1024::encapsulate(&peer_pk);
                    cache.insert(parsed.dst, ss);
                    (ss, Some(ct), true)
                }
            };

            let id = next_id;
            next_id += 1;
            inflight += 1;
            meta.insert(
                id,
                (
                    parsed.src,
                    parsed.dst,
                    ciphertext.map(|c| c.as_bytes().to_vec()),
                    first_time,
                ),
            );

            if let Err(e) = crypto.submit(CryptoJob::Encrypt {
                packet_id: id,
                key: shared_secret.as_bytes().to_vec(),
                data: buf[..n].to_vec(),
                resp: resp_tx.clone(),
            }) {
                meta.remove(&id);
                return Err(format!("failed to submit encrypt job: {}", e));
            }
        }

        loop {
            match resp_rx.try_recv() {
                Ok(r) => {
                    inflight -= 1;
                    handle_resp(r, &mut meta, &mut ready, &mut next_to_send, udp)?;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err("crypto response channel closed".into());
                }
            }
        }
    }
}

pub fn run_client() -> Result<(), String> {
    let config = load_config()?;
    let addr = format!("{}:{}", config.ip, config.port);

    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("Connection failed: {}", e))?;
    info!("✅ Connected to server");
    let udp_socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("UDP bind failed: {}", e))?;
    udp_socket
        .connect(&addr)
        .map_err(|e| format!("UDP connect failed: {}", e))?;

    let (my_pk, my_sk) = get_kyber_key();
    let shared_secrets = Arc::new(Mutex::new(HashMap::new()));
    let public_keys = create_cache(config.ttl_seconds, config.max_keys);

    let public_key = my_pk.as_bytes();
    let local_ipv6 = ipv6_from_public_key(public_key);
    info!("✅ Own IPv6 address: {}", local_ipv6);

    let (tun_reader, tun_name) =
        create_tun(local_ipv6).map_err(|e| format!("Failed to create TUN: {}", e))?;
    info!("✅ Created TUN device {}", tun_name);

    #[cfg(unix)]
    let tun_writer = {
        use std::fs::OpenOptions;
        use std::os::unix::io::IntoRawFd;

        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| format!("Failed to open /dev/net/tun: {}", e))?
            .into_raw_fd();

        let mut write_cfg = Configuration::default();
        write_cfg.name(&tun_name).raw_fd(fd);
        let tun_writer_dev =
            tun::create(&write_cfg).map_err(|e| format!("Failed to open TUN writer: {}", e))?;
        TunWriter::new(tun_writer_dev)
    };

    #[cfg(not(unix))]
    let tun_writer = {
        let mut write_cfg = Configuration::default();
        write_cfg.name(&tun_name);
        let tun_writer_dev =
            tun::create(&write_cfg).map_err(|e| format!("Failed to open TUN writer: {}", e))?;
        TunWriter::new(tun_writer_dev)
    };

    let (tx, rx) = unbounded();

    let crypto = CryptoPool::new();

    let my_sk_clone = my_sk;
    spawn_receive_loop(
        stream.try_clone().unwrap(),
        tx,
        tun_writer.clone(),
        public_keys.clone(),
        shared_secrets.clone(),
        my_sk_clone,
        crypto.clone(),
    );
    spawn_udp_receive_loop(
        udp_socket.try_clone().unwrap(),
        tun_writer.clone(),
        shared_secrets.clone(),
        my_sk,
        crypto.clone(),
    );

    register_to_server(&rx, &mut stream, local_ipv6, public_key)?;

    let res = process_tun_packets(
        &rx,
        &mut stream,
        &udp_socket,
        public_keys,
        shared_secrets,
        tun_reader,
        crypto,
    );

    tun_writer.shutdown();

    res
}

fn get_dst_public_key(
    cache: &SharedKeysCache,
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    address: Ipv6Addr,
) -> Result<Vec<u8>, String> {
    info!("🔍 Entering get_dst_public_key for address: {}", address);

    // Check LRU cache first
    if let Some(pk) = cache_get(cache, &address) {
        info!("📦 Found cached public key for: {}", address);
        return Ok(pk);
    }

    info!("📭 Sending KeyRequest to server for: {}", address);
    send_message(
        stream,
        &Message::KeyRequest {
            target_address: address,
        },
    )
    .map_err(|e| format!("Failed to send key request: {}", e))?;

    info!("⏳ Waiting for KeyResponse for: {}", address);

    loop {
        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Message::KeyResponse {
                target_address,
                result,
            }) if target_address == address => {
                info!("📬 Received KeyResponse for: {}", address);
                let public_key = result.map_err(|e| format!("Key error: {:?}", e))?;
                cache_insert(cache, address, public_key.clone());
                info!("✅ Cached public key for: {}", address);
                return Ok(public_key);
            }

            Ok(other) => {
                info!("📥 Received unrelated message while waiting: {:?}", other);
            }

            Err(RecvTimeoutError::Timeout) => {
                info!("⏰ Timeout waiting for KeyResponse: {}", address);
                return Err("Timed out waiting for key response".to_string());
            }

            Err(e) => {
                info!("❌ Error receiving from channel: {}", e);
                return Err(format!("Failed to receive from channel: {}", e));
            }
        }
    }
}

fn register_to_server(
    rx: &Receiver<Message>,
    stream: &mut TcpStream,
    local_ipv6: Ipv6Addr,
    public_key: &[u8],
) -> Result<(), String> {
    send_message(
        stream,
        &Message::Register {
            address: local_ipv6,
            public_key: public_key.to_vec(),
        },
    )
    .map_err(|e| format!("Failed to send registration: {}", e))?;

    loop {
        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Message::RegisterResponse { result }) => match result {
                Ok(()) => {
                    info!("✅ Registration successful");
                    return Ok(());
                }
                Err(e) => return Err(format!("Registration failed: {:?}", e)),
            },
            Ok(other) => {
                info!("📥 Other message: {:?}", other);
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err("Timed out waiting for registration response".to_string());
            }
            Err(e) => return Err(format!("Failed to receive from channel: {}", e)),
        }
    }
}
