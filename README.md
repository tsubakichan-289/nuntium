# Nuntium

Nuntium は Kyber を用いた鍵交換と AES-256-GCM による暗号化を組み合わせ、IPv6 上で安全な通信を行うための実験的なツールです。

## 主な機能

- Kyber で生成された公開鍵から IPv6 アドレスを導出
- TUN デバイスを介したパケット転送
- AES-256-GCM によるペイロード暗号化
- サーバーを介した公開鍵の共有と暗号化データの中継

## ビルドとテスト

Rust 2021 edition に対応しています。開発時は以下のコマンドでコード整形と検証を行ってください。

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

## 実行方法

サーバーを起動する:

```bash
cargo run -- server
```

クライアントを起動する:

```bash
cargo run -- client
```

設定は `nuntium.conf` で行います。

Below is a minimal example for trying out the tunnel. The relay listens on UDP
port `9001` and root privileges are required to create the interface:

1. **Start the relay** on the server:
   ```bash
   nuntium --mode server-tun
   ```
2. **Configure** `/etc/nuntium.conf` on each client with the server's IPv4
   address (the port is fixed at `9001`).
3. **Run the client** as root to create the `nuntun` device:
   ```bash
   sudo nuntium --mode client-tun
   ```
4. **Ping another peer** using the printed IPv6 address:
   ```bash
   ping -6 <addr> -I nuntun
   ```

