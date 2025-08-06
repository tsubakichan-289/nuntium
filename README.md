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
`ttl_seconds` で公開鍵キャッシュの有効期限（秒）を、`max_keys` で保持する最大件数を指定できます。

```json
{
  "ip": "172.30.0.2",
  "port": 5072,
  "ttl_seconds": 3600,
  "max_keys": 1000
}
```

