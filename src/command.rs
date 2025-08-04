use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ServerError {
    /// 公開鍵が見つからなかった
    KeyNotFound(Ipv6Addr),

    /// クライアントが未登録
    UnregisteredClient,

    /// 宛先クライアントがオフライン
    DestinationUnavailable(Ipv6Addr),

    /// 不正な要求
    InvalidRequest(String),

    /// サーバー内部エラー
    InternalError(String),

    /// クライアントのアドレスが無効
    InvalidAddress,

    /// 排他制御のロックが破損
    LockPoisoned,

    /// ストレージへの保存に失敗
    StorageFailure,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    /// クライアント登録要求 (c -> s)
    Register {
        address: Ipv6Addr,
        public_key: Vec<u8>,
    },

    /// クライアント登録応答 (s -> c)
    RegisterResponse { result: Result<(), ServerError> },

    /// 公開鍵要求 (c -> s)
    KeyRequest { target_address: Ipv6Addr },

    /// 公開鍵応答 (s -> c)
    KeyResponse {
        target_address: Ipv6Addr,
        result: Result<Vec<u8>, ServerError>, // OK
    },

    /// encrypted_payload を送信する (c -> s)
    SendEncryptedData {
        source: Ipv6Addr,
        destination: Ipv6Addr,
        ciphertext: Option<Vec<u8>>,
        encrypted_payload: Vec<u8>,
    },

    /// encrypted_payload を受信する (s -> c)
    ReceiveEncryptedData {
        source: Ipv6Addr,
        ciphertext: Option<Vec<u8>>,
        encrypted_payload: Vec<u8>,
    },

    /// フォワーディングされた暗号通信 (s -> c2)
    ForwardedData {
        source: Ipv6Addr,
        encrypted_payload: Vec<u8>,
    },

    /// エラーメッセージ (s -> c)
    Error(ServerError),
}
