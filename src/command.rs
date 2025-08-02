use std::net::Ipv6Addr;
use serde::{Serialize, Deserialize}; // ← 追加

#[derive(Debug, Serialize, Deserialize)] // ← 追加
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
}

#[derive(Debug, Serialize, Deserialize)] // ← 追加
pub enum Message {
    /// クライアント登録要求 (c -> s)
    Register {
        address: Ipv6Addr,
        public_key: Vec<u8>,
    },

	/// クライアント登録応答 (s -> c)
	RegisterResponse {
		result: Result<(), ServerError>,
	},

    /// 公開鍵要求 (c -> s)
    KeyRequest {
        target_address: Ipv6Addr,
    },

    /// 公開鍵応答 (s -> c)
    KeyResponse {
        target_address: Ipv6Addr,
        result: Result<Vec<u8>, ServerError>, // OK
    },

    /// 暗号化ペイロードのフォワーディング要求 (c1 -> s -> c2)
    ForwardRequest {
        destination: Ipv6Addr,
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
