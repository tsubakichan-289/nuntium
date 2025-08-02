use crate::command::Message;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::error::Error;
use std::io::{Read, Write};

/// メッセージを送信（先頭に長さをつける）
pub fn send_message<W: Write>(writer: &mut W, msg: &Message) -> Result<(), Box<dyn Error>> {
    let encoded = bincode::serialize(msg)?;
    let length = encoded.len() as u32;

    // 長さを先頭に書く（BigEndianで4バイト）
    writer.write_u32::<BigEndian>(length)?;
    // 本体を書き込む
    writer.write_all(&encoded)?;

    Ok(())
}

/// メッセージを受信（先頭の長さを読み取ってから本体を読む）
pub fn receive_message<R: Read>(reader: &mut R) -> Result<Message, Box<dyn Error>> {
    // 先頭の 4 バイトでメッセージの長さを取得
    let length = reader.read_u32::<BigEndian>()?;
    let mut buffer = vec![0u8; length as usize];

    // 本体を長さぶんだけ正確に読み込む
    reader.read_exact(&mut buffer)?;

    // 復元
    let msg: Message = bincode::deserialize(&buffer)?;
    Ok(msg)
}
