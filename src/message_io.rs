use crate::command::Message;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::error::Error;
use std::io::{Read, Write};

/// Send a message with a length prefix
pub fn send_message<W: Write>(writer: &mut W, msg: &Message) -> Result<(), Box<dyn Error>> {
    let encoded = bincode::serialize(msg)?;
    let length = encoded.len() as u32;

    // Write the length prefix (4 bytes, BigEndian)
    writer.write_u32::<BigEndian>(length)?;
    // Write the payload
    writer.write_all(&encoded)?;

    Ok(())
}

/// Receive a message by reading the length prefix and then the payload
pub fn receive_message<R: Read>(reader: &mut R) -> Result<Message, Box<dyn Error>> {
    // Read the first 4 bytes to get the message length
    let length = reader.read_u32::<BigEndian>()?;
    let mut buffer = vec![0u8; length as usize];

    // Read exactly `length` bytes for the payload
    reader.read_exact(&mut buffer)?;

    // Deserialize
    let msg: Message = bincode::deserialize(&buffer)?;
    Ok(msg)
}

/// Receive a message into a reusable buffer to reduce allocations.
#[allow(dead_code)]
pub fn receive_message_into<R: Read>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> Result<Message, Box<dyn Error>> {
    let length = reader.read_u32::<BigEndian>()?;
    buffer.clear();
    buffer.resize(length as usize, 0);
    reader.read_exact(buffer)?;
    let msg: Message = bincode::deserialize(buffer)?;
    Ok(msg)
}
