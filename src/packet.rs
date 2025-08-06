#![allow(dead_code)]
use std::net::Ipv6Addr;

/// Enumeration of upper-layer packet types
#[derive(Debug)]
pub enum UpperLayerPacket {
    Tcp(TcpHeader),
    Icmpv6(Icmpv6Header),
    Unknown(u8, Vec<u8>), // Unsupported protocol and raw payload
}

/// Parsed IPv6 header
#[derive(Debug)]
pub struct Ipv6Header {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: u8,
    pub payload_length: u16,
    pub hop_limit: u8,
    pub upper_layer: UpperLayerPacket,
}

/// Parsed TCP header
#[derive(Debug)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub payload: Vec<u8>,
}

/// Parsed ICMPv6 header
#[derive(Debug)]
pub struct Icmpv6Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

/// Parse an IPv6 packet
#[inline]
pub fn parse_ipv6_packet(packet: &[u8]) -> Option<Ipv6Header> {
    if packet.len() < 40 {
        return None;
    }

    let payload_length = u16::from_be_bytes([packet[4], packet[5]]);
    let next_header = packet[6];
    let hop_limit = packet[7];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    let payload = &packet[40..];

    let upper_layer = match next_header {
        6 => parse_tcp_packet(payload)
            .map(UpperLayerPacket::Tcp)
            .unwrap_or_else(|| UpperLayerPacket::Unknown(6, payload.to_vec())),
        58 => parse_icmpv6_packet(payload)
            .map(UpperLayerPacket::Icmpv6)
            .unwrap_or_else(|| UpperLayerPacket::Unknown(58, payload.to_vec())),
        other => UpperLayerPacket::Unknown(other, payload.to_vec()),
    };

    Some(Ipv6Header {
        src,
        dst,
        next_header,
        payload_length,
        hop_limit,
        upper_layer,
    })
}

/// Parse a TCP header
#[inline]
fn parse_tcp_packet(payload: &[u8]) -> Option<TcpHeader> {
    if payload.len() < 20 {
        return None;
    }

    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    let sequence_number = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let acknowledgement_number =
        u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let data_offset = (payload[12] >> 4) * 4;

    if payload.len() < data_offset as usize {
        return None;
    }

    let flags = u16::from_be_bytes([payload[12] & 0x0F, payload[13]]);
    let window_size = u16::from_be_bytes([payload[14], payload[15]]);
    let checksum = u16::from_be_bytes([payload[16], payload[17]]);
    let urgent_pointer = u16::from_be_bytes([payload[18], payload[19]]);
    let payload_data = payload[data_offset as usize..].to_vec();

    Some(TcpHeader {
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer,
        payload: payload_data,
    })
}

/// Parse an ICMPv6 header
#[inline]
fn parse_icmpv6_packet(payload: &[u8]) -> Option<Icmpv6Header> {
    if payload.len() < 4 {
        return None;
    }

    let icmp_type = payload[0];
    let code = payload[1];
    let checksum = u16::from_be_bytes([payload[2], payload[3]]);
    let rest = payload[4..].to_vec();

    Some(Icmpv6Header {
        icmp_type,
        code,
        checksum,
        payload: rest,
    })
}
