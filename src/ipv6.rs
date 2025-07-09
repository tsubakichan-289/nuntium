use std::net::Ipv6Addr;

/// IPv6 prefix used for all derived addresses (4000::/7).
const PREFIX: [u8; 2] = [0x40, 0x00];

/// Derive an IPv6 address from a public key within the `4000::/7` prefix.
///
/// The suffix is obtained by bitwise inverting the public key and skipping any
/// leading zero bits until the first `1` is encountered. The next 121 bits are
/// taken as the suffix (padded with zeros if necessary).
pub fn ipv6_from_public_key(pk: &[u8]) -> Ipv6Addr {
    // Bitwise invert the public key
    let inverted: Vec<u8> = pk.iter().map(|b| !b).collect();

    // Collect bits in big-endian order
    let mut bits = Vec::with_capacity(inverted.len() * 8);
    for b in inverted {
        for i in (0..8).rev() {
            bits.push((b >> i) & 1);
        }
    }

    // Skip leading zeros
    let start = bits.iter().position(|&bit| bit == 1).unwrap_or(bits.len());
    let bits = &bits[start..];

    // Prepare address bytes with the prefix
    let mut addr = [0u8; 16];
    addr[0] = PREFIX[0];
    addr[1] = PREFIX[1];

    // Fill in the suffix bits
    let mut bit_index = 7; // start after the 7-bit prefix
    for i in 0..121 {
        let bit = if i < bits.len() { bits[i] } else { 0 };
        if bit == 1 {
            let byte_idx = bit_index / 8;
            let bit_pos = 7 - (bit_index % 8);
            addr[byte_idx] |= 1 << bit_pos;
        }
        bit_index += 1;
    }

    Ipv6Addr::from(addr)
}
