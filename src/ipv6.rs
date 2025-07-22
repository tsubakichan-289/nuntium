use std::net::Ipv6Addr;

/// Derive an IPv6 address from a Kyber public key by bitwise inverting the key
/// bytes and embedding the resulting bit sequence under the `4000::/7` prefix.
/// Leading zero bits of the inverted key are skipped. The next 121 bits fill the
/// suffix of the IPv6 address. If fewer than 121 bits remain, the suffix is
/// padded with zeros.
pub fn ipv6_from_public_key(pk: &[u8]) -> Ipv6Addr {
    let mut bits = Vec::with_capacity(pk.len() * 8);
    for &b in pk {
        let inv = !b;
        for i in (0..8).rev() {
            bits.push((inv >> i) & 1);
        }
    }

    // Remove leading zeros until the first '1' bit
    while let Some(0) = bits.first() {
        bits.remove(0);
    }

    // Take exactly 121 bits for the suffix
    bits.resize(121, 0);

    let mut addr = [0u8; 16];
    // Prefix 4000::/7 -> binary 0100_000, plus first suffix bit
    addr[0] = 0b0100_0000 | bits[0];
    let mut idx = 1;
    for byte in &mut addr[1..] {
        let mut b = 0u8;
        for _ in 0..8 {
            b = (b << 1) | bits[idx];
            idx += 1;
        }
        *byte = b;
    }

    Ipv6Addr::from(addr)
}
