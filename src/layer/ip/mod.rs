/*!
Ipv4 and Ipv6 layer
*/

#[macro_use]
pub mod ipv4;
pub mod ipv6;
pub mod protocols;

pub use ipv4::Ipv4;
pub use ipv6::Ipv6;
pub use protocols::IpProtocol;

use crate::layer::LayerError;
use std::convert::TryInto;

pub fn checksum(input: &[u8]) -> Result<u16, LayerError> {
    let mut sum = 0x00;
    let mut chunks_iter = input.chunks_exact(2);
    while let Some(chunk) = chunks_iter.next() {
        sum += u32::from(u16::from_be_bytes(
            chunk.try_into().expect("chunks of 2 bytes"),
        ));
    }

    if let [rem] = chunks_iter.remainder() {
        sum += u32::from(u16::from_be_bytes([*rem, 0x00]));
    }

    let carry_add = (sum & 0xffff) + (sum >> 16);
    let chksum = !(((carry_add & 0xffff) + (carry_add >> 16)) as u16);

    Ok(chksum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rstest::*;

    #[rstest(input, expected,
        case::calculate(&hex!("45000073000040004011 0000 c0a80001c0a800c7"), 0xB861),
        case::validate(&hex!("45000073000040004011 B861 c0a80001c0a800c7"), 0x0000),

        case::calculate_rem(&hex!("45000073000040004011 0000 c0a80001c0a800c7aa"), 0x0E61),
        case::validate_rem(&hex!("45000073000040004011 0E61 c0a80001c0a800c7aa"), 0x0000),
    )]
    fn test_checksum(input: &[u8], expected: u16) {
        let chksum = checksum(&input).unwrap();
        assert_eq!(expected, chksum);
    }
}
