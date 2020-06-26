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
    if input.len() % 2 != 0 {
        return Err(LayerError::Checksum(
            "input length not divisible by 2".to_string(),
        ));
    }

    let sum: u32 = input
        .chunks_exact(2)
        .map(|v| u32::from(u16::from_be_bytes(v.try_into().expect("chunks of 2 bytes"))))
        .sum();

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

        #[should_panic(expected = "Checksum(\"input length not divisible by 2\")")]
        case(&hex!("450000730000400040110000c0a80001c0a800"), 0xFF),
    )]
    fn test_checksum(input: &[u8], expected: u16) {
        let chksum = checksum(&input).unwrap();
        assert_eq!(expected, chksum);
    }
}
