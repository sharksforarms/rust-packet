use crate::layer::{Layer, LayerError};
use std::convert::TryInto;

pub mod macaddress;
pub use macaddress::MacAddress;
mod parser;
use parser::parse_ether_header;

#[derive(Debug, PartialEq)]
pub struct Ether {
    pub dst: MacAddress,
    pub src: MacAddress,
    pub ether_type: u16,
}

impl Layer for Ether {
    /// Parsers an `Ether` struct from bytes returning the struct and un-consumed data
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), LayerError> {
        let (rest, (dst, src, ether_type)) = parse_ether_header(bytes)?;

        Ok((
            Ether {
                dst: dst.try_into()?,
                src: src.try_into()?,
                ether_type,
            },
            rest,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use quickcheck;
    use rstest::rstest_parametrize;

    const EMPTY: &[u8] = &[];

    #[rstest_parametrize(expected, input,
    // Normal
    case(
        Ok((
            Ether { dst: MacAddress::from_bytes([236, 8, 107, 80, 125, 88]), src: MacAddress::from_bytes([76, 204, 106, 214, 31, 118]), ether_type: 0x0800 },
            EMPTY
        )),
        &hex::decode("ec086b507d584ccc6ad61f760800").unwrap()
    ),
    // Ether + rest (FFFF)
    case(
        Ok((
            Ether { dst: MacAddress::from_bytes([236, 8, 107, 80, 125, 88]), src: MacAddress::from_bytes([76, 204, 106, 214, 31, 118]), ether_type: 0x0800 },
            [0xFF, 0xFF].as_ref()
        )),
        &hex::decode("ec086b507d584ccc6ad61f760800FFFF").unwrap()
    ),
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b""),
    )]
    fn test_ether_from_bytes(expected: Result<(Ether, &[u8]), LayerError>, input: &[u8]) {
        let ether = Ether::from_bytes(input);
        assert_eq!(expected, ether);
    }

    #[test]
    fn test_quickcheck_test_ether_from_bytes() {
        fn prop(input: Vec<u8>) {
            let _ = Ether::from_bytes(&input);
        }
        quickcheck::quickcheck(prop as fn(Vec<u8>));
    }
}
