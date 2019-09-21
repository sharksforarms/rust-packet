use crate::layer::{Layer, LayerError};
use byteorder::{ByteOrder, NetworkEndian};
use nom::bytes::streaming::take;
use nom::combinator::map_res;
use nom::sequence::tuple;
use nom::IResult;
use std::convert::TryInto;

pub mod macaddress;
use macaddress::MacAddress;

const ETH_TYPE_SIZE: usize = 2;

#[derive(Debug, PartialEq)]
pub struct Ether {
    dst: MacAddress,
    src: MacAddress,
    ether_type: u16,
}

impl Layer for Ether {
    type LayerType = Ether;

    /// Parsers an `Ether` struct from bytes returning the struct and un-consumed data
    fn from_bytes(bytes: &[u8]) -> Result<(Self::LayerType, &[u8]), LayerError> {
        fn take_mac_address(input: &[u8]) -> IResult<&[u8], &[u8]> {
            take(macaddress::MACADDR_SIZE)(input)
        }

        fn take_ether_type(input: &[u8]) -> IResult<&[u8], u16> {
            map_res(take(ETH_TYPE_SIZE), |v| -> Result<u16, LayerError> {
                Ok(NetworkEndian::read_u16(v))
            })(input)
        }

        let parser = tuple((take_mac_address, take_mac_address, take_ether_type));
        let (rest, (dst, src, ether_type)) = parser(bytes)?;

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
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b"aa"),
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b"aaaaaaa"),
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b"aaaaaaaaaaaa"),
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
