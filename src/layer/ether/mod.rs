use crate::layer::{Layer, LayerError};

pub mod macaddress;
use byteorder::{ByteOrder, NetworkEndian};
use nom::bytes::streaming::take;
use nom::combinator::map_res;
use nom::sequence::tuple;
use nom::IResult;
use std::convert::TryInto;

const ETH_TYPE_LEN: usize = 2;
const ETH_MACADDR_LEN: usize = 6;

#[derive(Debug, PartialEq)]
struct Ether {
    dst: [u8; ETH_MACADDR_LEN],
    src: [u8; ETH_MACADDR_LEN],
    ether_type: u16,
}

impl Layer for Ether {
    type LayerType = Ether;

    fn from_bytes(bytes: &[u8]) -> Result<Self::LayerType, LayerError> {
        fn take_mac_address(input: &[u8]) -> IResult<&[u8], &[u8]> {
            take(ETH_MACADDR_LEN)(input)
        }
        fn take_ether_type(input: &[u8]) -> IResult<&[u8], u16> {
            map_res(take(ETH_TYPE_LEN), |v| -> Result<u16, LayerError> {
                Ok(NetworkEndian::read_u16(v))
            })(input)
        }

        let parser = tuple((take_mac_address, take_mac_address, take_ether_type));
        let (_, (dst, src, ether_type)) = parser(bytes)?;

        Ok(Ether {
            dst: dst.try_into().map_err(|e| {
                LayerError::Unexpected(format!("ether dst conversion error: {:?}", e))
            })?,
            src: src.try_into().map_err(|e| {
                LayerError::Unexpected(format!("ether src conversion error: {:?}", e))
            })?,
            ether_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use rstest::rstest_parametrize;

    fn ether_from_bytes(input: &[u8]) -> Result<Ether, LayerError> {
        Ether::from_bytes(input)
    }

    #[rstest_parametrize(expected, input,
    case(Ether { dst: [236, 8, 107, 80, 125, 88], src: [76, 204, 106, 214, 31, 118], ether_type: 0x0800 }, &hex::decode("ec086b507d584ccc6ad61f760800").unwrap()),
    )]
    fn test_ether_from_bytes(expected: Ether, input: &[u8]) {
        let ether = ether_from_bytes(input).unwrap();
        assert_eq!(expected, ether);
    }

    #[rstest_parametrize(expected, input,
    case(LayerError::Parse("incomplete data, parser step failed. Step needs 6 bytes".to_string()), b""),
    case(LayerError::Parse("incomplete data, parser step failed. Step needs 6 bytes".to_string()), b"aa"),
    case(LayerError::Parse("incomplete data, parser step failed. Step needs 6 bytes".to_string()), b"aaaaaaa"),
    case(LayerError::Parse("incomplete data, parser step failed. Step needs 2 bytes".to_string()), b"aaaaaaaaaaaa"),
    case(LayerError::Parse("incomplete data, parser step failed. Step needs 2 bytes".to_string()), b"aaaaaaaaaaaaa"),
    )]
    fn test_ether_from_bytes_error(expected: LayerError, input: &[u8]) {
        let ether = ether_from_bytes(input).expect_err("Expect error");
        assert_eq!(expected, ether);
    }

}
