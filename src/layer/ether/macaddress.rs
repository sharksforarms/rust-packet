use crate::layer::LayerError;
use deku::prelude::*;
use nom::bytes::{complete::tag, complete::take_while_m_n};
use nom::combinator::{map_res, verify};
use nom::multi::separated_nonempty_list;
use nom::IResult;
use std::convert::TryFrom;

const MACADDR_SIZE: usize = 6;

// Parse mac address from string and return a Vec<u8>
// Format: MM:MM:MM:SS:SS:SS
fn parse_macaddr_str(input: &str) -> IResult<&str, Vec<u8>> {
    fn from_hex(input: &str) -> Result<u8, std::num::ParseIntError> {
        u8::from_str_radix(input, 16)
    }

    fn is_hex_digit(c: char) -> bool {
        c.is_digit(16)
    }

    fn hex_2(input: &str) -> IResult<&str, u8> {
        map_res(take_while_m_n(2, 2, is_hex_digit), from_hex)(input)
    }

    verify(separated_nonempty_list(tag(":"), hex_2), |v: &Vec<u8>| {
        v.len() == MACADDR_SIZE
    })(input)
}

/// Type representing an ethernet mac address
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
pub struct MacAddress(pub [u8; MACADDR_SIZE]);

impl std::str::FromStr for MacAddress {
    type Err = LayerError;

    /// From a `MM:MM:MM:SS:SS:SS` formatted mac address
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = parse_macaddr_str(s)
            .map_err(|_e| LayerError::Parse("parsing failure, invalid format".to_string()))?
            .1;

        Ok(MacAddress::try_from(res.as_ref())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest(input, expected,
        case(&[1,2,3,4,5,6], MacAddress([1,2,3,4,5,6])),

        // TODO: https://github.com/sharksforarms/deku/issues/47
        // #[should_panic(expected = "reason")]
        // case(&[1,2,3,4,5,6,7], MacAddress([1,2,3,4,5,6])),
    )]
    fn test_mac_from_bytes(expected: MacAddress, input: &[u8]) {
        let res = MacAddress::try_from(input).unwrap();
        assert_eq!(expected, res);
    }

    #[rstest(input, expected,
        case("00:00:00:00:00:00", Ok(MacAddress([0,0,0,0,0,0]))),
        case("aa:ff:ff:ff:ff:bb", Ok(MacAddress([170, 255, 255, 255, 255, 187]))),
        case("AA:FF:FF:FF:FF:BB", Ok(MacAddress([170, 255, 255, 255, 255, 187]))),
        case("", Err(LayerError::Parse("parsing failure, invalid format".to_string()))),
        case(":", Err(LayerError::Parse("parsing failure, invalid format".to_string()))),
        case("00:00:00:00:00", Err(LayerError::Parse("parsing failure, invalid format".to_string()))),
        case("00:00:00:00:00:00:00", Err(LayerError::Parse("parsing failure, invalid format".to_string()))),
    )]
    fn test_mac_from_str(input: &str, expected: Result<MacAddress, LayerError>) {
        let mac: Result<MacAddress, LayerError> = input.parse();
        assert_eq!(expected, mac);
    }
}
