use crate::layer::LayerError;
use deku::bitvec::BitView;
use deku::prelude::*;
use nom::bytes::{complete::tag, complete::take_while_m_n};
use nom::combinator::{map_res, verify};
use nom::multi::separated_nonempty_list;
use nom::IResult;

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
#[derive(Debug, PartialEq, Clone, Default, DekuRead, DekuWrite)]
#[deku(
    ctx_default = "deku::ctx::Endian::Big",
    ctx = "_endian: deku::ctx::Endian"
)]
pub struct MacAddress(pub [u8; MACADDR_SIZE]);

impl std::str::FromStr for MacAddress {
    type Err = LayerError;

    /// From a `MM:MM:MM:SS:SS:SS` formatted mac address
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = parse_macaddr_str(s)
            .map_err(|_e| LayerError::Parse("parsing failure, invalid format".to_string()))?
            .1;

        let (_rest, mac_addr) = MacAddress::read(res.view_bits(), deku::ctx::Endian::Big)?;

        Ok(mac_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest(input, expected,
        case(&[0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xBB], MacAddress([0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xBB])),
    )]
    fn test_macaddress(input: &[u8], expected: MacAddress) {
        let (_rest, ret_read) = MacAddress::from_bytes((input, 0)).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = ret_read.to_bytes().unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_macaddress_default() {
        assert_eq!(MacAddress([0x00u8; 6]), MacAddress::default())
    }

    #[rstest(input, expected,
        case("00:00:00:00:00:00", Ok(MacAddress([0,0,0,0,0,0]))),
        case("aa:ff:ff:ff:ff:bb", Ok(MacAddress([0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xBB]))),
        case("AA:FF:FF:FF:FF:BB", Ok(MacAddress([0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xBB]))),
        case("", Err(LayerError::Parse("parsing failure, invalid format".to_string()))),
        case(":", Err(LayerError::Parse("parsing failure, invalid format".to_string()))),
        case("00:00:00:00:00", Err(LayerError::Parse("parsing failure, invalid format".to_string()))),
        case("00:00:00:00:00:00:00", Err(LayerError::Parse("parsing failure, invalid format".to_string()))),
    )]
    fn test_macaddress_from_str(input: &str, expected: Result<MacAddress, LayerError>) {
        let mac: Result<MacAddress, LayerError> = input.parse();
        assert_eq!(expected, mac);
    }
}
