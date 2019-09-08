use super::macaddress::MACADDR_SIZE;
use byteorder::{ByteOrder, NetworkEndian};
use nom::bytes::complete::tag;
use nom::bytes::complete::take_while_m_n;
use nom::bytes::streaming::take;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::combinator::verify;
use nom::multi::separated_nonempty_list;
use nom::sequence::tuple;
use nom::IResult;

pub fn parse_macaddr_str(input: &str) -> IResult<&str, Vec<u8>> {
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

pub fn parse_ether_header(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8], u16)> {
    fn take_mac_address(input: &[u8]) -> IResult<&[u8], &[u8]> {
        take(MACADDR_SIZE)(input)
    }

    fn take_ether_type(input: &[u8]) -> IResult<&[u8], u16> {
        map(take(2usize), |v| -> u16 { NetworkEndian::read_u16(v) })(input)
    }

    tuple((take_mac_address, take_mac_address, take_ether_type))(input)
}
