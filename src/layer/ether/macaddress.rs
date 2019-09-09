use crate::layer::LayerError;
use nom::bytes::complete::tag;
use nom::bytes::complete::take_while_m_n;
use nom::combinator::map_res;
use nom::combinator::verify;
use nom::multi::separated_nonempty_list;
use nom::IResult;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn from_bytes(_input: &[u8]) -> Result<Self, LayerError> {
        unimplemented!()
    }
}

impl FromStr for MacAddress {
    type Err = LayerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Format: MM:MM:MM:SS:SS:SS

        let mut data = [0; 6];

        fn from_hex(input: &str) -> Result<u8, std::num::ParseIntError> {
            u8::from_str_radix(input, 16)
        }

        fn is_hex_digit(c: char) -> bool {
            c.is_digit(16)
        }

        pub(crate) fn hex_2(input: &str) -> IResult<&str, u8> {
            map_res(take_while_m_n(2, 2, is_hex_digit), from_hex)(input)
        }

        let parser = verify(separated_nonempty_list(tag(":"), hex_2), |v: &Vec<u8>| {
            v.len() == 6
        });

        let res = parser(s)
            .map_err(|_e| LayerError::Parse("parsing failure, invalid format".to_string()))?
            .1;

        data.copy_from_slice(&res);

        Ok(MacAddress(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest_parametrize;

    fn parse_mac_from_str(input: &str) -> Result<MacAddress, LayerError> {
        input.parse()
    }

    #[rstest_parametrize(expected, input,
    case(MacAddress([0,0,0,0,0,0]), "00:00:00:00:00:00"),
    case(MacAddress([170, 255, 255, 255, 255, 187]), "aa:ff:ff:ff:ff:bb"),
    case(MacAddress([170, 255, 255, 255, 255, 187]), "AA:FF:FF:FF:FF:BB"),
    )]
    fn test_parse_mac_str(expected: MacAddress, input: &str) {
        let mac = parse_mac_from_str(input).unwrap();
        assert_eq!(expected, mac);
    }

    #[rstest_parametrize(expected, input,
    case(LayerError::Parse("parsing failure, invalid format".to_string()),""),
    case(LayerError::Parse("parsing failure, invalid format".to_string()),":"),
    case(LayerError::Parse("parsing failure, invalid format".to_string()),"00:00:00:00:00"),
    case(LayerError::Parse("parsing failure, invalid format".to_string()),"00:00:00:00:00:00:00"),
    )]
    fn test_parse_mac_str_error(expected: LayerError, input: &str) {
        let layer_error = parse_mac_from_str(input).expect_err("Expect error");
        assert_eq!(expected, layer_error);
    }
}
