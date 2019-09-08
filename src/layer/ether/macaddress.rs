use crate::layer::noms::hex_2;
use crate::layer::LayerError;
use nom::bytes::complete::tag;
use nom::multi::separated_nonempty_list;
use nom::IResult;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    fn from_bytes(bytes: &[u8]) -> Result<MacAddress, LayerError> {
        unimplemented!()
    }
}

impl FromStr for MacAddress {
    type Err = LayerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Format: MM:MM:MM:SS:SS:SS

        let mut data = [0; 6];

        fn parser(s: &str) -> IResult<&str, Vec<u8>> {
            separated_nonempty_list(tag(":"), hex_2)(s)
        }

        let res = parser(s)
            .map_err(|e| LayerError::Parse(format!("parsing failure, invalid format")))?
            .1;

        if res.len() != data.len() {
            return Err(LayerError::Parse(format!(
                "expected {} bytes got {}",
                data.len(),
                res.len()
            )));
        }

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
    case(LayerError::Parse("expected 6 bytes got 5".to_string()),"00:00:00:00:00"),
    case(LayerError::Parse("expected 6 bytes got 7".to_string()),"00:00:00:00:00:00:00"),
    )]
    fn test_parse_mac_str_error(expected: LayerError, input: &str) {
        let layer_error = parse_mac_from_str(input).expect_err("Expect error");
        assert_eq!(expected, layer_error);
    }
}
