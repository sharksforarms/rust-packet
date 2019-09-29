use crate::layer::LayerError;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::str::FromStr;

use super::parser::parse_macaddr_str;
pub(crate) const MACADDR_SIZE: usize = 6;

#[derive(Debug, PartialEq)]
pub struct MacAddress(pub [u8; MACADDR_SIZE]);

impl MacAddress {
    pub fn from_bytes(input: [u8; MACADDR_SIZE]) -> Self {
        MacAddress(input)
    }
    pub fn from_slice(input: &[u8]) -> Result<Self, LayerError> {
        if input.len() != MACADDR_SIZE {
            return Err(LayerError::Parse(format!(
                "expected {} bytes got {}",
                MACADDR_SIZE,
                input.len()
            )));
        }

        Ok(MacAddress::from_bytes(input.try_into().map_err(|e| {
            LayerError::Unexpected(format!(
                "during conversion of byte slice to mac address: {:?}",
                e
            ))
        })?))
    }
}

impl TryFrom<&[u8]> for MacAddress {
    type Error = LayerError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        MacAddress::from_slice(value)
    }
}
impl FromStr for MacAddress {
    type Err = LayerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Format: MM:MM:MM:SS:SS:SS

        let res = parse_macaddr_str(s)
            .map_err(|_e| LayerError::Parse("parsing failure, invalid format".to_string()))?
            .1;

        MacAddress::from_slice(&res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest_parametrize;

    #[test]
    fn test_mac_from_bytes() {
        let _mac = MacAddress::from_bytes([0, 0, 0, 0, 0, 0]);
    }

    #[rstest_parametrize(expected, input,
    case(Ok(MacAddress([1,2,3,4,5,6])), &[1,2,3,4,5,6]),
    case(Err(LayerError::Parse("expected 6 bytes got 7".to_string())), &[1,2,3,4,5,6,7]),
    case(Err(LayerError::Parse("expected 6 bytes got 5".to_string())), &[1,2,3,4,5]),
    case(Err(LayerError::Parse("expected 6 bytes got 0".to_string())), &[]),
    )]
    fn test_mac_from_slice(expected: Result<MacAddress, LayerError>, input: &[u8]) {
        let res = MacAddress::from_slice(input);
        assert_eq!(expected, res);

        // this is a proxy function to from_slice
        let res: Result<MacAddress, LayerError> = input.try_into();
        assert_eq!(expected, res);
    }

    #[rstest_parametrize(expected, input,
    case(Ok(MacAddress([0,0,0,0,0,0])), "00:00:00:00:00:00"),
    case(Ok(MacAddress([170, 255, 255, 255, 255, 187])), "aa:ff:ff:ff:ff:bb"),
    case(Ok(MacAddress([170, 255, 255, 255, 255, 187])), "AA:FF:FF:FF:FF:BB"),
    case(Err(LayerError::Parse("parsing failure, invalid format".to_string())),""),
    case(Err(LayerError::Parse("parsing failure, invalid format".to_string())),":"),
    case(Err(LayerError::Parse("parsing failure, invalid format".to_string())),"00:00:00:00:00"),
    case(Err(LayerError::Parse("parsing failure, invalid format".to_string())),"00:00:00:00:00:00:00"),
    )]
    fn test_mac_from_str(expected: Result<MacAddress, LayerError>, input: &str) {
        let mac: Result<MacAddress, LayerError> = input.parse();
        assert_eq!(expected, mac);
    }
}
