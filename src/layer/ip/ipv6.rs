use crate::layer::{Layer, LayerError};
use std::net::Ipv6Addr;

use super::parser::parse_ipv6_header;

/// IPv6 Header
/// ```text
///    0                   1                   2                   3   
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |Version|   DSCP  | ECN |           Flow Label                  |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |         Payload Length        |  Next Header  |   Hop Limit   |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                                                               |
///    +                                                               +
///    |                                                               |
///    +                         Source Address                        +
///    |                                                               |
///    +                                                               +
///    |                                                               |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                                                               |
///    +                                                               +
///    |                                                               |
///    +                      Destination Address                      +
///    |                                                               |
///    +                                                               +
///    |                                                               |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq)]
pub struct Ipv6 {
    pub version: u8,     // Version
    pub ds: u8,          // Differentiated Services
    pub ecn: u8,         // Explicit Congestion Notification
    pub label: u32,      // Flow Label
    pub length: u16,     // Payload Length
    pub next_header: u8, // Next Header
    pub hop_limit: u8,   // Hop Limit
    pub src: Ipv6Addr,   // Source IP Address
    pub dst: Ipv6Addr,   // Destination IP Address
}

impl Layer for Ipv6 {
    /// Parsers an `Ipv6` struct from bytes returning the struct and un-consumed data
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), LayerError> {
        let ((rest, _), (version, ds, ecn, label, length, next_header, hop_limit, src, dst)) =
            parse_ipv6_header(bytes)?;

        let src: Ipv6Addr = src.into();
        let dst: Ipv6Addr = dst.into();

        Ok((
            Ipv6 {
                version,
                ds,
                ecn,
                label,
                length,
                next_header,
                hop_limit,
                src,
                dst,
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
            Ipv6 {
                version: 6,
                ds: 0,
                ecn: 0,
                label: 0,
                length: 296,
                next_header: 103,
                hop_limit: 64,
                src: "3ffe:8020:0:1:260:97ff:fe07:69ea".parse().unwrap(),
                dst: "3ffe:501:0:1c01:200:f8ff:fe03:d9c0".parse().unwrap(),
            },
            EMPTY
        )),
        &hex::decode("60000000012867403ffe802000000001026097fffe0769ea3ffe050100001c010200f8fffe03d9c0").unwrap()
    ),
    // IP + rest (FFFF)
    case(
        Ok((
            Ipv6 {
                version: 6,
                ds: 0,
                ecn: 0,
                label: 0,
                length: 296,
                next_header: 103,
                hop_limit: 64,
                src: "3ffe:8020:0:1:260:97ff:fe07:69ea".parse().unwrap(),
                dst: "3ffe:501:0:1c01:200:f8ff:fe03:d9c0".parse().unwrap(),
            },
            [0xFF, 0xFF].as_ref(),
        )),
        &hex::decode("60000000012867403ffe802000000001026097fffe0769ea3ffe050100001c010200f8fffe03d9c0FFFF").unwrap()
    ),
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b""),
    )]
    fn test_ipv6_from_bytes(expected: Result<(Ipv6, &[u8]), LayerError>, input: &[u8]) {
        let ipv6 = Ipv6::from_bytes(input);
        assert_eq!(expected, ipv6);
    }

    #[test]
    fn test_quickcheck_test_ipv6_from_bytes() {
        fn prop(input: Vec<u8>) {
            let _ = Ipv6::from_bytes(&input);
        }
        quickcheck::quickcheck(prop as fn(Vec<u8>));
    }
}
