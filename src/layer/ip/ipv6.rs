use crate::layer::{Layer, LayerError};
use nom::bits::streaming::take as take_bits;
use nom::IResult;
use std::net::Ipv6Addr;

/// IPv6 Header
/// ```text
///    0                   1                   2                   3   
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |Version| Traffic Class |           Flow Label                  |
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
    type LayerType = Ipv6;

    /// Parsers an `Ipv6` struct from bytes returning the struct and un-consumed data
    fn from_bytes(bytes: &[u8]) -> Result<(Self::LayerType, &[u8]), LayerError> {
        fn parse_ip_header(
            input: &[u8],
        ) -> IResult<(&[u8], usize), (u8, u8, u8, u32, u16, u8, u8, u128, u128)> {
            let (rest, version): (_, u8) = take_bits(4usize)((input, 0usize))?;
            let (rest, ds): (_, u8) = take_bits(6usize)(rest)?;
            let (rest, ecn): (_, u8) = take_bits(2usize)(rest)?;
            let (rest, label): (_, u32) = take_bits(20usize)(rest)?;
            let (rest, length): (_, u16) = take_bits(16usize)(rest)?;
            let (rest, next_header): (_, u8) = take_bits(8usize)(rest)?;
            let (rest, hop_limit): (_, u8) = take_bits(8usize)(rest)?;
            let (rest, src): (_, u128) = take_bits(128usize)(rest)?;
            let (rest, dst): (_, u128) = take_bits(128usize)(rest)?;

            Ok((
                rest,
                (
                    version,
                    ds,
                    ecn,
                    label,
                    length,
                    next_header,
                    hop_limit,
                    src,
                    dst,
                ),
            ))
        }

        let ((rest, _), (version, ds, ecn, label, length, next_header, hop_limit, src, dst)) =
            parse_ip_header(bytes)?;

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
