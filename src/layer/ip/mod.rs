use crate::layer::{Layer, LayerError};
use byteorder::{ByteOrder, NetworkEndian};
use nom::bytes::streaming::take;
use nom::combinator::map_res;
use nom::sequence::tuple;
use nom::IResult;
use std::convert::TryInto;
use std::net::Ipv4Addr;

enum Ip {
    V4(Ipv4),
}

/// Ipv4 Header
/// ```text
///     0                   1                   2                   3   
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |Version|  IHL  |    DSCP   | ECN |        Total Length         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |         Identification        |Flags|      Fragment Offset    |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |  Time to Live |    Protocol   |         Header Checksum       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                       Source Address                          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                    Destination Address                        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                    Options                    |    Padding    |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///```
#[derive(Debug, PartialEq)]
pub struct Ipv4 {
    version: u8,         // Version
    ihl: u8,             // Internet Header Length
    dscp: u8,            // Differentiated Services Code Point
    ecn: u8,             // Explicit Congestion Notification
    length: u16,         // Total Length
    identification: u16, // Identification
    flags: u8,           // Flags
    offset: u8,          // Fragment Offset
    ttl: u8,             // Time To Live
    protocol: u8,        // Protocol
    checksum: u16,       // Header checksum
    src: Ipv4Addr,       // Source IP Address
    dst: Ipv4Addr,       // Destination IP Address
    options: Vec<u8>,    // Options
    padding: Vec<u8>,    // padding
}

impl Layer for Ipv4 {
    type LayerType = Ipv4;

    /// Parsers an `Ipv4` struct from bytes returning the struct and un-consumed data
    fn from_bytes(bytes: &[u8]) -> Result<(Self::LayerType, &[u8]), LayerError> {
        // Tuples of (shift, mask)
        // Word 1
        const IPV4_VERSION_MASK: (usize, u32) = (28, 0b1111000000000000_0000000000000000);
        const IPV4_IHL_MASK: (usize, u32) = (24, 0b0000111100000000_0000000000000000);
        const IPV4_DSCP_MASK: (usize, u32) = (18, 0b0000000011111100_0000000000000000);
        const IPV4_ECN_MASK: (usize, u32) = (16, 0b0000000000000011_0000000000000000);
        const IPV4_LENGTH_MASK: (usize, u32) = (0, 0x00FF);

        // Word 2
        const IPV4_IDENTIFICATION_MASK: (usize, u32) = (16, 0xFFFF0000);
        const IPV4_FLAGS_MASK: (usize, u32) = (13, 0b0000000000000000_1110000000000000);
        const IPV4_OFFSET_MASK: (usize, u32) = (0, 0b0000000000000000_0001111111111111);

        // Word 3
        const IPV4_TTL_MASK: (usize, u32) = (24, 0xFF000000);
        const IPV4_PROTOCOL_MASK: (usize, u32) = (16, 0x00FF0000);
        const IPV4_CHECKSUM_MASK: (usize, u32) = (0, 0x0000FFFF);

        // Word 4 and 5
        const IPV4_SRC_MASK: (usize, u32) = (0, 0xFFFFFFFF);
        const IPV4_DST_MASK: (usize, u32) = (0, 0xFFFFFFFF);

        fn take_word(input: &[u8]) -> IResult<&[u8], u32> {
            map_res(take(4u8), |v| -> Result<u32, LayerError> {
                Ok(NetworkEndian::read_u32(v))
            })(input)
        }

        let (extra, word1) = take_word(bytes)?;
        let (extra, word2) = take_word(extra)?;
        let (extra, word3) = take_word(extra)?;
        let (extra, word4) = take_word(extra)?;
        let (extra, word5) = take_word(extra)?;

        macro_rules! get_field {
            ($word:ident, $mask:ident, $as_type:ty) => {
                (($word & $mask.1) >> $mask.0) as $as_type
            };
        }

        let version = get_field!(word1, IPV4_VERSION_MASK, u8);
        let ihl = get_field!(word1, IPV4_IHL_MASK, u8);
        let dscp = get_field!(word1, IPV4_DSCP_MASK, u8);
        let ecn = get_field!(word1, IPV4_ECN_MASK, u8);
        let length = get_field!(word1, IPV4_LENGTH_MASK, u16);
        let identification = get_field!(word2, IPV4_IDENTIFICATION_MASK, u16);
        let flags = get_field!(word2, IPV4_FLAGS_MASK, u8);
        let offset = get_field!(word2, IPV4_OFFSET_MASK, u8);
        let ttl = get_field!(word3, IPV4_TTL_MASK, u8);
        let protocol = get_field!(word3, IPV4_PROTOCOL_MASK, u8);
        let checksum = get_field!(word3, IPV4_CHECKSUM_MASK, u16);
        let src: Ipv4Addr = get_field!(word4, IPV4_SRC_MASK, u32).into();
        let dst: Ipv4Addr = get_field!(word5, IPV4_DST_MASK, u32).into();

        let options = Vec::new(); // TODO
        let padding = Vec::new(); // TODO

        Ok((
            Ipv4 {
                version,
                ihl,
                ecn,
                dscp,
                length,
                identification,
                flags,
                offset,
                ttl,
                protocol,
                checksum,
                src,
                dst,
                options,
                padding,
            },
            extra,
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
    case(
        Ok((
            Ipv4 {
                version: 4,
                ihl: 5,
                ecn: 0,
                dscp: 0,
                length: 80,
                identification: 0x2bc1,
                flags: 2,
                offset: 0,
                ttl: 64,
                protocol: 6,
                checksum: 0x8f37,
                src: Ipv4Addr::new(192,168,1,107),
                dst: Ipv4Addr::new(192,30,253,125),
                options: Vec::new(),
                padding: Vec::new(),
            },
            EMPTY
        )),
        &hex::decode("450000502bc1400040068f37c0a8016bc01efd7d").unwrap()
    ),
    )]
    fn test_ipv4_from_bytes(expected: Result<(Ipv4, &[u8]), LayerError>, input: &[u8]) {
        let ipv4 = Ipv4::from_bytes(input);
        assert_eq!(expected, ipv4);
    }

    #[test]
    fn test_quickcheck_test_ipv4_from_bytes() {
        fn prop(input: Vec<u8>) {
            let _ = Ipv4::from_bytes(&input);
        }
        quickcheck::quickcheck(prop as fn(Vec<u8>));
    }
}
