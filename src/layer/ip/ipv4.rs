use crate::layer::{Layer, LayerError};
use nom::bits::streaming::take as take_bits;
use nom::IResult;
use std::net::Ipv4Addr;

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
    pub version: u8,         // Version
    pub ihl: u8,             // Internet Header Length
    pub dscp: u8,            // Differentiated Services Code Point
    pub ecn: u8,             // Explicit Congestion Notification
    pub length: u16,         // Total Length
    pub identification: u16, // Identification
    pub flags: u8,           // Flags
    pub offset: u16,         // Fragment Offset
    pub ttl: u8,             // Time To Live
    pub protocol: u8,        // Protocol
    pub checksum: u16,       // Header checksum
    pub src: Ipv4Addr,       // Source IP Address
    pub dst: Ipv4Addr,       // Destination IP Address
                             // options: Vec<u8>,    // Options // TODO
                             // padding: Vec<u8>,    // padding // TODO
}

impl Layer for Ipv4 {
    type LayerType = Ipv4;

    /// Parsers an `Ipv4` struct from bytes returning the struct and un-consumed data
    fn from_bytes(bytes: &[u8]) -> Result<(Self::LayerType, &[u8]), LayerError> {
        // Tuples of (shift, mask)

        fn parse_ip_header(
            input: &[u8],
        ) -> IResult<(&[u8], usize), (u8, u8, u8, u8, u16, u16, u8, u16, u8, u8, u16, u32, u32)>
        {
            let (rest, version): (_, u8) = take_bits(4usize)((input, 0usize))?;
            let (rest, ihl): (_, u8) = take_bits(4usize)(rest)?;
            let (rest, dscp): (_, u8) = take_bits(6usize)(rest)?;
            let (rest, ecn): (_, u8) = take_bits(2usize)(rest)?;
            let (rest, length): (_, u16) = take_bits(16usize)(rest)?;
            let (rest, identification): (_, u16) = take_bits(16usize)(rest)?;
            let (rest, flags): (_, u8) = take_bits(3usize)(rest)?;
            let (rest, offset): (_, u16) = take_bits(13usize)(rest)?;
            let (rest, ttl): (_, u8) = take_bits(8usize)(rest)?;
            let (rest, protocol): (_, u8) = take_bits(8usize)(rest)?;
            let (rest, checksum): (_, u16) = take_bits(16usize)(rest)?;
            let (rest, src): (_, u32) = take_bits(32usize)(rest)?;
            let (rest, dst): (_, u32) = take_bits(32usize)(rest)?;

            Ok((
                rest,
                (
                    version,
                    ihl,
                    dscp,
                    ecn,
                    length,
                    identification,
                    flags,
                    offset,
                    ttl,
                    protocol,
                    checksum,
                    src,
                    dst,
                ),
            ))
        }

        let (
            (rest, _),
            (
                version,
                ihl,
                dscp,
                ecn,
                length,
                identification,
                flags,
                offset,
                ttl,
                protocol,
                checksum,
                src,
                dst,
            ),
        ) = parse_ip_header(bytes)?;

        let src: Ipv4Addr = src.into();
        let dst: Ipv4Addr = dst.into();
        // let options = Vec::new(); // TODO
        // let padding = Vec::new(); // TODO

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
            },
            EMPTY
        )),
        &hex::decode("450000502bc1400040068f37c0a8016bc01efd7d").unwrap()
    ),
    // IP + rest (FFFF)
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
            },
            [0xFF, 0xFF].as_ref(),
        )),
        &hex::decode("450000502bc1400040068f37c0a8016bc01efd7dFFFF").unwrap()
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
