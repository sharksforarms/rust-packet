use crate::layer::{Layer, LayerError};
use nom::bits::streaming::take as take_bits;
use nom::sequence::tuple;
use nom::IResult;

/// TCP Header
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |          Source Port          |       Destination Port        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        Sequence Number                        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Acknowledgment Number                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |  Data |           |U|A|P|R|S|F|                               |
///   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
///   |       |           |G|K|H|T|N|N|                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |           Checksum            |         Urgent Pointer        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Options                    |    Padding    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                             data                              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq)]
pub struct Tcp {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub offset: u8,
    pub reserved: u16,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgptr: u16,
    pub options: u32,
    pub padding: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
struct SackPtr {
    begin: u32,
    end: u32,
}

#[derive(Debug, PartialEq)]
enum TcpOption {
    EOL,
    NOP,
    Mss(u16),
    Ws(u8),
    SackPerm,
    Sack(Vec<SackPtr>),
    Timestamp((u32, u32)),
}

impl Layer for Tcp {
    type LayerType = Tcp;

    /// Parsers an `Tcp` struct from bytes returning the struct and un-consumed data
    fn from_bytes(bytes: &[u8]) -> Result<(Self::LayerType, &[u8]), LayerError> {
        fn parse_tcp_header(
            input: &[u8],
        ) -> IResult<(&[u8], usize), (u16, u16, u32, u32, u8, u16, u16, u16, u16, u16)> {
            tuple((
                take_bits(16usize), // sport
                take_bits(16usize), // dport
                take_bits(32usize), // seq
                take_bits(32usize), // ack
                take_bits(4usize),  // offset
                take_bits(6usize),  // reserved
                take_bits(6usize),  // flags
                take_bits(16usize), // window
                take_bits(16usize), // checksum
                take_bits(16usize), // urgptr
            ))((input, 0usize))
        }

        fn parse_tcp_options(
            rest: (&[u8], usize),
            offset: u8,
        ) -> IResult<(&[u8], usize), Vec<TcpOption>> {
            fn parse_single_option(rest: (&[u8], usize)) -> IResult<(&[u8], usize), TcpOption> {
                let (rest, kind): (_, u8) = take_bits(8usize)(rest)?;
                match kind {
                    0x0 => Ok((rest, TcpOption::EOL)),
                    0x1 => Ok((rest, TcpOption::NOP)),
                    0x2 => {
                        let (rest, _length): (_, usize) = take_bits(8usize)(rest)?;
                        //let size: usize = length - 2; // 1 byte for kind and one byte for length inclusive
                        let (rest, mss): (_, u16) = take_bits(16usize)(rest)?;

                        Ok((rest, TcpOption::Mss(mss)))
                    }
                    0x3 => {
                        let (rest, _length): (_, usize) = take_bits(8usize)(rest)?;
                        //let size: usize = length - 2; // 1 byte for kind and one byte for length inclusive
                        let (rest, ws): (_, u8) = take_bits(8usize)(rest)?;

                        Ok((rest, TcpOption::Ws(ws)))
                    }
                    0x4 => {
                        let (rest, _length): (_, usize) = take_bits(8usize)(rest)?;
                        Ok((rest, TcpOption::SackPerm))
                    }
                    0x5 => {
                        let (rest, length): (_, usize) = take_bits(8usize)(rest)?;
                        let count: usize = (((length - 2) * 8) / 32) / 2; // TODO figure this out better

                        let mut rest = rest;
                        let mut sackptrs: Vec<SackPtr> = Vec::with_capacity(count);
                        for _ in 0..count {
                            let (r, begin): (_, u32) = take_bits(32usize)(rest)?;
                            let (r, end): (_, u32) = take_bits(32usize)(r)?;
                            let sackptr = SackPtr { begin, end };
                            sackptrs.push(sackptr);

                            rest = r;
                        }

                        Ok((rest, TcpOption::Sack(sackptrs)))
                    }
                    0x8 => {
                        let (rest, _length): (_, usize) = take_bits(8usize)(rest)?;
                        // let size: usize = length - 2; // 1 byte for kind and one byte for length inclusive
                        let (rest, timestamp): (_, u32) = take_bits(32usize)(rest)?;
                        let (rest, prev_timestamp): (_, u32) = take_bits(32usize)(rest)?;

                        Ok((rest, TcpOption::Timestamp((timestamp, prev_timestamp))))
                    }
                    _ => {
                        println!("Unknown: {:x?}", kind);
                        unimplemented!() // TODO
                    }
                }
            }

            let options_size: usize = ((offset as usize - 5) * 32) / 8;
            let mut rest = (rest.0[..options_size].as_ref(), rest.1);

            let mut options: Vec<TcpOption> = Vec::with_capacity(offset as usize - 5);
            while let Ok((rest2, option)) = parse_single_option(rest) {
                options.push(option);
                rest = rest2;
            }

            return Ok((rest, options));
        }

        let (rest, (sport, dport, seq, ack, offset, reserved, flags, window, checksum, urgptr)) =
            parse_tcp_header(bytes)?;

        dbg!(offset);
        let ((rest, _), options) = parse_tcp_options(rest, offset)?;
        dbg!(options);

        let options: u32 = 0;
        let padding: u8 = 0;
        let data: Vec<u8> = Vec::new();

        Ok((
            Tcp {
                sport,
                dport,
                seq,
                ack,
                offset,
                reserved,
                flags,
                window,
                checksum,
                urgptr,
                options,
                padding,
                data,
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
            Tcp {
                sport: 3372,
                dport: 80,
                seq: 951057940,
                ack: 290218380,
                offset: 5,
                reserved: 0,
                flags: 0x018,
                window: 9660,
                checksum: 0xa958,
                urgptr: 0,
                options: 0,
                padding: 0,
                data: Vec::new(),
            },
            EMPTY
        )),
        &hex::decode("0d2c005038affe14114c618c501825bca9580000").unwrap()
    ),
    // TCP + rest (FFFF)
    case(
        Ok((
            Tcp {
                sport: 3372,
                dport: 80,
                seq: 951057940,
                ack: 290218380,
                offset: 5,
                reserved: 0,
                flags: 0x018,
                window: 9660,
                checksum: 0xa958,
                urgptr: 0,
                options: 0,
                padding: 0,
                data: Vec::new(),
            },
            [0xFF, 0xFF].as_ref(),
        )),
        &hex::decode("0d2c005038affe14114c618c501825bca9580000FFFF").unwrap()
    ),
    // TCP + Options
    case(
        Ok((
            Tcp {
                sport: 3372,
                dport: 80,
                seq: 951057940,
                ack: 290218380,
                offset: 5,
                reserved: 0,
                flags: 0x018,
                window: 9660,
                checksum: 0xa958,
                urgptr: 0,
                options: 0,
                padding: 0,
                data: Vec::new(),
            },
            [0xFF, 0xFF].as_ref(),
        )),
        //&hex::decode("c213005086eebbdf00000000a00216d0fd060000020405b40402080ad38457420000000001030307").unwrap()
        &hex::decode("c213005086eebc64e4d6bb98b01000c49afc00000101080ad3845879407337de0101050ae4d6c0f0e4d6cba0").unwrap()
   ),
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b""),
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b"aa"),
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b"aaaaaaa"),
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b"aaaaaaaaaaaa"),
    )]
    fn test_tcp_from_bytes(expected: Result<(Tcp, &[u8]), LayerError>, input: &[u8]) {
        let tcp = Tcp::from_bytes(input);
        assert_eq!(expected, tcp);
    }

    #[test]
    fn test_quickcheck_test_tcp_from_bytes() {
        fn prop(input: Vec<u8>) {
            let _ = Tcp::from_bytes(&input);
        }
        quickcheck::quickcheck(prop as fn(Vec<u8>));
    }
}
