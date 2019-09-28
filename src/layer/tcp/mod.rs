use crate::layer::{Layer, LayerError};
use nom::bits::bytes;
use nom::bits::streaming::{tag, take as take_bits};
use nom::bytes::streaming::take as take_bytes;
use nom::combinator::verify;
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
    pub options: Vec<TcpOption>,
}

#[derive(Debug, PartialEq)]
pub struct SackPtr {
    pub begin: u32,
    pub end: u32,
}

#[derive(Debug, PartialEq)]
pub enum TcpOption {
    EOL,
    NOP,
    Mss(u16),
    Ws(u8),
    SackPerm,
    Sack(Vec<SackPtr>),
    Timestamp((u32, u32)),
    Unknown(Vec<u8>),
}

fn parse_single_option(rest: (&[u8], usize)) -> IResult<(&[u8], usize), TcpOption> {
    let (rest, kind): (_, u8) = take_bits(8usize)(rest)?;
    match kind {
        0x0 => Ok((rest, TcpOption::EOL)),
        0x1 => Ok((rest, TcpOption::NOP)),
        0x2 => {
            let (rest, _size): (_, usize) = tag(4usize, 8usize)(rest)?;
            let (rest, mss): (_, u16) = take_bits(16usize)(rest)?;

            Ok((rest, TcpOption::Mss(mss)))
        }
        0x3 => {
            let (rest, _size): (_, usize) = tag(3usize, 8usize)(rest)?;
            let (rest, ws): (_, u8) = take_bits(8usize)(rest)?;

            Ok((rest, TcpOption::Ws(ws)))
        }
        0x4 => {
            let (rest, _size): (_, usize) = tag(2usize, 8usize)(rest)?;
            Ok((rest, TcpOption::SackPerm))
        }
        0x5 => {
            let (rest, size): (_, usize) = verify(take_bits(8usize), |v: &usize| {
                (*v == 10) || (*v == 18) || (*v == 26) || (*v == 34)
            })(rest)?;
            let ptr_count: usize = (((size - 2) * 8) / 32) / 2; // TODO figure this out better

            let mut rest = rest;
            let mut sackptrs: Vec<SackPtr> = Vec::with_capacity(ptr_count);
            for _ in 0..ptr_count {
                let (r, begin): (_, u32) = take_bits(32usize)(rest)?;
                let (r, end): (_, u32) = take_bits(32usize)(r)?;
                let sackptr = SackPtr { begin, end };
                sackptrs.push(sackptr);

                rest = r;
            }

            Ok((rest, TcpOption::Sack(sackptrs)))
        }
        0x8 => {
            let (rest, _size): (_, usize) = tag(10usize, 8usize)(rest)?;
            let (rest, timestamp): (_, u32) = take_bits(32usize)(rest)?;
            let (rest, prev_timestamp): (_, u32) = take_bits(32usize)(rest)?;

            Ok((rest, TcpOption::Timestamp((timestamp, prev_timestamp))))
        }
        _ => {
            // TODO maybe error out instead? are non-standard tcp options a thing?
            let (rest, size): (_, usize) = verify(take_bits(8usize), |v: &usize| *v >= 2)(rest)?;
            let size: usize = size - 2; // 1 byte for kind and one byte for length inclusive

            let mut rest = rest;
            let mut data = Vec::with_capacity(size);
            for _ in 1..size {
                let (r, byte): (_, u8) = take_bits(8usize)(rest)?;
                data.push(byte);
                rest = r;
            }

            Ok((rest, TcpOption::Unknown(data)))
        }
    }
}

impl Layer for Tcp {
    type LayerType = Tcp;

    /// Parsers an `Tcp` struct from bytes returning the struct and un-consumed data
    fn from_bytes(input: &[u8]) -> Result<(Self::LayerType, &[u8]), LayerError> {
        fn parse_tcp_header(
            input: &[u8],
        ) -> IResult<(&[u8], usize), (u16, u16, u32, u32, u8, u16, u16, u16, u16, u16)> {
            tuple((
                take_bits(16usize),                                          // sport
                take_bits(16usize),                                          // dport
                take_bits(32usize),                                          // seq
                take_bits(32usize),                                          // ack
                verify(take_bits(4usize), |v: &u8| (*v >= 5) && (*v <= 15)), // offset
                take_bits(6usize),                                           // reserved
                take_bits(6usize),                                           // flags
                take_bits(16usize),                                          // window
                take_bits(16usize),                                          // checksum
                take_bits(16usize),                                          // urgptr
            ))((input, 0usize))
        }

        fn parse_tcp_options(
            rest: (&[u8], usize),
            offset: u8,
        ) -> IResult<(&[u8], usize), Vec<TcpOption>> {
            let options_count: usize = offset as usize - 5;
            let options_size: usize = (options_count * 32) / 8;
            let (rest, option_data) = bytes::<_, _, (_, _), _, _>(take_bytes(options_size))(rest)?;
            let mut option_data = (option_data, 0usize);

            let mut options: Vec<TcpOption> = Vec::with_capacity(offset as usize - 5);
            // TODO: Might be padded with 0s
            while !option_data.0.is_empty() {
                let (option_data2, option) = parse_single_option(option_data)?;
                options.push(option);
                option_data = option_data2;
            }

            Ok((rest, options))
        }

        let (rest, (sport, dport, seq, ack, offset, reserved, flags, window, checksum, urgptr)) =
            parse_tcp_header(input)?;

        let ((rest, _), options) = parse_tcp_options(rest, offset)?;

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
                options: Vec::new(),
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
                options: Vec::new(),
            },
            [0xFF, 0xFF].as_ref(),
        )),
        &hex::decode("0d2c005038affe14114c618c501825bca9580000FFFF").unwrap()
    ),
    // TCP + Options
    case(
        Ok((
            Tcp {
                sport: 49683,
                dport: 80,
                seq: 2263792740,
                ack: 3839277976,
                offset: 11,
                reserved: 0,
                flags: 0x010,
                window: 196,
                checksum: 0x9afc,
                urgptr: 0,
                options: vec![TcpOption::NOP, TcpOption::NOP, TcpOption::Timestamp((3548665977, 1081292766)), TcpOption::NOP, TcpOption::NOP, TcpOption::Sack(vec![SackPtr { begin: 3839279344, end: 3839282080 }])],
            },
            [0xFF, 0xFF].as_ref(),
        )),
        &hex::decode("c213005086eebc64e4d6bb98b01000c49afc00000101080ad3845879407337de0101050ae4d6c0f0e4d6cba0FFFF").unwrap()
    ),
    // TODO: Add more tests with various tcp options

    // panic regression: underflow
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), &hex::decode("7777770000000000000000777777777777f70a0a2f").unwrap()),
    // panic regresion: unknown option kind with invalid size
    case(Err(LayerError::Parse("parsing error has occurred: predicate verification".to_string())), &hex::decode("2500a50a5c2fc3c31a0a0a0a652565255cff0a25ff033b0025").unwrap()),
    // panic regresion: invalid sack ptr option size
    case(Err(LayerError::Parse("parsing error has occurred: predicate verification".to_string())), &hex::decode("2500a50a5c2fc3c31a0a0a0a6525651b5cffc2ff0501000325").unwrap()),
    case(Err(LayerError::Parse("incomplete data, needs more".to_string())), b""),
    )]
    fn test_tcp_from_bytes(expected: Result<(Tcp, &[u8]), LayerError>, input: &[u8]) {
        let tcp = Tcp::from_bytes(input);
        assert_eq!(expected, tcp);
    }

    // TODO: Test parse_single_option as a stand-alone function

    #[test]
    fn test_quickcheck_test_tcp_from_bytes() {
        fn prop(input: Vec<u8>) {
            let _ = Tcp::from_bytes(&input);
        }
        quickcheck::quickcheck(prop as fn(Vec<u8>));
    }
}
