use crate::layer::{Layer, LayerError};

mod parser;
use parser::{parse_tcp_header, parse_tcp_options, TcpOption};

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
    pub reserved: u8,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgptr: u16,
    pub options: Vec<TcpOption>,
}

impl Layer for Tcp {
    /// Parsers an `Tcp` struct from bytes returning the struct and un-consumed data
    fn from_bytes(input: &[u8]) -> Result<(Self, &[u8]), LayerError> {
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
    use super::parser::SackPtr;
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

    #[test]
    fn test_quickcheck_test_tcp_from_bytes() {
        fn prop(input: Vec<u8>) {
            let _ = Tcp::from_bytes(&input);
        }
        quickcheck::quickcheck(prop as fn(Vec<u8>));
    }
}
