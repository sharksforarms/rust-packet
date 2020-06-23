use deku::prelude::*;

mod options;
pub use options::{SAckData, TcpOption, TimestampData};

/**
TCP Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Tcp {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    #[deku(bits = "4")]
    pub offset: u8, // size of tcp header in 32-bit words
    #[deku(bits = "12")]
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgptr: u16,
    #[deku(reader = "Tcp::read_options(offset, rest, input_is_le)")]
    pub options: Vec<TcpOption>,
}

impl Default for Tcp {
    fn default() -> Self {
        Tcp {
            sport: 0,
            dport: 0,
            seq: 0,
            ack: 0,
            offset: 0,
            flags: 0,
            window: 0,
            checksum: 0,
            urgptr: 0,
            options: Vec::new(),
        }
    }
}

impl Tcp {
    fn read_options(
        offset: u8, // tcp offset header field
        rest: &BitSlice<Msb0, u8>,
        input_is_le: bool,
    ) -> Result<(&BitSlice<Msb0, u8>, Vec<TcpOption>), DekuError> {
        let length = offset
            .checked_sub(5)
            .and_then(|v| v.checked_mul(4))
            .ok_or_else(|| DekuError::Parse("error: invalid tcp offset".to_string()))?;

        if length == 0 {
            return Ok((rest, Vec::new()));
        }

        // slice off length from rest
        let bits: usize = length as usize * 8;
        let (mut option_rest, rest) = rest.split_at(bits);

        let mut tcp_options = Vec::with_capacity(1); // at-least 1
        while !option_rest.is_empty() {
            let (option_rest_new, tcp_option) =
                TcpOption::read(option_rest, input_is_le, None, None)?;

            tcp_options.push(tcp_option);

            option_rest = option_rest_new;
        }

        Ok((rest, tcp_options))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rstest::*;
    use std::convert::TryFrom;

    #[rstest(input, expected,
        case(
            &hex!("0d2c005038affe14114c618c501825bca9580000"),
            Tcp {
                sport: 3372,
                dport: 80,
                seq: 951057940,
                ack: 290218380,
                offset: 5,
                flags: 0x018,
                window: 9660,
                checksum: 0xa958,
                urgptr: 0,
                options: Vec::new(),
            },
        ),
        case(
            &hex!("c213005086eebc64e4d6bb98b01000c49afc00000101080ad3845879407337de0101050ae4d6c0f0e4d6cba0"),
            Tcp {
                sport: 49683,
                dport: 80,
                seq: 2263792740,
                ack: 3839277976,
                offset: 11,
                flags: 0x010,
                window: 196,
                checksum: 0x9afc,
                urgptr: 0,
                options: vec![
                    TcpOption::NOP, TcpOption::NOP,
                    TcpOption::Timestamp {
                        length: 10,
                        value: TimestampData {
                            start: 3548665977,
                            end: 1081292766
                        }
                    },
                    TcpOption::NOP, TcpOption::NOP,
                    TcpOption::SAck {
                        length: 10,
                        value: vec![SAckData { begin: 3839279344, end: 3839282080 }]
                    },
                ]
            },
        ),
        #[should_panic(expected = "error: invalid tcp offset")]
        case(
            &hex!("0d2c005038affe14114c618c101825bca9580000"),
            Tcp::default(),
        ),
    )]
    fn test_tcp(input: &[u8], expected: Tcp) {
        let ret_read = Tcp::try_from(input).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = ret_read.to_bytes().unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_tcp_default() {
        assert_eq!(
            Tcp {
                sport: 0,
                dport: 0,
                seq: 0,
                ack: 0,
                offset: 0,
                flags: 0,
                window: 0,
                checksum: 0,
                urgptr: 0,
                options: Vec::new(),
            },
            Tcp::default()
        )
    }
}
