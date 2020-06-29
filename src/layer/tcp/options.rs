use deku::prelude::*;

#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct SAckData {
    pub begin: u32,
    pub end: u32,
}

#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct TimestampData {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "big")]
pub enum TcpOption {
    #[deku(id = "0x00")]
    EOL,
    #[deku(id = "0x01")]
    NOP,
    #[deku(id = "0x02")]
    MSS { length: u8, value: u16 },
    #[deku(id = "0x03")]
    WScale { length: u8, value: u8 },
    #[deku(id = "0x04")]
    SAckOK { length: u8 },
    #[deku(id = "0x05")]
    SAck {
        // #[deku(update = "(((value.len() * 2) * 4) + 2)")]
        #[deku(update = "{use std::convert::TryFrom; u8::try_from(
            value.len()
            .checked_mul(8)
            .and_then(|v| v.checked_add(2))
            .ok_or_else(|| DekuError::Parse(\"overflow when parsing SAckData length\".to_string()))?
        )?}")]
        length: u8,
        // #[deku(count = "(((length - 2) / 4) / 2)")]
        #[deku(
            count = "length.checked_sub(2).and_then(|v| v.checked_div(8)).ok_or_else(|| DekuError::Parse(\"overflow when parsing SAckData vec\".to_string()))?"
        )]
        value: Vec<SAckData>,
    },
    #[deku(id = "0x08")]
    Timestamp { length: u8, value: TimestampData },
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;
    use std::convert::TryFrom;

    #[rstest(input, expected,
        case(&hex!("00"), TcpOption::EOL),
        case(&hex!("01"), TcpOption::NOP),
        case(&hex!("0201BBAA"), TcpOption::MSS { length: 0x01, value: 0xBBAA }),
        case(&hex!("0301AA"), TcpOption::WScale { length: 0x01, value: 0xAA }),
        case(&hex!("0401"), TcpOption::SAckOK { length: 0x01 }),
        case(&hex!("050ae4d6c0f0e4d6cba0"), TcpOption::SAck {
            length: 10,
            value: vec![SAckData { begin: 3839279344, end: 3839282080 }]
        }),
        case(&hex!("080ad3845879407337de"), TcpOption::Timestamp {
            length: 10,
            value: TimestampData {
                start: 3548665977,
                end: 1081292766
            }
        }),


        // Errors
        #[should_panic(expected = "Parse(\"overflow when parsing SAckData vec\")")]
        case::sack_length_underflow(&hex!("0500e4d6c0f0e4d6cba0"), TcpOption::EOL),
    )]
    fn test_tcp_option(input: &[u8], expected: TcpOption) {
        let option = TcpOption::try_from(input).unwrap();
        assert_eq!(expected, option);
    }

    #[rstest(sack_len,
        case::max(31),

        #[should_panic(expected = "Parse(\"error parsing int: out of range integral type conversion attempted\")")]
        case::overflow(32),
    )]
    fn test_sack_update_overflow(sack_len: usize) {
        let mut sack = TcpOption::SAck {
            length: 0,
            value: vec![SAckData { begin: 0, end: 0 }; sack_len],
        };

        sack.update().unwrap();

        if let TcpOption::SAck { length, value } = sack {
            assert_eq!(value.len() * 8 + 2, length as usize);
        } else {
            unreachable!()
        }
    }
}
