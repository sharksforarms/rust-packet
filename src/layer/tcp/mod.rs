/*!
TCP layer
*/
use super::{Layer, LayerError};
use crate::layer::{ip::checksum, Ipv4, Ipv6};
use deku::prelude::*;
use std::convert::TryFrom;

mod options;
pub use options::{SAckData, TcpOption, TimestampData};

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(
    endian = "endian",
    ctx = "endian: deku::ctx::Endian",
    ctx_default = "deku::ctx::Endian::Big"
)]
pub struct TcpFlags {
    #[deku(bits = "3")]
    pub reserved: u8,
    #[deku(bits = "1")]
    pub nonce: u8,
    /// Congestion Window Reduced (CWR)
    #[deku(bits = "1")]
    pub crw: u8,
    /// ECN-Echo
    #[deku(bits = "1")]
    pub ecn: u8,
    #[deku(bits = "1")]
    pub urgent: u8,
    #[deku(bits = "1")]
    pub ack: u8,
    #[deku(bits = "1")]
    pub push: u8,
    #[deku(bits = "1")]
    pub reset: u8,
    #[deku(bits = "1")]
    pub syn: u8,
    #[deku(bits = "1")]
    pub fin: u8,
}

impl Default for TcpFlags {
    fn default() -> Self {
        TcpFlags {
            reserved: 0,
            nonce: 0,
            crw: 0,
            ecn: 0,
            urgent: 0,
            ack: 0,
            push: 0,
            reset: 0,
            syn: 0,
            fin: 0,
        }
    }
}

impl std::fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}{}{}",
            if self.syn == 1 { "S" } else { "" },
            if self.push == 1 { "P" } else { "" },
            if self.ack == 1 { "A" } else { "" },
            if self.fin == 1 { "F" } else { "" },
            if self.reset == 1 { "R" } else { "" },
        )
    }
}

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
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgptr: u16,
    #[deku(reader = "Tcp::read_options(*offset, rest)")]
    pub options: Vec<TcpOption>,
}

impl Tcp {
    pub fn update_checksum_ipv4(&mut self, ipv4: &Ipv4, data: &[Layer]) -> Result<(), LayerError> {
        let mut data_buf = Vec::new();
        for layer in data {
            data_buf.extend(layer.to_bytes()?)
        }

        let mut tcp = self.to_bytes()?;
        // Bytes 16, 17 are the checksum. Clear them for calculation.
        tcp[16] = 0x00;
        tcp[17] = 0x00;

        let mut buf = Vec::with_capacity(12 + tcp.len() + data_buf.len());

        // Write pseudo header
        let mut ipv4_src = BitVec::<Msb0, u8>::new();
        ipv4.src.write(&mut ipv4_src, deku::ctx::Endian::Big)?;
        buf.extend(ipv4_src.into_vec());

        let mut ipv4_dst = BitVec::<Msb0, u8>::new();
        ipv4.dst.write(&mut ipv4_dst, deku::ctx::Endian::Big)?;
        buf.extend(ipv4_dst.into_vec());

        buf.push(0);

        let mut ipv4_protocol = BitVec::<Msb0, u8>::new();
        ipv4.protocol
            .write(&mut ipv4_protocol, deku::ctx::Endian::Big)?;
        buf.extend(ipv4_protocol.into_vec());

        let len_sum = (u16::try_from(data_buf.len())?.checked_add(u16::try_from(tcp.len())?))
            .ok_or_else(|| LayerError::IntError("overflow occurred".to_string()))?;
        let mut len_sum_res = BitVec::<Msb0, u8>::new();
        len_sum.write(&mut len_sum_res, deku::ctx::Endian::Big)?;
        buf.extend(len_sum_res.into_vec());

        // Write tcp header
        buf.extend(tcp);

        // Write remaining data
        buf.extend(data_buf);

        self.checksum = checksum(&buf)?;

        Ok(())
    }

    pub fn update_checksum_ipv6(&mut self, ipv6: &Ipv6, data: &[Layer]) -> Result<(), LayerError> {
        let mut data_buf = Vec::new();
        for layer in data {
            data_buf.extend(layer.to_bytes()?)
        }

        let mut tcp = self.to_bytes()?;
        // Bytes 16, 17 are the checksum. Clear them for calculation.
        tcp[16] = 0x00;
        tcp[17] = 0x00;

        let mut buf = Vec::with_capacity(40 + tcp.len() + data_buf.len());

        // Write pseudo header
        let mut ipv6_src = BitVec::<Msb0, u8>::new();
        ipv6.src.write(&mut ipv6_src, deku::ctx::Endian::Big)?;
        buf.extend(ipv6_src.into_vec());

        let mut ipv6_dst = BitVec::<Msb0, u8>::new();
        ipv6.dst.write(&mut ipv6_dst, deku::ctx::Endian::Big)?;
        buf.extend(ipv6_dst.into_vec());

        let len_sum = (u16::try_from(data_buf.len())?.checked_add(u16::try_from(tcp.len())?))
            .ok_or_else(|| LayerError::IntError("overflow occurred".to_string()))?;
        let mut len_sum_res = BitVec::<Msb0, u8>::new();
        len_sum.write(&mut len_sum_res, deku::ctx::Endian::Big)?;
        buf.extend(len_sum_res.into_vec());

        buf.push(0);
        buf.push(0);
        buf.push(0);

        let mut ipv6_next_header = BitVec::<Msb0, u8>::new();
        ipv6.next_header
            .write(&mut ipv6_next_header, deku::ctx::Endian::Big)?;
        buf.extend(ipv6_next_header.into_vec());

        // Write tcp header
        buf.extend(tcp);

        // Write remaining data
        buf.extend(data_buf);

        self.checksum = checksum(&buf)?;

        Ok(())
    }

    fn read_options(
        offset: u8, // tcp offset header field
        rest: &BitSlice<Msb0, u8>,
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

        // Check split_at precondition
        if bits > rest.len() {
            return Err(DekuError::Parse(
                "not enough data to read tcp options".to_string(),
            ));
        }

        let (mut option_rest, rest) = rest.split_at(bits);

        let mut tcp_options = Vec::with_capacity(1); // at-least 1
        while !option_rest.is_empty() {
            let (option_rest_new, tcp_option) =
                TcpOption::read(option_rest, deku::ctx::Endian::Big)?;

            tcp_options.push(tcp_option);

            option_rest = option_rest_new;
        }

        Ok((rest, tcp_options))
    }
}

impl Default for Tcp {
    fn default() -> Self {
        Tcp {
            sport: 0,
            dport: 0,
            seq: 0,
            ack: 0,
            offset: 0,
            flags: TcpFlags::default(),
            window: 0,
            checksum: 0,
            urgptr: 0,
            options: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::Raw;
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
                flags: TcpFlags { ack: 1, push: 1, ..TcpFlags::default()},
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
                flags: TcpFlags { ack: 1, ..TcpFlags::default()},
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
        #[should_panic(expected = "Parse(\"not enough data to read tcp options\")")]
        case(
            &hex!("ffffffffffffffffffffffffffffffffffffffff"),
            Tcp::default(),
        )
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
                flags: TcpFlags::default(),
                window: 0,
                checksum: 0,
                urgptr: 0,
                options: Vec::new(),
            },
            Tcp::default()
        )
    }

    #[test]
    fn test_tcp_checksum_update_v4() {
        let expected_checksum = 0xa958;

        let ipv4 =
            Ipv4::try_from(hex!("450002070f4540008006901091fea0ed41d0e4df").as_ref()).unwrap();

        let mut tcp =
            Tcp::try_from(hex!("0d2c005038affe14114c618c501825bc AAAA 0000").as_ref()).unwrap();

        let raw = Raw::try_from(hex!("474554202f646f776e6c6f61642e68746d6c20485454502f312e310d0a486f73743a207777772e657468657265616c2e636f6d0d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f77733b20553b2057696e646f7773204e5420352e313b20656e2d55533b2072763a312e3629204765636b6f2f32303034303131330d0a4163636570743a20746578742f786d6c2c6170706c69636174696f6e2f786d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c746578742f68746d6c3b713d302e392c746578742f706c61696e3b713d302e382c696d6167652f706e672c696d6167652f6a7065672c696d6167652f6769663b713d302e322c2a2f2a3b713d302e310d0a4163636570742d4c616e67756167653a20656e2d75732c656e3b713d302e350d0a4163636570742d456e636f64696e673a20677a69702c6465666c6174650d0a4163636570742d436861727365743a2049534f2d383835392d312c7574662d383b713d302e372c2a3b713d302e370d0a4b6565702d416c6976653a203330300d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a526566657265723a20687474703a2f2f7777772e657468657265616c2e636f6d2f646576656c6f706d656e742e68746d6c0d0a0d0a").as_ref()).unwrap();

        tcp.update_checksum_ipv4(&ipv4, &[Layer::Raw(raw)]).unwrap();

        assert_eq!(expected_checksum, tcp.checksum);
    }

    #[test]
    fn test_tcp_checksum_update_v6() {
        let expected_checksum = 0x0e91;

        let ipv6 = Ipv6::try_from(
            hex!(
                "6000000000240680200251834383000000000000518343832001063809020001020102fffee27596"
            )
            .as_ref(),
        )
        .unwrap();

        let mut tcp =
            Tcp::try_from(hex!("04020015626bf2f8e537a573501842640e910000").as_ref()).unwrap();

        let raw = Raw::try_from(hex!("5553455220616e6f6e796d6f75730d0a").as_ref()).unwrap();

        tcp.update_checksum_ipv6(&ipv6, &[Layer::Raw(raw)]).unwrap();

        assert_eq!(expected_checksum, tcp.checksum);
    }
}
