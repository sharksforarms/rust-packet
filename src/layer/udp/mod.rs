/*!
UDP layer
*/

use super::{Layer, LayerError};
use crate::layer::{ip::checksum, Ipv4, Ipv6};
use deku::bitvec::{BitVec, Msb0};
use deku::prelude::*;
use std::convert::TryFrom;

/**
UDP Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |            Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Udp {
    pub sport: u16,
    pub dport: u16,
    pub length: u16,
    pub checksum: u16,
}

impl Udp {
    pub fn update_checksum_ipv4(&mut self, ipv4: &Ipv4, data: &[Layer]) -> Result<(), LayerError> {
        let mut data_buf = Vec::new();
        for layer in data {
            data_buf.extend(layer.to_bytes()?)
        }

        let mut udp = self.to_bytes()?;
        // Bytes 6, 7 are the checksum. Clear them for calculation.
        udp[6] = 0x00;
        udp[7] = 0x00;

        let mut buf = Vec::with_capacity(12 + udp.len() + data_buf.len());

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

        let len_sum = (u16::try_from(data_buf.len())?.checked_add(u16::try_from(udp.len())?))
            .ok_or_else(|| LayerError::IntError("overflow occurred".to_string()))?;
        let mut len_sum_res = BitVec::<Msb0, u8>::new();
        len_sum.write(&mut len_sum_res, deku::ctx::Endian::Big)?;
        buf.extend(len_sum_res.into_vec());

        // Write udp header
        buf.extend(udp);

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

        let mut udp = self.to_bytes()?;
        // Bytes 6, 7 are the checksum. Clear them for calculation.
        udp[6] = 0x00;
        udp[7] = 0x00;

        let mut buf = Vec::with_capacity(40 + udp.len() + data_buf.len());

        // Write pseudo header
        let mut ipv6_src = BitVec::<Msb0, u8>::new();
        ipv6.src.write(&mut ipv6_src, deku::ctx::Endian::Big)?;
        buf.extend(ipv6_src.into_vec());

        let mut ipv6_dst = BitVec::<Msb0, u8>::new();
        ipv6.dst.write(&mut ipv6_dst, deku::ctx::Endian::Big)?;
        buf.extend(ipv6_dst.into_vec());

        let len_sum = (u16::try_from(data_buf.len())?.checked_add(u16::try_from(udp.len())?))
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

        // Write udp header
        buf.extend(udp);

        // Write remaining data
        buf.extend(data_buf);

        self.checksum = checksum(&buf)?;

        Ok(())
    }

    pub fn update_length(&mut self, data: &[Layer]) -> Result<(), LayerError> {
        let header = self.to_bytes()?;
        let mut data_buf = Vec::new();
        for layer in data {
            data_buf.extend(layer.to_bytes()?)
        }

        self.length = u16::try_from(header.len() + data_buf.len())?;

        Ok(())
    }
}

impl Default for Udp {
    fn default() -> Self {
        Udp {
            sport: 0,
            dport: 0,
            length: 0,
            checksum: 0,
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
            &hex!("ff02ff35002907a9"),
            Udp {
                sport: 65282,
                dport: 65333,
                length: 41,
                checksum: 0x07a9,
            },
        ),
    )]
    fn test_udp(input: &[u8], expected: Udp) {
        let ret_read = Udp::try_from(input).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = ret_read.to_bytes().unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_udp_default() {
        assert_eq!(
            Udp {
                sport: 0,
                dport: 0,
                length: 0,
                checksum: 0,
            },
            Udp::default()
        )
    }

    #[test]
    fn test_udp_checksum_update_v4() {
        let expected_checksum = 0x07a9;

        let ipv4 =
            Ipv4::try_from(hex!("4500003d0a41000080117cebc0a83232c0a80001").as_ref()).unwrap();

        let mut udp = Udp::try_from(hex!("ff02ff350029 AAAA").as_ref()).unwrap();

        let raw = Raw::try_from(
            hex!("002b0100000100000000000002757304706f6f6c036e7470036f72670000010001").as_ref(),
        )
        .unwrap();

        udp.update_checksum_ipv4(&ipv4, &[Layer::Raw(raw)]).unwrap();

        assert_eq!(expected_checksum, udp.checksum);
    }

    #[test]
    fn test_udp_checksum_update_v6() {
        let expected_checksum = 0x2841;

        let ipv6 = Ipv6::try_from(
            hex!(
                "60000000003f1140200300de20160125fc3683174e86cb72200300de201601ff0000000000000011"
            )
            .as_ref(),
        )
        .unwrap();

        let mut udp = Udp::try_from(hex!("ff5000a1003f AAAA").as_ref()).unwrap();

        let raw = Raw::try_from(hex!("303502010104146e35724144316967333134497166696f59425777a11a020455e8831e020100020100300c300a06062b060102010b0500").as_ref()).unwrap();

        udp.update_checksum_ipv6(&ipv6, &[Layer::Raw(raw)]).unwrap();

        assert_eq!(expected_checksum, udp.checksum);
    }
}
