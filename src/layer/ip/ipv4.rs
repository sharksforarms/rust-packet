use super::checksum;
use super::IpProtocol;
use crate::layer::{Layer, LayerError, LayerValidate, ValidationError};
use deku::bitvec::{BitSlice, Msb0};
use deku::prelude::*;
use std::convert::TryFrom;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(
    type = "u8",
    bits = "2",
    ctx = "endian: deku::ctx::Endian",
    endian = "endian"
)]
pub enum Ipv4OptionClass {
    #[deku(id = "0")]
    Control,
    #[deku(id = "1")]
    Reserved1,
    #[deku(id = "2")]
    Debug,
    #[deku(id = "3")]
    Reserved2,
}

#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(
    type = "u8",
    bits = "5",
    ctx = "endian: deku::ctx::Endian",
    endian = "endian"
)]
pub enum Ipv4OptionType {
    /// End of Option List
    #[deku(id = "0")]
    EOOL,
    /// No Operation
    #[deku(id = "1")]
    NOP,
    /// Unknown
    #[deku(id_pat = "_")]
    Unknown {
        #[deku(bits = "5")]
        type_: u8,
        #[deku(update = "{use std::convert::TryFrom; u8::try_from(
            value.len()
            .checked_add(2)
            .ok_or_else(|| DekuError::Parse(\"overflow when updating ipv4 option length\".to_string()))?
        )?}")]
        length: u8,
        #[deku(
            count = "length.checked_sub(2).ok_or_else(|| DekuError::Parse(\"overflow when parsing ipv4 option\".to_string()))?"
        )]
        value: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct Ipv4Option {
    #[deku(bits = 1)]
    pub copied: u8,
    pub class: Ipv4OptionClass,
    pub option: Ipv4OptionType,
}

/**
Ipv4 Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |    DSCP   |ECN|         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Ipv4 {
    #[deku(bits = "4")]
    pub version: u8, // Version
    #[deku(bits = "4")]
    pub ihl: u8, // Internet Header Length
    #[deku(bits = "6")]
    pub dscp: u8, // Differentiated Services Code Point
    #[deku(bits = "2")]
    pub ecn: u8, // Explicit Congestion Notification
    pub length: u16,         // Total Length
    pub identification: u16, // Identification
    #[deku(bits = "3")]
    pub flags: u8, // Flags
    #[deku(bits = "13")]
    pub offset: u16, // Fragment Offset
    pub ttl: u8,             // Time To Live
    pub protocol: IpProtocol, // Protocol
    #[deku(update = "self.update_checksum()?")]
    pub checksum: u16, // Header checksum
    pub src: Ipv4Addr,       // Source IP Address
    pub dst: Ipv4Addr,       // Destination IP Address
    #[deku(reader = "Ipv4::read_options(*ihl, deku::rest)")]
    pub options: Vec<Ipv4Option>,
}

impl Ipv4 {
    fn update_checksum(&self) -> Result<u16, DekuError> {
        let mut ipv4 = self.to_bytes()?;

        // Bytes 10, 11 are the checksum. Clear them and re-calculate.
        ipv4[10] = 0x00;
        ipv4[11] = 0x00;

        checksum(&ipv4).map_err(|e| DekuError::InvalidParam(e.to_string()))
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

    fn read_options(
        ihl: u8, // number of 32 bit words
        rest: &BitSlice<Msb0, u8>,
    ) -> Result<(&BitSlice<Msb0, u8>, Vec<Ipv4Option>), DekuError> {
        if ihl > 5 {
            // we have options to parse

            // slice off length of options
            let bits = (ihl as usize - 5) * 32;

            // Check split_at precondition
            if bits > rest.len() {
                return Err(DekuError::Parse(
                    "not enough data to read ipv4 options".to_string(),
                ));
            }

            let (mut option_rest, rest) = rest.split_at(bits);

            let mut ipv4_options = Vec::with_capacity(1); // at-least 1
            while !option_rest.is_empty() {
                let (option_rest_new, tcp_option) =
                    Ipv4Option::read(option_rest, deku::ctx::Endian::Big)?;

                ipv4_options.push(tcp_option);

                option_rest = option_rest_new;
            }

            Ok((rest, ipv4_options))
        } else {
            Ok((rest, vec![]))
        }
    }
}

impl LayerValidate for Ipv4 {
    fn validate(&self) -> Result<Vec<ValidationError>, LayerError> {
        let mut ret = Vec::new();

        // verify checksum
        let bytes = self.to_bytes()?;
        if 0x00 != checksum(&bytes)? {
            ret.push(ValidationError::Checksum)
        }

        Ok(ret)
    }
}

impl Default for Ipv4 {
    fn default() -> Self {
        Ipv4 {
            version: 0,
            ihl: 0,
            ecn: 0,
            dscp: 0,
            length: 0,
            identification: 0,
            flags: 0,
            offset: 0,
            ttl: 0,
            protocol: IpProtocol::HOPOPT,
            checksum: 0x1fd,
            src: Ipv4Addr::new(127, 0, 0, 1),
            dst: Ipv4Addr::new(127, 0, 0, 1),
            options: vec![],
        }
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
            &hex!("4500004b0f490000801163a591fea0ed91fd02cb"),
            Ipv4 {
                version: 4,
                ihl: 5,
                ecn: 0,
                dscp: 0,
                length: 75,
                identification: 0x0f49,
                flags: 0,
                offset: 0,
                ttl: 128,
                protocol: IpProtocol::UDP,
                checksum: 0x63a5,
                src: Ipv4Addr::new(145,254,160,237),
                dst: Ipv4Addr::new(145,253,2,203),
                options: vec![],
            },
        ),

        case::with_option(
            &hex!("4f00007c000040004001fd307f0000017f00000186280000000101220001ae0000000000000000000000000000000000000000000000000000000001"),
            Ipv4 {
                version: 4,
                ihl: 15,
                ecn: 0,
                dscp: 0,
                length: 124,
                identification: 0,
                flags: 2,
                offset: 0,
                ttl: 64,
                protocol: IpProtocol::ICMP,
                checksum: 0xfd30,
                src: Ipv4Addr::new(127,0,0,1),
                dst: Ipv4Addr::new(127,0,0,1),
                options: vec![
                    Ipv4Option {
                        copied: 1,
                        class: Ipv4OptionClass::Control,
                        option: Ipv4OptionType::Unknown { type_: 6, length: 40, value: vec![0, 0, 0, 1, 1, 34, 0, 1, 174, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] }
                    }
                ],
            },
        ),
    )]
    fn test_ipv4(input: &[u8], expected: Ipv4) {
        let ret_read = Ipv4::try_from(input).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = ret_read.to_bytes().unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_ipv4_default() {
        assert_eq!(
            Ipv4 {
                version: 0,
                ihl: 0,
                ecn: 0,
                dscp: 0,
                length: 0,
                identification: 0,
                flags: 0,
                offset: 0,
                ttl: 0,
                protocol: IpProtocol::HOPOPT,
                checksum: 0x1fd,
                src: Ipv4Addr::new(127, 0, 0, 1),
                dst: Ipv4Addr::new(127, 0, 0, 1),
                options: vec![],
            },
            Ipv4::default()
        );
    }

    #[test]
    fn test_ipv4_checksum_update() {
        let expected_checksum = 0x9010;

        let mut ipv4 =
            Ipv4::try_from(hex!("450002070f4540008006 AABB 91fea0ed41d0e4df").as_ref()).unwrap();

        // Update the checksum
        ipv4.update().unwrap();

        assert_eq!(expected_checksum, ipv4.checksum);
    }

    #[rstest(input, expected,
        case::valid(&hex!("450002070f4540008006901091fea0ed41d0e4df"), vec![]),
        case::modify_chksum(&hex!("450002070f4540008006FF1091fea0ed41d0e4df"), vec![ValidationError::Checksum]),
        case::modify_version(&hex!("550002070f4540008006901091fea0ed41d0e4df"), vec![ValidationError::Checksum]),
    )]
    fn test_ipv4_checksum_validate(input: &[u8], expected: Vec<ValidationError>) {
        let ipv4 = Ipv4::try_from(input).unwrap();

        // validate
        assert_eq!(expected, ipv4.validate().unwrap());
    }
}
