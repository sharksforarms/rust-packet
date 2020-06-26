use super::checksum;
use super::IpProtocol;
use crate::layer::{LayerError, LayerValidate, ValidationError};
use deku::prelude::*;
use std::net::Ipv4Addr;

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
    #[deku(update = "self.calculate_checksum()?")]
    pub checksum: u16, // Header checksum
    pub src: Ipv4Addr,       // Source IP Address
    pub dst: Ipv4Addr,       // Destination IP Address
                             // options: [u8; ?],    // Options // TODO
                             // padding: [u8; ?],    // padding // TODO
}

impl Ipv4 {
    fn calculate_checksum(&self) -> Result<u16, DekuError> {
        let mut bytes = self.to_bytes()?;

        // Bytes 10, 11 are the checksum. Clear them and re-calculate.
        bytes[10] = 0x00;
        bytes[11] = 0x00;

        checksum(&bytes).map_err(|e| DekuError::InvalidParam(e.to_string()))
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
            },
            Ipv4::default()
        );
    }

    #[test]
    fn test_ipv4_checksum_update() {
        let expected_checksum = 0x9010;

        let mut ipv4 =
            Ipv4::try_from(hex!("450002070f4540008006901091fea0ed41d0e4df").as_ref()).unwrap();

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
