use super::IpProtocol;
use crate::layer::{Layer, LayerError};
use deku::prelude::*;
use std::convert::TryFrom;
use std::net::Ipv6Addr;

/**
IPv6 Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|     DS    |ECN|            Flow Label                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                                 |
+                                                                 +
|                                                                 |
+                         Source Address                          +
|                                                                 |
+                                                                 +
|                                                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                                 |
+                                                                 +
|                                                                 |
+                      Destination Address                        +
|                                                                 |
+                                                                 +
|                                                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Ipv6 {
    #[deku(bits = "4")]
    pub version: u8, // Version
    #[deku(bits = "6")]
    pub ds: u8, // Differentiated Services
    #[deku(bits = "2")]
    pub ecn: u8, // Explicit Congestion Notification
    #[deku(bits = "20")]
    pub label: u32, // Flow Label
    pub length: u16,             // Payload Length
    pub next_header: IpProtocol, // Next Header
    pub hop_limit: u8,           // Hop Limit
    pub src: Ipv6Addr,           // Source IP Address
    pub dst: Ipv6Addr,           // Destination IP Address
}

impl Ipv6 {
    pub fn update_length(&mut self, data: &[Layer]) -> Result<(), LayerError> {
        let mut data_buf = Vec::new();
        for layer in data {
            data_buf.extend(layer.to_bytes()?)
        }

        self.length = u16::try_from(data_buf.len())?;

        Ok(())
    }
}

impl Default for Ipv6 {
    fn default() -> Self {
        Ipv6 {
            version: 0,
            ds: 0,
            ecn: 0,
            label: 0,
            length: 0,
            next_header: IpProtocol::IPV6NONXT,
            hop_limit: 0,
            src: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            dst: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
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
            &hex!("60000000012867403ffe802000000001026097fffe0769ea3ffe050100001c010200f8fffe03d9c0"),
            Ipv6 {
                version: 6,
                ds: 0,
                ecn: 0,
                label: 0,
                length: 296,
                next_header: IpProtocol::PIM,
                hop_limit: 64,
                src: "3ffe:8020:0:1:260:97ff:fe07:69ea".parse().unwrap(),
                dst: "3ffe:501:0:1c01:200:f8ff:fe03:d9c0".parse().unwrap(),
            }
        ),
    )]
    fn test_ipv6(input: &[u8], expected: Ipv6) {
        let ipv6 = Ipv6::try_from(input).unwrap();
        assert_eq!(expected, ipv6);
    }

    #[test]
    fn test_ipv6_default() {
        assert_eq!(
            Ipv6 {
                version: 0,
                ds: 0,
                ecn: 0,
                label: 0,
                length: 0,
                next_header: IpProtocol::IPV6NONXT,
                hop_limit: 0,
                src: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
                dst: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            },
            Ipv6::default(),
        );
    }
}
