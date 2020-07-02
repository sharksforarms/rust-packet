/*!
Ethernet layer
*/

mod ethertype;
mod macaddress;

use deku::prelude::*;

pub use ethertype::EtherType;
pub use macaddress::MacAddress;

/**
Ethernet Frame Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                         Source Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           EtherType           |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                             Payload                           +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, Default, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Ether {
    pub dst: MacAddress,
    pub src: MacAddress,
    pub ether_type: EtherType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rstest::*;
    use std::convert::TryFrom;

    #[rstest(input, expected,
        case(&hex!("feff200001000000010000000800"), Ether {
            dst: MacAddress([0xfe, 0xff, 0x20, 0x00, 0x01, 0x00]),
            src: MacAddress([0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
            ether_type: EtherType::IPv4,
        }),
    )]
    fn test_ether(input: &[u8], expected: Ether) {
        let ret_read = Ether::try_from(input).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = ret_read.to_bytes().unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_ether_default() {
        assert_eq!(
            Ether {
                dst: MacAddress([0x00u8; 6]),
                src: MacAddress([0x00u8; 6]),
                ether_type: EtherType::IPv4,
            },
            Ether::default()
        )
    }
}
