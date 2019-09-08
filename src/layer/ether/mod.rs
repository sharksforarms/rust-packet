use crate::layer::{Layer, LayerError};

pub mod macaddress;
use macaddress::MacAddress;

#[derive(Debug)]
enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    VlanTaggedFrame = 0x8100,
    ProviderBridging = 0x88A8,
    VlanDoubleTaggedFrame = 0x9100,
}

#[derive(Debug)]
struct Ether {
    src: MacAddress,
    dst: MacAddress,
    ether_type: EtherType,
}

impl Layer for Ether {
    type LayerType = Ether;

    fn from_bytes(bytes: &[u8]) -> Result<Self::LayerType, LayerError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest_parametrize;

    #[rstest_parametrize(expected, input,
//    case(Ether{a: 1}, b"aabb"),
    )]
    fn test_parse_ether(expected: Ether, input: &[u8]) {
        std::dbg!(expected);
        std::dbg!(input);
    }

}
