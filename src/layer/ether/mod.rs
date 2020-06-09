use crate::layer::Layer;

mod macaddress;
pub use macaddress::MacAddress;
mod ethertype;
use deku::prelude::*;
pub use ethertype::EtherType;

/**
Ethernet type
*/
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Ether {
    pub dst: MacAddress,
    pub src: MacAddress,
    pub ether_type: EtherType,
}

impl Layer for Ether {}
