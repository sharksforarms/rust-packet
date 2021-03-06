/*!
Module containing the `Packet` type

A Packet is a collection of layers
*/

pub mod error;
pub use error::PacketError;

use crate::layer::{Layer, LayerType};

const MAX_LAYERS: usize = 10;

/// Container for network layers
#[derive(Debug)]
pub struct Packet {
    layers: Vec<Layer>,
}

impl Packet {
    pub fn new(layers: Vec<Layer>) -> Self {
        Packet { layers }
    }

    /// Read a packet from bytes
    /// This will read layers in accordance to the protocol
    pub fn from_bytes(input: &[u8]) -> Result<Packet, PacketError> {
        let layers = Layer::from_bytes_multi_layer(input, MAX_LAYERS)?;
        Ok(Packet::new(layers))
    }

    /// Write packet to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut acc = Vec::new();
        for layer in &self.layers {
            acc.extend(layer.to_bytes()?);
        }

        Ok(acc)
    }

    /// Update the packet
    /// This is used to re-compute dynamic data such as checksums and lengths
    pub fn update(&mut self) -> Result<(), PacketError> {
        /* TODO:
            I feel like this routine can be optimized.
            The main quirk is that some layers depend on others,
            such as lengths and checksums
        */

        for i in 0..self.layers.len() {
            let layers = &mut self.layers.as_mut_slice()[i..];

            let layers_copy = layers.to_vec();

            match layers {
                [] => {}
                [layer] => {
                    match layer {
                        Layer::Ipv4(ipv4) => ipv4.update_length(&[])?,
                        Layer::Ipv6(ipv6) => ipv6.update_length(&[])?,
                        Layer::Udp(udp) => udp.update_length(&[])?,
                        _ => {}
                    }

                    layer.update()?;
                }
                [layer, next_layer, ..] => {
                    // Update current layers which depend on next-layers
                    match layer {
                        Layer::Ipv4(ipv4) => ipv4.update_length(&layers_copy[1..])?,
                        Layer::Ipv6(ipv6) => ipv6.update_length(&layers_copy[1..])?,
                        _ => {}
                    }

                    // Update next-layers which depend on current layer
                    match next_layer {
                        Layer::Tcp(tcp) => match layer {
                            Layer::Ipv4(ipv4) => {
                                tcp.update_checksum_ipv4(ipv4, &layers_copy[2..])?
                            }
                            Layer::Ipv6(ipv6) => {
                                tcp.update_checksum_ipv6(ipv6, &layers_copy[2..])?
                            }
                            _ => {}
                        },
                        Layer::Udp(udp) => {
                            udp.update_length(&layers_copy[2..])?;

                            match layer {
                                Layer::Ipv4(ipv4) => {
                                    udp.update_checksum_ipv4(ipv4, &layers_copy[2..])?
                                }
                                Layer::Ipv6(ipv6) => {
                                    udp.update_checksum_ipv6(ipv6, &layers_copy[2..])?
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }

                    // Update current layer
                    layer.update()?;
                }
            }
        }

        Ok(())
    }
}

macro_rules! impl_layer_packet_funcs {
    ($layer:ident, $func:ident, $func_mut:ident) => {
        /// Returns the first layer as a reference
        pub fn $func(&self) -> Option<&crate::layer::$layer> {
            let layer = self
                .layers
                .iter()
                .find(|v| v.layer_type() == LayerType::$layer);

            if let Some(Layer::$layer(layer)) = layer {
                Some(layer)
            } else {
                None
            }
        }

        /// Returns the first layer as a mutable reference
        pub fn $func_mut(&mut self) -> Option<&mut crate::layer::$layer> {
            let layer = self
                .layers
                .iter_mut()
                .find(|v| v.layer_type() == LayerType::$layer);

            if let Some(Layer::$layer(layer)) = layer {
                Some(layer)
            } else {
                None
            }
        }
    };
}

// # LAYER: Function to access layer from packet
impl Packet {
    impl_layer_packet_funcs!(Raw, raw, raw_mut);
    impl_layer_packet_funcs!(Ether, ether, ether_mut);
    impl_layer_packet_funcs!(Ipv4, ipv4, ipv4_mut);
    impl_layer_packet_funcs!(Ipv6, ipv6, ipv6_mut);
    impl_layer_packet_funcs!(Tcp, tcp, tcp_mut);
    impl_layer_packet_funcs!(Udp, udp, udp_mut);
}

impl std::ops::Index<LayerType> for Packet {
    type Output = Layer;

    fn index(&self, layer_type: LayerType) -> &Self::Output {
        self.layers
            .iter()
            .find(|v| v.layer_type() == layer_type)
            .unwrap_or_else(|| panic!("could not find layer: {:?}", layer_type))
    }
}

impl std::ops::IndexMut<LayerType> for Packet {
    fn index_mut(&mut self, layer_type: LayerType) -> &mut Self::Output {
        self.layers
            .iter_mut()
            .find(|v| v.layer_type() == layer_type)
            .unwrap_or_else(|| panic!("could not find layer: {:?}", layer_type))
    }
}

/**
Create a [Packet](packet/struct.Packet.html)

Returns `Result<Packet, PacketError>`

Example:

```rust
# use rust_packet::prelude::*;
let pkt: Packet = pkt! {
    ether! {
        dst: "de:ad:be:ef:c0:fe".parse()?
    }?,
    ipv4! {
        src: "127.0.0.1".parse()?,
        dst: "127.0.0.2".parse()?,
    }?,
    udp! {
        dport: 1337
    }?,
    raw! {
        data: b"hello world!".to_vec()
    }?,
}.unwrap();
```
*/
#[macro_export]
macro_rules! pkt {
    ($($layers:expr),+ $(,)?) => ({
        || -> Result<_, PacketError> {
            let mut pkt = Packet::new(vec![$($layers),*]);
            pkt.update()?;
            Ok(pkt)
        }()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    use crate::layer::ether::{Ether, EtherType, MacAddress};
    use crate::layer::ip::{IpProtocol, Ipv4};
    use crate::layer::tcp::{Tcp, TcpFlags};
    use crate::layer::Raw;

    #[test]
    fn test_packet_read_multi_layer() {
        // Ether / IP / TCP / "hello world"
        let test_data = hex!("ffffffffffff0000000000000800450000330001000040067cc27f0000017f00000100140050000000000000000050022000ffa2000068656c6c6f20776f726c64");

        let pkt = Packet::from_bytes(test_data.as_ref()).unwrap();
        assert_eq!(4, pkt.layers.len());

        assert_eq!(
            Layer::Ether(Ether {
                dst: MacAddress([255, 255, 255, 255, 255, 255]),
                src: MacAddress([0, 0, 0, 0, 0, 0]),
                ether_type: EtherType::IPv4
            }),
            pkt.layers[0]
        );

        assert_eq!(
            Layer::Ipv4(Ipv4 {
                version: 4,
                ihl: 5,
                dscp: 0,
                ecn: 0,
                length: 51,
                identification: 1,
                flags: 0,
                offset: 0,
                ttl: 64,
                protocol: IpProtocol::TCP,
                checksum: 31938,
                src: "127.0.0.1".parse().unwrap(),
                dst: "127.0.0.1".parse().unwrap(),
                options: vec![],
            }),
            pkt.layers[1]
        );

        assert_eq!(
            Layer::Tcp(Tcp {
                sport: 20,
                dport: 80,
                seq: 0,
                ack: 0,
                offset: 5,
                flags: TcpFlags {
                    syn: 1,
                    ..TcpFlags::default()
                },
                window: 8192,
                checksum: 65442,
                urgptr: 0,
                options: vec![]
            }),
            pkt.layers[2]
        );

        assert_eq!(
            Layer::Raw(Raw {
                data: b"hello world".to_vec(),
                bit_offset: 0,
            }),
            pkt.layers[3]
        );
    }

    #[test]
    fn test_packet_update_ipv4_tcp() {
        // Ether / IPv4 / TCP / Raw
        let test_data = hex!("feff2000010000000100000008004500 AAAA 0f4540008006 AAAA 91fea0ed41d0e4df0d2c005038affe14114c618c501825bc AAAA 0000474554202f646f776e6c6f61642e68746d6c20485454502f312e310d0a486f73743a207777772e657468657265616c2e636f6d0d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f77733b20553b2057696e646f7773204e5420352e313b20656e2d55533b2072763a312e3629204765636b6f2f32303034303131330d0a4163636570743a20746578742f786d6c2c6170706c69636174696f6e2f786d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c746578742f68746d6c3b713d302e392c746578742f706c61696e3b713d302e382c696d6167652f706e672c696d6167652f6a7065672c696d6167652f6769663b713d302e322c2a2f2a3b713d302e310d0a4163636570742d4c616e67756167653a20656e2d75732c656e3b713d302e350d0a4163636570742d456e636f64696e673a20677a69702c6465666c6174650d0a4163636570742d436861727365743a2049534f2d383835392d312c7574662d383b713d302e372c2a3b713d302e370d0a4b6565702d416c6976653a203330300d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a526566657265723a20687474703a2f2f7777772e657468657265616c2e636f6d2f646576656c6f706d656e742e68746d6c0d0a0d0a");
        let mut pkt = Packet::from_bytes(test_data.as_ref()).unwrap();
        assert_eq!(4, pkt.layers.len());

        assert_eq!(0xAAAA, pkt.ipv4().unwrap().length);
        assert_eq!(0xAAAA, pkt.ipv4().unwrap().checksum);
        assert_eq!(0xAAAA, pkt.tcp().unwrap().checksum);

        pkt.update().unwrap();

        assert_eq!(0x0207, pkt.ipv4().unwrap().length);
        assert_eq!(0x9010, pkt.ipv4().unwrap().checksum);
        assert_eq!(0xa958, pkt.tcp().unwrap().checksum);
    }

    #[test]
    fn test_packet_update_ipv6_tcp() {
        // Ether / IPv6 / TCP / Raw
        let test_data = hex!("b40c25058e13000c29c134dc86dd60000000 AAAA 0640200300de20160125fc3683174e86cb72200300de20160110000000000a1204431d76005072e11aa7e255014450183f9e AAAA 0000474554202f66617669636f6e2e69636f20485454502f312e310d0a486f73743a2069702e77656265726e65747a2e6e65740d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f7773204e5420362e313b2072763a35392e3029204765636b6f2f32303130303130312046697265666f782f35392e300d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c2a2f2a3b713d302e380d0a4163636570742d4c616e67756167653a2064652c656e2d55533b713d302e372c656e3b713d302e330d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a0d0a");
        let mut pkt = Packet::from_bytes(test_data.as_ref()).unwrap();
        assert_eq!(4, pkt.layers.len());

        assert_eq!(0xAAAA, pkt.ipv6().unwrap().length);
        assert_eq!(0xAAAA, pkt.tcp().unwrap().checksum);

        pkt.update().unwrap();

        assert_eq!(0x0143, pkt.ipv6().unwrap().length);
        assert_eq!(0x2eda, pkt.tcp().unwrap().checksum);
    }

    #[test]
    fn test_packet_update_ipv4_udp() {
        // Ether / IPv4 / UDP / Raw
        let test_data = hex!("000c4182b25300d0596c404e08004500 AAAA 0a4100008011 AAAA c0a83232c0a80001ff02ff35 AAAA AAAA 002b0100000100000000000002757304706f6f6c036e7470036f72670000010001");
        let mut pkt = Packet::from_bytes(test_data.as_ref()).unwrap();
        assert_eq!(4, pkt.layers.len());

        assert_eq!(0xAAAA, pkt.ipv4().unwrap().length);
        assert_eq!(0xAAAA, pkt.ipv4().unwrap().checksum);
        assert_eq!(0xAAAA, pkt.udp().unwrap().length);
        assert_eq!(0xAAAA, pkt.udp().unwrap().checksum);

        pkt.update().unwrap();

        assert_eq!(0x003d, pkt.ipv4().unwrap().length);
        assert_eq!(0x7ceb, pkt.ipv4().unwrap().checksum);
        assert_eq!(0x0029, pkt.udp().unwrap().length);
        assert_eq!(0x07a9, pkt.udp().unwrap().checksum);
    }

    #[test]
    fn test_packet_update_ipv6_udp() {
        // Ether / IPv6 / UDP / Raw
        let test_data = hex!("5475d0c90b810050568706b686dd60000000 AAAA 114020010470e5bf10011cc773ff65f5a2f720010470e5bf10960002009900c10010b4d100a1 AAAA AAAA 303e0201033011020429cdb17a020300ffcf0401040201030410300e0400020100020100040004000400301404000400a00e020460ba10f60201000201003000");
        let mut pkt = Packet::from_bytes(test_data.as_ref()).unwrap();
        assert_eq!(4, pkt.layers.len());

        assert_eq!(0xAAAA, pkt.ipv6().unwrap().length);
        assert_eq!(0xAAAA, pkt.udp().unwrap().length);
        assert_eq!(0xAAAA, pkt.udp().unwrap().checksum);

        pkt.update().unwrap();

        assert_eq!(0x0048, pkt.ipv6().unwrap().length);
        assert_eq!(0x0048, pkt.udp().unwrap().length);
        assert_eq!(0x15b3, pkt.udp().unwrap().checksum);
    }
}
