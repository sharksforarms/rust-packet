pub mod error;
pub use error::PacketError;

use crate::layer::{Layer, LayerType};

#[derive(Debug)]
pub struct Packet {
    layers: Vec<Layer>,
}

impl Packet {
    pub fn new(layers: Vec<Layer>) -> Self {
        Packet { layers }
    }

    pub fn from_bytes(input: &[u8]) -> Result<Packet, PacketError> {
        let layers = Layer::from_bytes_multi_layer(input)?;
        Ok(Packet::new(layers))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut acc = Vec::new();
        for layer in &self.layers {
            acc.extend(layer.to_bytes()?);
        }

        Ok(acc)
    }

    pub fn update(&mut self) -> Result<(), PacketError> {
        /* TODO:
            I feel like this routine can be optimized.
            The main quirk is that TCP/UDP checksums depend
            on the ip header and following data...
        */

        for i in 0..self.layers.len() {
            let layers = &mut self.layers.as_mut_slice()[i..];

            let data = if layers.len() > 2 {
                (layers[2..]).to_vec()
            } else {
                vec![]
            };

            match layers {
                [] => {}
                [layer] => {
                    layer.update()?;
                }
                [layer, next_layer, ..] => {
                    // Update current layer
                    layer.update()?;

                    // Update next-layers which depend on current layer
                    #[allow(clippy::single_match)]
                    match next_layer {
                        Layer::Tcp(tcp) => match layer {
                            Layer::Ipv4(ipv4) => tcp.update_checksum_ipv4(ipv4, &data)?,
                            Layer::Ipv6(ipv6) => tcp.update_checksum_ipv6(ipv6, &data)?,
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
}

macro_rules! impl_packet_layer {
    ($layer:ident, $func:ident, $func_mut:ident) => {
        impl Packet {
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
        }
    };
}

impl_packet_layer!(Ether, ether, ether_mut);
impl_packet_layer!(Ipv4, ipv4, ipv4_mut);
impl_packet_layer!(Ipv6, ipv6, ipv6_mut);
impl_packet_layer!(Tcp, tcp, tcp_mut);
impl_packet_layer!(Raw, raw, raw_mut);

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

#[macro_export]
macro_rules! pkt {
    ($($layers:expr),+ $(,)?) => ({
        || -> Result<_, PacketError> {
            Ok(Packet::new(vec![$($layers),*]))
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
                dst: "127.0.0.1".parse().unwrap()
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

        assert_eq!(Layer::Raw(Raw::new(b"hello world", 0)), pkt.layers[3]);
    }

    #[test]
    fn test_packet_update_tcp_checksums() {
        // Ether / IP / TCP / Raw with checksums replaced with AAAA
        let test_data = hex!("feff200001000000010000000800450002070f4540008006 AAAA 91fea0ed41d0e4df0d2c005038affe14114c618c501825bc AAAA 0000474554202f646f776e6c6f61642e68746d6c20485454502f312e310d0a486f73743a207777772e657468657265616c2e636f6d0d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f77733b20553b2057696e646f7773204e5420352e313b20656e2d55533b2072763a312e3629204765636b6f2f32303034303131330d0a4163636570743a20746578742f786d6c2c6170706c69636174696f6e2f786d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c746578742f68746d6c3b713d302e392c746578742f706c61696e3b713d302e382c696d6167652f706e672c696d6167652f6a7065672c696d6167652f6769663b713d302e322c2a2f2a3b713d302e310d0a4163636570742d4c616e67756167653a20656e2d75732c656e3b713d302e350d0a4163636570742d456e636f64696e673a20677a69702c6465666c6174650d0a4163636570742d436861727365743a2049534f2d383835392d312c7574662d383b713d302e372c2a3b713d302e370d0a4b6565702d416c6976653a203330300d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a526566657265723a20687474703a2f2f7777772e657468657265616c2e636f6d2f646576656c6f706d656e742e68746d6c0d0a0d0a");
        let mut pkt = Packet::from_bytes(test_data.as_ref()).unwrap();
        assert_eq!(4, pkt.layers.len());

        assert_eq!(0xAAAA, pkt.ipv4().unwrap().checksum);
        assert_eq!(0xAAAA, pkt.tcp().unwrap().checksum);

        pkt.update().unwrap();

        assert_eq!(0x9010, pkt.ipv4().unwrap().checksum);
        assert_eq!(0xa958, pkt.tcp().unwrap().checksum);
    }
}
