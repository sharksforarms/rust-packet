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
}
