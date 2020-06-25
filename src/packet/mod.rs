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
    use crate::layer::tcp::TcpOption;
    use crate::{ether, ipv4, tcp};

    #[test]
    fn test_packet() {
        let mut pkt = pkt! {
            ether! {
                src: "00:0a:95:9d:68:16".parse()?,
                dst: "00:0a:95:9d:68:17".parse()?,
            }?,
            ipv4! {
                src: "127.0.0.1".parse()?,
                dst: "127.0.0.2".parse()?,
            }?,
            tcp! {
                sport: 80,
                options: vec![
                    TcpOption::NOP,
                ]
            }?
        }
        .unwrap();

        if let Layer::Ipv4(layer) = &mut pkt[LayerType::Ipv4] {
            (*layer).src = "127.0.0.4".parse().unwrap();
        }

        pkt.tcp_mut().unwrap().sport = 81;

        println!("{:#?}", pkt[LayerType::Ipv4]);
        println!("{:#?}", pkt[LayerType::Tcp]);
        println!("{:#?}", pkt.ipv6());
        println!("{:x?}", pkt.to_bytes().unwrap());

        let _ipv4 = ipv4! {
            src: "127.0.0.....2".parse()?,
        };

        // TODO
    }
}
