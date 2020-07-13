pub mod layer;
use layer::Layer;

pub struct Packet {
    layers: Vec<Box<dyn Layer>>,
}

impl Packet {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut acc = Vec::new();
        for layer in &self.layers {
            acc.extend(
                deku::DekuWrite::write(&**layer, false, None)
                    .unwrap()
                    .into_vec(),
            );
        }

        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet() {
        let pkt = Packet {
            layers: vec![
                Box::new(layer::Ether::default()),
                Box::new(layer::Ipv4::default()),
            ],
        };

        // TODO
    }
}
