/*!
Packet interface implementation using `libpcap`

libpcap interface exposed via libpnet
*/
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};

use super::{DataLinkError, PacketInterface, PacketRead, PacketWrite};
use crate::packet::Packet;

pub struct Pcap {
    rx: Box<dyn DataLinkReceiver + 'static>,
    tx: Box<dyn DataLinkSender + 'static>,
}

impl PacketInterface for Pcap {
    fn init(interface_name: &str) -> Result<Self, DataLinkError> {
        let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .filter(interface_names_match)
            .next()
            .ok_or(DataLinkError::InterfaceNotFound)?;

        let (tx, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
            Ok(_) => Err(DataLinkError::UnhandledInterfaceType),
            Err(e) => Err(DataLinkError::IoError(e)),
        }?;

        Ok(Pcap { rx, tx })
    }
}

impl PacketRead for Pcap {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        match self.rx.next() {
            Ok(packet_bytes) => {
                let packet = Packet::from_bytes(packet_bytes)?;
                Ok(packet)
            }
            Err(e) => Err(DataLinkError::IoError(e)),
        }
    }
}

impl PacketWrite for Pcap {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        let bytes = packet.to_bytes()?;
        if let Some(res) = self.tx.send_to(bytes.as_ref(), None) {
            Ok(res?)
        } else {
            Err(DataLinkError::BufferError)
        }
    }
}
