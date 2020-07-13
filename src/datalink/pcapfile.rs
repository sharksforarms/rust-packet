/*!
Packet interface implementation using `libpcap` to read pcap files

Note: Pcap writing currently not supported

libpcap interface exposed via libpnet
*/
use pnet::datalink::{self, Channel, DataLinkReceiver};

use super::{DataLinkError, PacketInterface, PacketRead, PacketWrite};
use crate::packet::Packet;

pub struct PcapFile {
    rx: Box<dyn DataLinkReceiver + 'static>,
    // tx: Box<dyn DataLinkSender + 'static>, // TODO: implement pcap writing
}

impl PacketInterface for PcapFile {
    fn init(filename: &str) -> Result<Self, DataLinkError> {
        let (_tx, rx) = match datalink::pcap::from_file(filename, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
            Ok(_) => Err(DataLinkError::UnhandledInterfaceType),
            Err(e) => Err(DataLinkError::IoError(e)),
        }?;

        Ok(PcapFile { rx })
    }
}

impl PacketRead for PcapFile {
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

impl PacketWrite for PcapFile {
    fn write(&mut self, _packet: Packet) -> Result<(), DataLinkError> {
        unimplemented!();
    }
}
