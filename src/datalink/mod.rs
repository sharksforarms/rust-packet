/*!
Module to send and receive packets over an interface
*/

#[cfg(feature = "pcap")]
pub mod pcap;

#[cfg(feature = "pcap")]
pub mod pcapfile;

#[cfg(feature = "pnet")]
pub mod pnet;

pub mod error;

use crate::datalink::error::DataLinkError;
use crate::packet::Packet;

/// A generic Packet interface used to Read and Write packets
pub struct Interface<T: PacketRead + PacketWrite>(T);

impl<T: PacketRead + PacketWrite> Iterator for Interface<T> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.0.read();
        if let Ok(packet) = packet {
            Some(packet)
        } else {
            None
        }
    }
}

impl<T: PacketRead + PacketWrite> PacketInterface for Interface<T> {
    fn init(interface_name: &str) -> Result<Self, DataLinkError>
    where
        Self: Sized,
    {
        Interface::<T>::new(interface_name)
    }
}

impl<T: PacketRead + PacketWrite> PacketWrite for Interface<T> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.0.write(packet)
    }
}

impl<T: PacketRead + PacketWrite> Interface<T> {
    /// Packet sniffing via a callback
    pub fn sniff<U, F, C, R, D>(
        name: &str,
        user_data: &mut U,
        filter: F,
        callback: C,
        condition: D,
    ) -> Result<R, DataLinkError>
    where
        F: Fn(&Packet, &mut U) -> bool,
        C: Fn(&Packet, &mut U) -> R,
        D: Fn(&Packet, &mut U) -> bool,
    {
        let mut interface = T::init(name)?;
        loop {
            let pkt = interface.read()?;

            if filter(&pkt, user_data) {
                let callback_res = callback(&pkt, user_data);
                if condition(&pkt, user_data) {
                    return Ok(callback_res);
                }
            }
        }
    }

    /// Create a new interface
    ///
    /// `name` could be a network interface id, pcap filename, etc. dependant on `T`
    pub fn new(name: &str) -> Result<Self, DataLinkError> {
        Ok(Interface(T::init(name)?))
    }
}

/// Packet interface
pub trait PacketInterface {
    /// Initialization of an interface
    ///
    /// `name` could be a network interface id, pcap filename, etc.
    fn init(name: &str) -> Result<Self, DataLinkError>
    where
        Self: Sized;
}

/// Packet read on an interface
pub trait PacketRead: PacketInterface {
    fn read(&mut self) -> Result<Packet, DataLinkError>;
}

/// Packet write on an interface
pub trait PacketWrite: PacketInterface {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError>;
}
