#[cfg(feature = "pcap")]
fn main() {
    use rust_packet::prelude::*;
    // Read from pcap file
    let mut rx = Interface::<PcapFile>::new("test.pcap").unwrap();
    let mut tx = Interface::<Pnet>::new("lo").unwrap();

    for pkt in &mut rx {
        tx.write(pkt).unwrap();
    }
}

#[cfg(not(feature = "pcap"))]
fn main() {}
