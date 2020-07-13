use rust_packet::prelude::*;

fn main() {
    // Read from interface
    let mut int = Interface::<Pnet>::new("lo").unwrap();

    for (i, pkt) in (&mut int).enumerate() {
        println!("Packet: {:?}", pkt);
        if i == 5 {
            break;
        }
    }

    // Write to interface
    let pkt = pkt! {
        ether! {}?,
        ipv4! {}?,
        udp! {}?,
        raw! {
            data: b"Hello world".to_vec(),
        }?
    }
    .unwrap();

    int.write(pkt).unwrap();
}
