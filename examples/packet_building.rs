use rust_packet::prelude::*;

fn main() {
    let my_pkt = pkt! {
        ether! {
            dst: "da:af:d8:5f:73:f8".parse()?
        }?,
        ipv4! {
            src: "127.0.0.1".parse()?,
            dst: "127.0.0.2".parse()?,
        }?,
        udp! {
            dport: 53
        }?,
        raw! {
            data: b"hello world".to_vec()
        }?,
    }
    .unwrap();

    let _raw_bytes = my_pkt.to_bytes();
}
