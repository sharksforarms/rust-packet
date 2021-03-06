/*!
A network packet parser and builder. This crate is meant to provide similar functionality to python's scapy module in terms of packet and layer manipulation.

# Example

See [examples](https://github.com/sharksforarms/rust-packet/tree/master/examples) for more.

```rust
use rust_packet::prelude::*;

// Build a packet!
let pkt: Packet = pkt! {
    ether! {
        dst: "de:ad:be:ef:c0:fe".parse()?
    }?,
    ipv4! {
        src: "127.0.0.1".parse()?,
        dst: "127.0.0.2".parse()?,
    }?,
    udp! {
        dport: 1337
    }?,
    raw! {
        data: b"hello world!".to_vec()
    }?,
}.unwrap();

// Read a packet!
let input: Vec<u8> = pkt.to_bytes().unwrap();
let mut pkt = Packet::from_bytes(input.as_ref()).unwrap();

// Change the packet!
if let Some(ipv4) = pkt.ipv4_mut() {
    ipv4.dst = "127.0.0.3".parse().unwrap()
}

// Update the packet! (This will update the various checksums (Ipv4, TCP, UDP))
pkt.update().unwrap();

// Write the packet!
let raw_bytes = pkt.to_bytes().unwrap();
```
*/

pub mod datalink;
pub mod layer;
pub mod packet;
pub mod prelude;
