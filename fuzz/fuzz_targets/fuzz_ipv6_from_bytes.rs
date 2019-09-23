#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rust_packet;

use rust_packet::layer::{
    Layer,
    ip::Ipv6,
};

fuzz_target!(|data: &[u8]| {
    Ipv6::from_bytes(data);
});
