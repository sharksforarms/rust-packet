#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rust_packet;

use rust_packet::layer::{
    Layer,
    ip::Ipv4,
};

fuzz_target!(|data: &[u8]| {
    Ipv4::from_bytes(data);
});
