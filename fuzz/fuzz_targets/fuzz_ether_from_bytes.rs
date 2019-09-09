#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rust_packet;

use rust_packet::layer::{
    Layer,
    ether::Ether
};

fuzz_target!(|data: &[u8]| {
    Ether::from_bytes(data);
});
