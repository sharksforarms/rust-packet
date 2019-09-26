#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rust_packet;

use rust_packet::layer::{
    Layer,
    tcp::Tcp,
};

fuzz_target!(|data: &[u8]| {
    Tcp::from_bytes(data);
});
