#![no_main]
use libfuzzer_sys::fuzz_target;

use rust_packet::prelude::*;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::from_bytes(data);
});
