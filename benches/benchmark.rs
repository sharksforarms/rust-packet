#[macro_use]
extern crate criterion;
extern crate rust_packet;

use criterion::black_box;
use criterion::Criterion;
use hex_literal::hex;

use rust_packet::packet::layer::{ether::Ether, ip::Ipv4, ip::Ipv6, tcp::Tcp, Layer};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("ether_from_bytes", |b| {
        let input = hex!("ec086b507d584ccc6ad61f760800FFFF");
        b.iter(|| Ether::from_bytes(black_box((&input, 0))))
    });

    c.bench_function("ipv4_from_bytes", |b| {
        let input = hex!("450000502bc1400040068f37c0a8016bc01efd7dFFFF");
        b.iter(|| Ipv4::from_bytes(black_box((&input, 0))))
    });

    c.bench_function("ipv6_from_bytes", |b| {
        let input = hex!(
            "60000000012867403ffe802000000001026097fffe0769ea3ffe050100001c010200f8fffe03d9c0FFFF"
        );
        b.iter(|| Ipv6::from_bytes(black_box((&input, 0))))
    });

    c.bench_function("tcp_from_bytes", |b| {
        let input = hex!("0d2c005038affe14114c618c501825bca9580000FFFF");
        b.iter(|| Tcp::from_bytes(black_box((&input, 0))))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
