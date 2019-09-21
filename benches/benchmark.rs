#[macro_use]
extern crate criterion;
extern crate rust_packet;

use criterion::black_box;
use criterion::Criterion;

use rust_packet::layer::{ether::Ether, ip::Ipv4, ip::Ipv6, Layer};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("ether_from_bytes", |b| {
        let input = &hex::decode("ec086b507d584ccc6ad61f760800FFFF").unwrap();
        b.iter(|| Ether::from_bytes(black_box(input)))
    });

    c.bench_function("ipv4_from_bytes", |b| {
        let input = &hex::decode("450000502bc1400040068f37c0a8016bc01efd7dFFFF").unwrap();
        b.iter(|| Ipv4::from_bytes(black_box(input)))
    });

    c.bench_function("ipv6_from_bytes", |b| {
        let input = &hex::decode(
            "60000000012867403ffe802000000001026097fffe0769ea3ffe050100001c010200f8fffe03d9c0FFFF",
        )
        .unwrap();
        b.iter(|| Ipv6::from_bytes(black_box(input)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
