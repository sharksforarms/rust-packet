#[macro_use]
extern crate criterion;
extern crate rust_packet;

use criterion::black_box;
use criterion::Criterion;

use rust_packet::layer::{ether::Ether, ip::Ipv4, Layer};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("ether_from_bytes", |b| {
        b.iter(|| Ether::from_bytes(black_box(b"ec086b507d584ccc6ad61f760800")))
    });

    c.bench_function("ipv4_from_bytes", |b| {
        b.iter(|| Ipv4::from_bytes(black_box(b"450000502bc1400040068f37c0a8016bc01efd7d")))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
