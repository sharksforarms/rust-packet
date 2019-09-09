#[macro_use]
extern crate criterion;
extern crate rust_packet;

use criterion::Criterion;
use criterion::black_box;

use rust_packet::layer::{
    Layer,
    ether::Ether
};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("ether_from_bytes", |b| b.iter(|| Ether::from_bytes(black_box(b"12345678901234"))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);