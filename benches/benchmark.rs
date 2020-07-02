#[macro_use]
extern crate criterion;
extern crate rust_packet;

use criterion::black_box;
use criterion::Criterion;
use hex_literal::hex;

use rust_packet::prelude::*;

macro_rules! gen_header_bench {
    ($crit:ident, $name:ident, $header:expr, $layer:ident) => {
        $crit.bench_function(concat!(stringify!($name), "_from_bytes"), |b| {
            b.iter(|| $layer::from_bytes(black_box(($header, 0))).expect("expected Ok"))
        });

        $crit.bench_function(concat!(stringify!($name), "_to_bytes"), |b| {
            let (_rest, header) = $layer::from_bytes(($header, 0)).unwrap();
            b.iter(|| header.to_bytes().expect("expected Ok"))
        });
    };
}

pub fn criterion_benchmark(c: &mut Criterion) {
    // # LAYER: Benchmarks
    gen_header_bench!(c, bench_raw, &hex!("b4d100a1004815b3"), Raw);
    gen_header_bench!(c, bench_ether, &hex!("ec086b507d584ccc6ad61f760800"), Ether);
    gen_header_bench!(
        c,
        bench_ipv4,
        &hex!("450000502bc1400040068f37c0a8016bc01efd7d"),
        Ipv4
    );
    gen_header_bench!(
        c,
        bench_ipv4,
        &hex!("60000000012867403ffe802000000001026097fffe0769ea3ffe050100001c010200f8fffe03d9c0"),
        Ipv6
    );
    gen_header_bench!(
        c,
        bench_tcp,
        &hex!("0d2c005038affe14114c618c501825bca9580000"),
        Tcp
    );
    gen_header_bench!(c, bench_udp, &hex!("b4d100a1004815b3"), Udp);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
