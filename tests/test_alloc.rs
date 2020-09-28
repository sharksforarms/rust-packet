extern crate rust_packet;
use alloc_counter::AllocCounterSystem;

#[global_allocator]
static A: AllocCounterSystem = AllocCounterSystem;

macro_rules! gen_count_alloc {
    ($test_name:ident, $layer:ident, $header:expr, $expected_from_bytes:expr, $expected_to_bytes:expr) => {
        #[ignore]
        #[test]
        fn $test_name() {
            let input_read = $header;
            let input_write = $layer::try_from(input_read).unwrap();

            assert_eq!(
                count_alloc(|| {
                    $layer::try_from(input_read).unwrap();
                })
                .0,
                $expected_from_bytes
            );

            assert_eq!(
                count_alloc(|| {
                    input_write.to_bytes().unwrap();
                })
                .0,
                $expected_to_bytes
            );
        }
    };
}

#[cfg(test)]
mod tests {

    use alloc_counter::count_alloc;
    use hex_literal::hex;
    use rust_packet::prelude::*;
    use std::convert::TryFrom;

    // # LAYER: Test to track allocation counts for read/write
    gen_count_alloc!(
        test_raw,
        Raw,
        hex!("FFFFFFFFFF").as_ref(),
        (1, 0, 1), // expected read allocations (malloc, realloc, free)
        (1, 0, 1)  // expected write allocations (malloc, realloc, free)
    );
    gen_count_alloc!(
        test_ether,
        Ether,
        hex!("ec086b507d584ccc6ad61f760800").as_ref(),
        (0, 0, 0),
        (1, 1, 1)
    );
    gen_count_alloc!(
        test_ipv4,
        Ipv4,
        hex!("450000502bc1400040068f37c0a8016bc01efd7d").as_ref(),
        (6, 0, 6),
        (1, 2, 1)
    );
    gen_count_alloc!(
        test_ipv6,
        Ipv6,
        hex!("60000000012867403ffe802000000001026097fffe0769ea3ffe050100001c010200f8fffe03d9c0")
            .as_ref(),
        (4, 1, 4),
        (1, 2, 1)
    );
    gen_count_alloc!(
        test_tcp,
        Tcp,
        hex!("0d2c005038affe14114c618c501825bca9580000").as_ref(),
        (11, 0, 11),
        (1, 2, 1)
    );
    gen_count_alloc!(
        test_udp,
        Udp,
        hex!("b4d100a1004815b3").as_ref(),
        (0, 0, 0),
        (1, 0, 1)
    );
}
