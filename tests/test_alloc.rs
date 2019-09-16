extern crate rust_packet;

use alloc_counter::AllocCounterSystem;

#[global_allocator]
static A: AllocCounterSystem = AllocCounterSystem;

mod tests {

    use alloc_counter::count_alloc;
    use rust_packet::layer::{ether::Ether, ip::Ipv4, Layer};

    #[test]
    fn test_alloc_ether_from_bytes() {
        assert_eq!(
            count_alloc(|| {
                let _ether = Ether::from_bytes(b"ec086b507d584ccc6ad61f760800FFFF");
            })
            .0,
            (0, 0, 0)
        );
    }

    #[test]
    fn test_alloc_ipv4_from_bytes() {
        assert_eq!(
            count_alloc(|| {
                let _ip = Ipv4::from_bytes(b"450000502bc1400040068f37c0a8016bc01efd7dFFFF");
            })
            .0,
            (0, 0, 0)
        );
    }
}
