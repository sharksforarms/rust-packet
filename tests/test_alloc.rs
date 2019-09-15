extern crate rust_packet;

use alloc_counter::AllocCounterSystem;

#[global_allocator]
static A: AllocCounterSystem = AllocCounterSystem;

mod tests {

    use alloc_counter::count_alloc;
    use rust_packet::layer::{ether::Ether, Layer};

    #[test]
    fn test_alloc() {
        assert_eq!(
            count_alloc(|| {
                let _ether = Ether::from_bytes(b"12345678901234");
            })
            .0,
            (0, 0, 0)
        );
    }
}
