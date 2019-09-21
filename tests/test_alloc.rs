extern crate rust_packet;
use alloc_counter::AllocCounterSystem;

#[global_allocator]
static A: AllocCounterSystem = AllocCounterSystem;

mod tests {

    use alloc_counter::count_alloc;
    use rust_packet::layer::{ether::Ether, ether::MacAddress, ip::Ipv4, Layer};
    use std::net::Ipv4Addr;

    #[test]
    fn test_alloc_ether_from_bytes() {
        let input = &hex::decode("ec086b507d584ccc6ad61f760800FFFF").unwrap();
        let expected = Ok((
            Ether {
                dst: MacAddress::from_bytes([236, 8, 107, 80, 125, 88]),
                src: MacAddress::from_bytes([76, 204, 106, 214, 31, 118]),
                ether_type: 0x0800,
            },
            [0xFF, 0xFF].as_ref(),
        ));

        assert_eq!(
            count_alloc(|| {
                let ether = Ether::from_bytes(input);

                assert_eq!(expected, ether);
            })
            .0,
            (0, 0, 0)
        );
    }

    #[test]
    fn test_alloc_ipv4_from_bytes() {
        let input = &hex::decode("450000502bc1400040068f37c0a8016bc01efd7dFFFF").unwrap();
        let expected = Ok((
            Ipv4 {
                version: 4,
                ihl: 5,
                ecn: 0,
                dscp: 0,
                length: 80,
                identification: 0x2bc1,
                flags: 2,
                offset: 0,
                ttl: 64,
                protocol: 6,
                checksum: 0x8f37,
                src: Ipv4Addr::new(192, 168, 1, 107),
                dst: Ipv4Addr::new(192, 30, 253, 125),
            },
            [0xFF, 0xFF].as_ref(),
        ));

        assert_eq!(
            count_alloc(|| {
                let ip = Ipv4::from_bytes(input);
                assert_eq!(expected, ip);
            })
            .0,
            (0, 0, 0)
        );
    }
}
