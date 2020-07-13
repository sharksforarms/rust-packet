extern crate rust_packet;
use alloc_counter::AllocCounterSystem;

#[global_allocator]
static A: AllocCounterSystem = AllocCounterSystem;

mod tests {

    use alloc_counter::count_alloc;
    use hex_literal::hex;
    use rust_packet::packet::layer::{
        ether::Ether, ether::EtherType, ether::MacAddress, ip::Ipv4, ip::Ipv6, tcp::Tcp,
    };
    use std::convert::TryFrom;
    use std::net::Ipv4Addr;

    #[test]
    fn test_alloc_ether_from_bytes() {
        let input = hex!("ec086b507d584ccc6ad61f760800").as_ref();
        let expected = Ether {
            dst: MacAddress([236, 8, 107, 80, 125, 88]),
            src: MacAddress([76, 204, 106, 214, 31, 118]),
            ether_type: EtherType::IPv4,
        };

        assert_eq!(
            count_alloc(|| {
                let ether = Ether::try_from(input).unwrap();

                assert_eq!(expected, ether);
            })
            .0,
            (13, 0, 13)
        );
    }

    #[test]
    fn test_alloc_ipv4_from_bytes() {
        let input = hex!("450000502bc1400040068f37c0a8016bc01efd7d").as_ref();
        let expected = Ipv4 {
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
        };

        assert_eq!(
            count_alloc(|| {
                let ip = Ipv4::try_from(input).unwrap();
                assert_eq!(expected, ip);
            })
            .0,
            (13, 0, 13)
        );
    }

    #[test]
    fn test_alloc_ipv6_from_bytes() {
        let input = hex!(
            "60000000012867403ffe802000000001026097fffe0769ea3ffe050100001c010200f8fffe03d9c0"
        )
        .as_ref();
        let expected = Ipv6 {
            version: 6,
            ds: 0,
            ecn: 0,
            label: 0,
            length: 296,
            next_header: 103,
            hop_limit: 64,
            src: "3ffe:8020:0:1:260:97ff:fe07:69ea".parse().unwrap(),
            dst: "3ffe:501:0:1c01:200:f8ff:fe03:d9c0".parse().unwrap(),
        };

        assert_eq!(
            count_alloc(|| {
                let ip = Ipv6::try_from(input).unwrap();
                assert_eq!(expected, ip);
            })
            .0,
            (9, 1, 9)
        );
    }

    #[test]
    fn test_alloc_tcp_from_bytes() {
        let input = hex!("0d2c005038affe14114c618c501825bca9580000").as_ref();
        let expected = Tcp {
            sport: 3372,
            dport: 80,
            seq: 951057940,
            ack: 290218380,
            offset: 5,
            flags: 0x018,
            window: 9660,
            checksum: 0xa958,
            urgptr: 0,
            options: Vec::new(),
        };

        assert_eq!(
            count_alloc(|| {
                let tcp = Tcp::try_from(input).unwrap();
                assert_eq!(expected, tcp);
            })
            .0,
            (9, 0, 9)
        );
    }
}
