use rust_packet::prelude::*;

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_layer {
        ($test_name:ident, $layer:ident, $layer_name:ident, $layer_name_mut:ident) => {
            #[test]
            fn $test_name() {
                // Test creating layer via macro call
                let layer = $layer_name!().unwrap();

                // Verify Layer enum
                if let Layer::$layer(v) = &layer {
                    assert_eq!($layer::default(), *v);
                } else {
                    panic!("expected layer");
                }

                // Construct packet with layer
                let mut pkt = pkt! {
                    layer
                }
                .unwrap();

                // Access layer via method
                let layer = pkt.$layer_name();
                assert!(layer.is_some());

                // Access mut layer via method
                let layer = pkt.$layer_name_mut();
                assert!(layer.is_some());
            }
        };
    }

    // Tests to ensure correct implementations of all layer functionality
    test_layer!(test_ether, Ether, ether, ether_mut);
    test_layer!(test_tcp, Tcp, tcp, tcp_mut);
    test_layer!(test_ipv4, Ipv4, ipv4, ipv4_mut);
    test_layer!(test_ipv6, Ipv6, ipv6, ipv6_mut);
    test_layer!(test_raw, Raw, raw, raw_mut);
}
