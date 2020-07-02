pub mod error;
pub mod ether;
pub mod ip;
pub mod raw;
pub mod tcp;
pub mod udp;

pub use error::LayerError;
pub use ether::Ether;
pub use ip::{IpProtocol, Ipv4, Ipv6};
pub use raw::Raw;
pub use tcp::Tcp;
pub use udp::Udp;

use deku::prelude::*;

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    Checksum,
}

pub trait LayerValidate {
    fn validate(&self) -> Result<Vec<ValidationError>, LayerError> {
        Ok(Vec::new())
    }
}

macro_rules! do_layer {
    ($layer:ident, $input:ident, $layers:ident) => {{
        let (rest, layer) = $layer::from_bytes($input)?;
        $layers.push(Layer::$layer(layer));

        rest
    }};
}

macro_rules! gen_layer_types {
    ($($types:ident,)*) => {
        #[derive(Debug, PartialEq, Clone)]
        pub enum Layer {
            $($types ( $types )),*
        }

        impl Layer {
            pub fn layer_type(&self) -> LayerType {
                match self {
                    $(
                        Layer::$types (_) => LayerType:: $types
                    ),*
                }
            }

            fn consume_layer<'a>(rest: (&'a [u8], usize), layers: &mut Vec<Layer>, max_depth: usize) -> Result<(), LayerError> {
                if max_depth == 0 {
                    if !rest.0.is_empty() {
                        let rest = {
                            do_layer!(Raw, rest, layers)
                        };

                        assert!(rest.0.is_empty(), "dev error: rest should always be empty here");
                    }

                    return Ok(())
                }

                // # Layer: How the layer is consumed
                let new_rest = if let Some(previous_layer) = layers.iter().last() {
                    match previous_layer {
                        Layer::Ether(eth) => {
                            match eth.ether_type {
                                ether::EtherType::IPv4 => {
                                    do_layer!(Ipv4, rest, layers)
                                },
                                ether::EtherType::IPv6 => {
                                    do_layer!(Ipv6, rest, layers)
                                },
                                _ => {
                                    // eth type not supported
                                    return Layer::consume_layer(rest, layers, 0);
                                }
                            }

                        },
                        Layer::Ipv4(ipv4) => {
                            match ipv4.protocol {
                                IpProtocol::TCP => {
                                    do_layer!(Tcp, rest, layers)
                                },
                                IpProtocol::UDP => {
                                    do_layer!(Udp, rest, layers)
                                },
                                _ => {
                                    // ip protocol not supported
                                    return Layer::consume_layer(rest, layers, 0);
                                }
                            }
                        },
                        Layer::Ipv6(ipv6) => {
                            match ipv6.next_header {
                                IpProtocol::TCP => {
                                    do_layer!(Tcp, rest, layers)
                                },
                                IpProtocol::UDP => {
                                    do_layer!(Udp, rest, layers)
                                },
                                _ => {
                                    // ip protocol not supported
                                    return Layer::consume_layer(rest, layers, 0);
                                }
                            }
                        }
                        _ => {
                            // nothing to consume next, create raw layer with rest
                            return Layer::consume_layer(rest, layers, 0);
                        }
                    }

                } else {
                    unreachable!("dev error: no previous layer available from caller")
                };

                Layer::consume_layer(new_rest, layers, max_depth-1)
            }

            pub fn from_bytes_multi_layer(input: &[u8], max_depth: usize) -> Result<Vec<Layer>, LayerError> {
                let mut layers = Vec::new();
                let mut rest = (input, 0);

                rest = {
                    do_layer!(Ether, rest, layers)
                };

                Layer::consume_layer(rest, &mut layers, max_depth)?;

                Ok(layers)
            }

            pub fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
                let ret = match self {
                    $(
                        Layer::$types (v) => v.to_bytes()?
                    ),*
                };

                Ok(ret)
            }

            pub fn update(&mut self) -> Result<(), LayerError> {
                match self {
                    $(
                        Layer::$types (v) => v.update()?
                    ),*
                };

                Ok(())
            }
        }

        #[derive(Debug, PartialEq)]
        pub enum LayerType {
            $($types,)*
        }
    };
}

// # LAYER: Add type to Layer enum
gen_layer_types!(Raw, Ether, Ipv4, Ipv6, Tcp, Udp,);

/// Internal macro used to expand layer macros, not for public use
#[doc(hidden)]
#[macro_export]
macro_rules! __builder_impl {
    ($layer_type:ident, $($field_ident:ident : $field:expr),*) => ({
        || -> Result<_, crate::layer::LayerError> {
            let mut layer = crate::layer::$layer_type {
                $($field_ident : $field,)*
                ..Default::default()
            };

            layer.update()?;

            Ok(crate::layer::Layer::$layer_type(layer))
        }()
    });
}

// # LAYER: macro to build layer

#[macro_export]
macro_rules! raw {
    ($($field_ident:ident : $field:expr),* $(,)?) => (
        $crate::__builder_impl!(Raw, $($field_ident : $field),*)
    );
}

#[macro_export]
macro_rules! ether {
    ($($field_ident:ident : $field:expr),* $(,)?) => (
        $crate::__builder_impl!(Ether, $($field_ident : $field),*)
    );
}

#[macro_export]
macro_rules! ipv4 {
    ($($field_ident:ident : $field:expr),* $(,)?) => (
        $crate::__builder_impl!(Ipv4, $($field_ident : $field),*)
    );
}

#[macro_export]
macro_rules! ipv6 {
    ($($field_ident:ident : $field:expr),* $(,)?) => (
        $crate::__builder_impl!(Ipv6, $($field_ident : $field),*)
    );
}

#[macro_export]
macro_rules! tcp {
    ($($field_ident:ident : $field:expr),* $(,)?)=> (
        $crate::__builder_impl!(Tcp, $($field_ident : $field),*)
    );
}

#[macro_export]
macro_rules! udp {
    ($($field_ident:ident : $field:expr),* $(,)?)=> (
        $crate::__builder_impl!(Udp, $($field_ident : $field),*)
    );
}
