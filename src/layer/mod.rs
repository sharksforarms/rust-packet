/*!
Collection of network layer types

A layer is a type representing a network header found in a packet, such as Ether, Ipv4, etc.
*/

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
        /// Layer wrapper type
        #[derive(Debug, PartialEq, Clone)]
        pub enum Layer {
            $($types ( $types )),*
        }

        impl Layer {
            /// Returns the layer type of the layer
            pub fn layer_type(&self) -> LayerType {
                match self {
                    $(
                        Layer::$types (_) => LayerType:: $types
                    ),*
                }
            }

            // Recursive function to consume layers from a stream of bytes
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

            /// Returns a vector of `Layer` consumed from the byte stream
            /// This will consume the next-layer in accordance to the protocol
            pub fn from_bytes_multi_layer(input: &[u8], max_depth: usize) -> Result<Vec<Layer>, LayerError> {
                let mut layers = Vec::new();
                let mut rest = (input, 0);

                rest = {
                    do_layer!(Ether, rest, layers)
                };

                Layer::consume_layer(rest, &mut layers, max_depth)?;

                Ok(layers)
            }

            /// Writes the layer
            pub fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
                let ret = match self {
                    $(
                        Layer::$types (v) => v.to_bytes()?
                    ),*
                };

                Ok(ret)
            }

            /// Updates the layer
            pub fn update(&mut self) -> Result<(), LayerError> {
                match self {
                    $(
                        Layer::$types (v) => v.update()?
                    ),*
                };

                Ok(())
            }
        }

        /// Type of layer
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

/**
Create a [Raw](layer/raw/struct.Raw.html) layer

Fields which are not provided are defaulted.

Returns `Result<Layer::Raw(Raw), LayerError>`

Example:

```rust
# use rust_packet::prelude::*;
let layer = raw! {
    data: b"hello world".to_vec()
}.unwrap();
```
*/
#[macro_export]
macro_rules! raw {
    ($($field_ident:ident : $field:expr),* $(,)?) => (
        $crate::__builder_impl!(Raw, $($field_ident : $field),*)
    );
}

/**
Create a [Ether](layer/ether/struct.Ether.html) layer

Fields which are not provided are defaulted.

Returns `Result<Layer::Ether(Ether), LayerError>`

Example:

```rust
# use rust_packet::prelude::*;
let layer = ether! {
    src: "de:ad:be:ef:c0:fe".parse().unwrap()
}.unwrap();
```
*/
#[macro_export]
macro_rules! ether {
    ($($field_ident:ident : $field:expr),* $(,)?) => (
        $crate::__builder_impl!(Ether, $($field_ident : $field),*)
    );
}

/**
Create a [Ipv4](layer/ip/ipv4/struct.Ipv4.html) layer

Fields which are not provided are defaulted.

Returns `Result<Layer::Ipv4(Ipv4), LayerError>`

Example:

```rust
# use rust_packet::prelude::*;
let layer = ipv4! {
    src: "127.0.0.1".parse().unwrap()
}.unwrap();
```
*/
#[macro_export]
macro_rules! ipv4 {
    ($($field_ident:ident : $field:expr),* $(,)?) => (
        $crate::__builder_impl!(Ipv4, $($field_ident : $field),*)
    );
}

/**
Create a [Ipv6](layer/ip/ipv6/struct.Ipv6.html) layer

Fields which are not provided are defaulted.

Returns `Result<Layer::Ipv6(Ipv6), LayerError>`

Example:

```rust
# use rust_packet::prelude::*;
let pkt = pkt! {
    ether! {
        dst: "de:ad:be:ef:c0:fe".parse()?
    }?,
    ipv4! {
        src: "127.0.0.1".parse()?,
        dst: "127.0.0.2".parse()?,
    }?,
    udp! {
        dport: 1337
    }?,
    raw! {
        data: b"hello world!".to_vec()
    }?,
}.unwrap();
```
*/
#[macro_export]
macro_rules! ipv6 {
    ($($field_ident:ident : $field:expr),* $(,)?) => (
        $crate::__builder_impl!(Ipv6, $($field_ident : $field),*)
    );
}

/**
Create a [Tcp](layer/tcp/struct.Tcp.html) layer

Fields which are not provided are defaulted.

Returns `Result<Layer::Tcp(Tcp), LayerError>`

Example:

```rust
# use rust_packet::prelude::*;
let layer = tcp! {
    dport: 8080
}.unwrap();
```
*/
#[macro_export]
macro_rules! tcp {
    ($($field_ident:ident : $field:expr),* $(,)?)=> (
        $crate::__builder_impl!(Tcp, $($field_ident : $field),*)
    );
}

/**
Create a [Udp](layer/udp/struct.Udp.html) layer

Fields which are not provided are defaulted.

Returns `Result<Layer::Udp(Udp), LayerError>`

Example:

```rust
# use rust_packet::prelude::*;
let layer = udp! {
    dport: 8080
}.unwrap();
```
*/
#[macro_export]
macro_rules! udp {
    ($($field_ident:ident : $field:expr),* $(,)?)=> (
        $crate::__builder_impl!(Udp, $($field_ident : $field),*)
    );
}
