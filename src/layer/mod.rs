#[macro_use]
pub mod ether;
#[macro_use]
pub mod ip;
#[macro_use]
pub mod tcp;

pub use ether::Ether;
pub use ip::{Ipv4, Ipv6};
pub use tcp::Tcp;

pub mod error;
pub use error::LayerError;

macro_rules! gen_layer_types {
    ($($types:ident,)*) => {
        #[derive(Debug, PartialEq)]
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

            pub fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
                let ret = match self {
                    $(
                        Layer::$types (v) => deku::DekuContainerWrite::to_bytes(v)?
                    ),*
                };

                Ok(ret)
            }
        }

        #[derive(Debug, PartialEq)]
        pub enum LayerType {
            $($types,)*
        }
    };
}

gen_layer_types!(Ether, Ipv4, Ipv6, Tcp,);

/// Internal macro used to expand layer macros, not for public use
#[doc(hidden)]
#[macro_export]
macro_rules! __builder_impl {
    ($layer_type:ident, $($field_ident:ident : $field:expr),*) => ({
        use deku::DekuUpdate;
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
