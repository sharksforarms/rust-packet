pub mod ether;
pub mod ip;
pub mod tcp;

pub use ether::Ether;
pub use ip::{Ipv4, Ipv6};
pub use tcp::Tcp;

pub mod error;
pub use error::LayerError;

pub trait Layer: core::fmt::Debug + deku::DekuRead + deku::DekuWrite {}

impl Layer for Ether {}
impl Layer for Ipv4 {}
impl Layer for Ipv6 {}
impl Layer for Tcp {}
