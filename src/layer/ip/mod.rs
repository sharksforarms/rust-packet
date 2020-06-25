#[macro_use]
pub mod ipv4;
pub mod ipv6;
pub mod protocols;

pub use ipv4::Ipv4;
pub use ipv6::Ipv6;
pub use protocols::IpProtocol;
