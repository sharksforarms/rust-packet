pub mod ipv4;

pub use ipv4::Ipv4;

enum Ip {
    V4(Ipv4),
}
