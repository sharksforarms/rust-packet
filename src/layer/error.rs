#[derive(Debug, PartialEq)]
pub enum LayerError {
    Parse(String),
    Unexpected(String),
    Checksum(String),
    DekuError(String),
    IntError(String),
}

impl From<deku::error::DekuError> for LayerError {
    fn from(e: deku::error::DekuError) -> Self {
        LayerError::DekuError(e.to_string())
    }
}

impl From<std::net::AddrParseError> for LayerError {
    fn from(e: std::net::AddrParseError) -> Self {
        LayerError::Parse(e.to_string())
    }
}

impl From<std::num::TryFromIntError> for LayerError {
    fn from(e: std::num::TryFromIntError) -> Self {
        LayerError::IntError(e.to_string())
    }
}

impl core::fmt::Display for LayerError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            LayerError::Parse(ref err) => write!(f, "Parse error: {}", err),
            LayerError::Unexpected(ref err) => write!(f, "Unexpected error: {}", err),
            LayerError::DekuError(ref err) => write!(f, "Deku Error: {}", err),
            LayerError::Checksum(ref err) => write!(f, "Checksum Error: {}", err),
            LayerError::IntError(ref err) => write!(f, "Int Error: {}", err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LayerError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(self)
    }
}
