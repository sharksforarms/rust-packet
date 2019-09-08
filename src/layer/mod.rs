use std::error;
use std::fmt;

mod ether;
mod noms;

trait Layer {
    type LayerType: Sized;
    fn from_bytes(bytes: &[u8]) -> Result<Self::LayerType, LayerError>;
}

#[derive(Debug, PartialEq)]
pub enum LayerError {
    Parse(String),
}

impl fmt::Display for LayerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LayerError::Parse(ref err) => write!(f, "Parse error: {}", err),
        }
    }
}

impl error::Error for LayerError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            LayerError::Parse(ref err) => Some(self),
        }
    }
}
