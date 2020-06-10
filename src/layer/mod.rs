use std::error;
use std::fmt;

pub mod ether;
pub mod ip;
pub mod tcp;

pub trait Layer {}

#[derive(Debug, PartialEq)]
pub enum LayerError {
    Parse(String),
    Unexpected(String),
    DekuError(String),
}

use deku::error::DekuError;

impl From<DekuError> for LayerError {
    fn from(e: DekuError) -> Self {
        LayerError::DekuError(e.to_string())
    }
}

impl fmt::Display for LayerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LayerError::Parse(ref err) => write!(f, "Parse error: {}", err),
            LayerError::Unexpected(ref err) => write!(f, "Unexpected error: {}", err),
            LayerError::DekuError(ref err) => write!(f, "Deku Error: {}", err),
        }
    }
}

impl error::Error for LayerError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            _ => Some(self),
        }
    }
}
