use std::error;
use std::fmt;

pub mod ether;

pub trait Layer {
    type LayerType: Sized;
    fn from_bytes(bytes: &[u8]) -> Result<(Self::LayerType, &[u8]), LayerError>;
}

#[derive(Debug, PartialEq)]
pub enum LayerError {
    Parse(String),
    Unexpected(String),
}

impl fmt::Display for LayerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LayerError::Parse(ref err) => write!(f, "Parse error: {}", err),
            LayerError::Unexpected(ref err) => write!(f, "Unexpected error: {}", err),
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

impl From<::nom::Err<(&[u8], ::nom::error::ErrorKind)>> for LayerError {
    fn from(err: ::nom::Err<(&[u8], ::nom::error::ErrorKind)>) -> Self {
        let msg = match err {
            ::nom::Err::Incomplete(needed) => match needed {
                ::nom::Needed::Size(v) => format!(
                    "incomplete data, parser step failed. Step needs {} bytes",
                    v
                ),
                ::nom::Needed::Unknown => format!("incomplete data"),
            },
            ::nom::Err::Error(e) | ::nom::Err::Failure(e) => {
                format!("parsing error has occurred: {}", e.1.description())
            }
        };

        LayerError::Parse(msg)
    }
}

impl From<::nom::Err<(&str, ::nom::error::ErrorKind)>> for LayerError {
    fn from(err: ::nom::Err<(&str, ::nom::error::ErrorKind)>) -> Self {
        let msg = match err {
            ::nom::Err::Incomplete(needed) => match needed {
                ::nom::Needed::Size(v) => format!(
                    "incomplete data, parser step failed. Step needs {} characters",
                    v
                ),
                ::nom::Needed::Unknown => format!("incomplete data"),
            },
            ::nom::Err::Error(e) | ::nom::Err::Failure(e) => {
                format!("parsing error has occurred: {}", e.1.description())
            }
        };

        LayerError::Parse(msg)
    }
}
