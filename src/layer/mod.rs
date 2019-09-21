use std::error;
use std::fmt;

pub mod ether;
pub mod ip;

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

macro_rules! nom_to_layererr {
    ($typ:ty) => {
        impl From<::nom::Err<($typ, ::nom::error::ErrorKind)>> for LayerError {
            fn from(err: ::nom::Err<($typ, ::nom::error::ErrorKind)>) -> Self {
                let msg = match err {
                    ::nom::Err::Incomplete(needed) => match needed {
                        ::nom::Needed::Size(_v) => format!("incomplete data, needs more"),
                        ::nom::Needed::Unknown => format!("incomplete data"),
                    },
                    ::nom::Err::Error(e) | ::nom::Err::Failure(e) => {
                        format!("parsing error has occurred: {}", e.1.description())
                    }
                };

                LayerError::Parse(msg)
            }
        }
    };
}

nom_to_layererr!(&str);
nom_to_layererr!(&[u8]);
nom_to_layererr!((&[u8], usize));
