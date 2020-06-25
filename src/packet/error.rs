use crate::layer::LayerError;

#[derive(Debug, PartialEq)]
pub enum PacketError {
    LayerError(LayerError),
}

impl From<LayerError> for PacketError {
    fn from(e: LayerError) -> Self {
        PacketError::LayerError(e)
    }
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            PacketError::LayerError(ref err) => write!(f, "Layer error: {}", err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PacketError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(self)
    }
}
