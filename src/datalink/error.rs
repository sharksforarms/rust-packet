use crate::packet::PacketError;

#[derive(Debug)]
pub enum DataLinkError {
    PacketError(PacketError),
    InterfaceNotFound,
    UnhandledInterfaceType,
    IoError(std::io::Error),
    BufferError,
}

impl From<PacketError> for DataLinkError {
    fn from(e: PacketError) -> Self {
        DataLinkError::PacketError(e)
    }
}

impl From<std::io::Error> for DataLinkError {
    fn from(e: std::io::Error) -> Self {
        DataLinkError::IoError(e)
    }
}

impl core::fmt::Display for DataLinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            DataLinkError::PacketError(ref err) => write!(f, "Layer error: {}", err),
            DataLinkError::InterfaceNotFound => write!(f, "Interface not found"),
            DataLinkError::UnhandledInterfaceType => write!(f, "Unhandled interface type"),
            DataLinkError::IoError(ref err) => write!(f, "IO error: {}", err),
            DataLinkError::BufferError => write!(f, "Buffer error"),
        }
    }
}

impl std::error::Error for DataLinkError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(self)
    }
}
