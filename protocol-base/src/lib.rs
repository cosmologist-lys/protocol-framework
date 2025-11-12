pub mod definitions;
pub mod error;

pub use error::ProtocolError;
pub type ProtocolResult<T> = Result<T, ProtocolError>;
pub use definitions::defi::CrcType;
