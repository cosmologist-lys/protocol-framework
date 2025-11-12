use thiserror::Error;

#[derive(Error, Debug)]
pub enum HexDigestError {
    #[error("CRC checksum mismatch. Expected {expected}, but got {actual}.")]
    CrcMismatch { expected: u16, actual: u16 },

    #[error("Invalid frame head")]
    InvalidHead,

    #[error("Invalid frame tail")]
    InvalidTail,

    #[error("Unknown or unsupported Data Object ID: {0}")]
    UnknownCommandId(&'static str),

    #[error("crc calculation error")]
    CRCCalculateError,
}
