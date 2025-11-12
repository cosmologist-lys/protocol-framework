pub mod comm_error;
pub mod hex_digest_error;
pub mod hex_error;

use thiserror::Error;

use crate::error::{
    comm_error::CommError, hex_digest_error::HexDigestError, hex_error::HexError,
};

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error(transparent)]
    HexDigestError(#[from] HexDigestError), // CrcError 自动转换为 ProtocolError::Crc

    #[error(transparent)]
    HexError(#[from] HexError),

    #[error(transparent)]
    CommError(#[from] CommError),

    #[error("protocol-core Error: {0}")]
    CommonError(String),

    #[error(
        "protocol-core crc compare error , crc in hex : {ori_crc} , calculated crc : {calc_crc}"
    )]
    CrcError { ori_crc: u16, calc_crc: u16 },

    #[error("AES Crypto Error: {0}")]
    CryptoError(String),

    #[error("Invalid AES key length. Expected 16, 24, or 32 bytes, but got {actual}.")]
    InvalidKeyLength { actual: usize },

    #[error("Unsupported AES mode: {0}")]
    UnsupportedMode(String),

    #[error(
        "Input data is too short. Needed at least {needed} bytes, but only {available} remain."
    )]
    InputTooShort { needed: usize, available: usize },

    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}
