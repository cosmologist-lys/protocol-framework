use thiserror::Error;

#[derive(Error, Debug)]
pub enum HexError {
    #[error("input {0} is not a valid hex string")]
    NotHex(String),

    #[error(
        "Invalid hex byte length for float conversion. Expected {expected} bytes, but got {actual}."
    )]
    InvalidFloatLength { expected: usize, actual: usize },

    #[error(
        "Invalid hex byte length for float/double conversion. Expected 4 or 8 bytes, but got {actual}."
    )]
    InvalidFloatLengthEither { actual: usize },

    #[error("Failed to parse hex string for {context}: {reason}")]
    HexParseError {
        context: &'static str,
        reason: String,
    },

    #[error(
        "Hex string for {context} is too long. Max {max_chars} chars allowed, but got {actual_chars}."
    )]
    HexLengthError {
        context: &'static str,
        max_chars: usize,
        actual_chars: usize,
    },

    #[error("Expected bit length must be positive, but got {bits}.")]
    BinaryLengthErrorNegative { bits: usize },

    #[error("Failed to parse binary string for {context}: {reason}")]
    BinaryParseError {
        context: &'static str,
        reason: String,
    },

    #[error("Invalid slice range. Start: {start}, End: {end}. Reason: {reason}")]
    InvalidRange {
        start: i64,
        end: i64,
        reason: String,
    },
    #[error("Input string is not valid ASCII (hex): {0}")]
    NotAscii(String),

    #[error("Input string is not valid BCD: {0}")]
    NotBcd(String),

    #[error("Input string is not a valid machine code (Hex, BCD, or ASCII-Hex): {0}")]
    NotMachineCode(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error(
        "Padding error: original byte length ({original_len}) exceeds target byte length ({target_len})."
    )]
    PaddingError {
        original_len: usize,
        target_len: usize,
    },
}
