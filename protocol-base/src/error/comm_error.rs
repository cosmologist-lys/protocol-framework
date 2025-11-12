use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommError {
    #[error("Unknown msg-type: {0}")]
    UnknownMsgType(String),
}
