use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Add error here")]
    AddErrorHere,
    #[error("Threshold < 2")]
    InsufficientThreshold,
}
