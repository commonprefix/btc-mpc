use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum DKGError {
    #[error("DKG not complete yet")]
    DKGPending,
    #[error("Error creating session")]
    ErrorCreatingSession,
    #[error("Error fetching session")]
    ErrorFetchingSession,
    #[error("Error posting message")]
    ErrorPostingMessage,
    #[error("Error posting confirmation")]
    ErrorPostingConfirmation,
    #[error("Message posting phase has been completed")]
    MessagePostingCompleted,
    #[error("Confirmation posting phase has been completed")]
    ConfirmationPostingCompleted,
}
