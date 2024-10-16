use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum DKGError {
    #[error("Error creating session")]
    ErrorCreatingSession,
    #[error("Error fetching session: {:?}", e)]
    ErrorFetchingSession { e: String },
    #[error("Error posting message: {}", e)]
    ErrorPostingMessage { e: String },
    #[error("Error posting confirmation: {}", e)]
    ErrorPostingConfirmation { e: String },
    #[error("Message posting phase has been completed")]
    MessagePostingCompleted,
    #[error("Confirmation posting phase has been completed")]
    ConfirmationPostingCompleted,
}

#[derive(Error, Debug, PartialEq)]
pub enum SigningError {
    #[error("DKG not complete yet")]
    DKGPending,
    #[error("Error creating signing session")]
    ErrorCreatingSession,
    #[error("Error fetching session")]
    ErrorFetchingSession,
    #[error("Error posting partial signatures")]
    ErrorPostingPartialSignatures,
}

#[derive(Error, Debug, PartialEq)]
pub enum VerificationError {
    #[error("DKG not complete yet")]
    DKGPending,
    #[error("Error fetching session")]
    ErrorFetchingSession,
    #[error("Failed to aggregate signatures: {}", e)]
    ErrorAggregatingSignatures { e: String },
}
