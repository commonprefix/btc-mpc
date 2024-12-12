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
    #[error("DKG not complete yet")]
    DKGPending,
}

#[derive(Error, Debug, PartialEq)]
pub enum SigningError {
    #[error("Error creating signing session")]
    ErrorCreatingSession,
    #[error("Error fetching session")]
    ErrorFetchingSession,
    #[error("Signing session not in commit phase")]
    NotInCommitPhase,
    #[error("Signing session not in signing phase")]
    NotInSigningPhase,
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
