use thiserror::Error;

#[derive(Debug, Error)]
/// Distributed key generation errors
pub enum KeygenError {
    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message or invalid message data length")]
    InvalidMessage,

    /// Invalid commitment hash
    #[error("Invalid commitment hash")]
    InvalidCommitmentHash,

    #[error("Invalid DLog proof")]
    /// Invalid DLog proof
    InvalidDLogProof,

    #[error("Invalid Polynomial Point")]
    /// Invalid Polynomial Point
    InvalidPolynomialPoint,

    #[error("Invalid key refresh")]
    /// Invalid key refresh
    InvalidKeyRefresh,

    /// Not unique x_i values
    #[error("Not unique x_i values")]
    NotUniqueXiValues,

    /// Big F vec mismatch
    #[error("Big F vec mismatch")]
    BigFVecMismatch,

    /// Failed felman verify
    #[error("Failed felman verify")]
    FailedFelmanVerify,

    /// Public key mismatch between the message and the party
    #[error("Public key mismatch between the message and the party")]
    PublicKeyMismatch,

    ///
    #[error("DKG failed before generating PK")]
    NoPublicKey,

    /// Big S value mismatch
    #[error("Big S value mismatch")]
    BigSMismatch,

    #[error("PPRF error")]
    /// PPRF error
    PPRFError(&'static str),

    /// We have internal state as pairs of (PairtyID, datum)
    /// This error is returned when we unable to find a datum
    /// corresponding to the party-id
    #[error("Missing piece of state")]
    InvalidParty,

    ///
    #[error("Missing message")]
    MissingMessage,

    /// We can't a send message
    #[error("Send message")]
    SendMessage,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(u8),
}

/// Distributed key generation errors
#[derive(Error, Debug)]
pub enum SignError {
    /// Mta error
    #[error("MTA error: {0}")]
    MtaError(&'static str),

    /// Invalid commitment
    #[error("Invalid commitment")]
    InvalidCommitment,

    /// Invalid digest
    #[error("Invalid digest")]
    InvalidDigest,

    /// Invalid final_session_id
    #[error("Invalid final_session_id")]
    InvalidFinalSessionID,

    #[error("Failed check: {0}")]
    /// Failed check
    FailedCheck(&'static str),

    /// k256 error
    #[error("k256 error: {0}")]
    K256Error(#[from] k256::ecdsa::Error),

    /// Invalid message format
    #[error("invalid message format")]
    InvalidMessage,

    /// Invalid party
    #[error("Bad Party")]
    BadParty,

    ///
    #[error("Missing message")]
    MissingMessage,

    /// We can't a send message
    #[error("Send message")]
    SendMessage,

    /// Some party decided to not participate in the protocol.
    #[error("Abort protocol by party {0}")]
    AbortProtocol(u8),

    /// Abort the protocol and ban the party
    #[error("Abort the protocol and ban the party {0}")]
    AbortProtocolAndBanParty(u8),
}
