// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use thiserror::Error;

#[derive(Debug, Error)]
/// Distributed key generation errors
pub enum KeygenError {
    /// error while serializing or deserializing or invalid message data length
    #[error(
        "Error while deserializing message or invalid message data length"
    )]
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

    /// Big S value mismatch
    #[error("Big S value mismatch")]
    BigSMismatch,

    #[error("PPRF error {0}")]
    /// PPRF error
    PPRFError(&'static str),

    #[error("Missing message")]
    MissingMessage,

    #[error("Invalid key refresh")]
    /// Invalid key refresh
    InvalidKeyRefresh,
}

/// Distributed key generation errors
#[derive(Error, Debug)]
pub enum SignError {
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

    #[error("Missing message")]
    MissingMessage,

    /// Abort the protocol and ban the party
    #[error("Abort the protocol and ban the party {0}")]
    AbortProtocolAndBanParty(u8),
}

/// Distributed key generation errors (OT variant)
#[derive(Error, Debug)]
pub enum SignOTVariantError {
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

    #[error("Missing message")]
    MissingMessage,

    /// Invalid RVOLE
    #[error("Invalid RVOLE")]
    Rvole,
}

impl From<SignError> for SignOTVariantError {
    fn from(err: SignError) -> Self {
        match err {
            SignError::InvalidCommitment => {
                SignOTVariantError::InvalidCommitment
            }
            SignError::InvalidDigest => SignOTVariantError::InvalidDigest,
            SignError::InvalidFinalSessionID => {
                SignOTVariantError::InvalidFinalSessionID
            }
            SignError::FailedCheck(e) => SignOTVariantError::FailedCheck(e),
            SignError::K256Error(e) => SignOTVariantError::K256Error(e),
            SignError::MissingMessage => SignOTVariantError::MissingMessage,
            SignError::AbortProtocolAndBanParty(_) => {
                SignOTVariantError::Rvole
            }
        }
    }
}
