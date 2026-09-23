use core::fmt;

/// Errors produced by the DKG/VUF protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid parameters, e.g. `t == 0`, `t > n`, or mismatched configs.
    InvalidConfig,
    /// The dealing is invalid: zero secrets or a polynomial of a wrong degree.
    InvalidDealing,
    /// A dealer's contribution receipt contains an invalid signature.
    InvalidReceiptSignature,
    /// The receipts don't add up to the aggregated secret sharing.
    InconsistentTranscript,
    /// The secret sharing failed public verification.
    InvalidSharing,
    /// Fewer than `t_dkg` authorized dealers contributed.
    NotEnoughContributions,
    /// An MSM failed (bases/scalars length mismatch).
    MsmFailed,
    /// A signature from an unknown signer.
    UnknownSigner,
    /// A duplicate signature from the same signer within one session.
    DuplicateSignature,
    /// A BLS signature doesn't verify.
    InvalidSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::InvalidConfig => "invalid configuration",
            Error::InvalidDealing => "invalid dealing",
            Error::InvalidReceiptSignature => "invalid receipt signature",
            Error::InconsistentTranscript => "inconsistent transcript",
            Error::InvalidSharing => "invalid secret sharing",
            Error::NotEnoughContributions => "not enough dealer contributions",
            Error::MsmFailed => "msm failed",
            Error::UnknownSigner => "unknown signer",
            Error::DuplicateSignature => "duplicate signature",
            Error::InvalidSignature => "invalid signature",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
