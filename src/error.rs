use thiserror::Error;

/// Errors that can occur when using the SSKR library.
#[derive(Debug, Error)]
pub enum SSKRError {
    #[error("When combining shares, the provided shares contained a duplicate member index")]
    DuplicateMemberIndex,

    #[error("When creating a split spec, the group count is invalid")]
    GroupCountInvalid,

    #[error("SSKR group threshold is invalid")]
    GroupThresholdInvalid,

    #[error("SSKR member count is invalid")]
    MemberCountInvalid,

    #[error("SSKR member threshold is invalid")]
    MemberThresholdInvalid,

    #[error("SSKR shares did not contain enough groups")]
    NotEnoughGroups,

    #[error("SSKR secret is not of even length")]
    SecretLengthNotEven,

    #[error("SSKR secret is too long")]
    SecretTooLong,

    #[error("SSKR secret is too short")]
    SecretTooShort,

    #[error("SSKR shares did not contain enough serialized bytes")]
    ShareLengthInvalid,

    #[error("SSKR shares contained invalid reserved bits")]
    ShareReservedBitsInvalid,

    #[error("SSKR shares were empty")]
    SharesEmpty,

    #[error("SSKR shares were invalid")]
    ShareSetInvalid,

    #[error("SSKR Shamir error: {0}")]
    ShamirError(bc_shamir::Error),
}

impl From<bc_shamir::Error> for SSKRError {
    fn from(err: bc_shamir::Error) -> Self {
        SSKRError::ShamirError(err)
    }
}
