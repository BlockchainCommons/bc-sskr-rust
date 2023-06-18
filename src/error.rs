/// Errors that can occur when using the SSKR library.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error {
    /// When combining shares, the provided shares contained a duplicate member index.
    DuplicateMemberIndex,

    /// When creating a split spec, the group count is invalid.
    GroupCountInvalid,

    /// When creating a split spec, the group threshold is invalid.
    GroupThresholdInvalid,

    /// When creating a group spec, the member count is invalid.
    MemberCountInvalid,

    /// When creating a group spec, the member threshold is invalid.
    MemberThresholdInvalid,

    /// When combining shares, the provided shares did not contain enough groups.
    NotEnoughGroups,

    /// When creating a secret, the secret is not of even length.
    SecretLengthNotEven,

    /// When creating a secret, the secret is too long.
    SecretTooLong,

    /// When creating a secret, the secret is too short.
    SecretTooShort,

    /// When combining shares, the provided shares did not contain enough serialized bytes.
    ShareLengthInvalid,

    /// When combining shares, the provided shares contained invalid reserved bits.
    ShareReservedBitsInvalid,

    /// When combining shares, the provided shares were empty.
    SharesEmpty,

    /// When combining shares, the provided shares were invalid.
    ShareSetInvalid,

    /// An error returned from the `bc-shamir` crate.
    ShamirError(bc_shamir::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::DuplicateMemberIndex => write!(f, "Duplicate member index"),
            Error::GroupCountInvalid => write!(f, "Invalid group count"),
            Error::GroupThresholdInvalid => write!(f, "Invalid group threshold"),
            Error::MemberCountInvalid => write!(f, "Not enough shares"),
            Error::MemberThresholdInvalid => write!(f, "Invalid member threshold"),
            Error::NotEnoughGroups => write!(f, "Not enough groups"),
            Error::SecretLengthNotEven => write!(f, "Secret is not of even length"),
            Error::SecretTooLong => write!(f, "Secret is too long"),
            Error::SecretTooShort => write!(f, "Secret is too short"),
            Error::ShareLengthInvalid => write!(f, "Not enough serialized bytes"),
            Error::ShareReservedBitsInvalid => write!(f, "Invalid reserved bits"),
            Error::SharesEmpty => write!(f, "Empty share set"),
            Error::ShareSetInvalid => write!(f, "Invalid share set"),
            Error::ShamirError(ref e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}
