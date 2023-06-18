/// Errors that can occur when using the SSKR library.
#[derive(Debug)]
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
        let s = match *self {
            Error::DuplicateMemberIndex => "Duplicate member index".to_string(),
            Error::GroupCountInvalid => "Invalid group count".to_string(),
            Error::GroupThresholdInvalid => "Invalid group threshold".to_string(),
            Error::MemberCountInvalid => "Not enough shares".to_string(),
            Error::MemberThresholdInvalid => "Invalid member threshold".to_string(),
            Error::NotEnoughGroups => "Not enough groups".to_string(),
            Error::SecretLengthNotEven => "Secret is not of even length".to_string(),
            Error::SecretTooLong => "Secret is too long".to_string(),
            Error::SecretTooShort => "Secret is too short".to_string(),
            Error::ShareLengthInvalid => "Not enough serialized bytes".to_string(),
            Error::ShareReservedBitsInvalid => "Invalid reserved bits".to_string(),
            Error::SharesEmpty => "Empty share set".to_string(),
            Error::ShareSetInvalid => "Invalid share set".to_string(),
            Error::ShamirError(ref e) => format!("{}", e),
        };
        f.write_str(&s)
    }
}

impl std::error::Error for Error {}
