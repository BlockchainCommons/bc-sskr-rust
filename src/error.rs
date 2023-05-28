#[derive(Debug, PartialEq)]
pub enum Error {
    NotEnoughShares,
    TooManyShares,
    SecretTooShort,
    SecretTooLong,
    SecretLengthNotEven,
    NotEnoughSerializedBytes,
    InvalidGroupThreshold,
    InvalidReservedBits,
    InvalidMemberThreshold,
    InvalidSingletonMember,
    EmptyShareSet,
    InvalidShareSet,
    DuplicateMemberIndex,
    NotEnoughGroups,
    ShamirError(bc_shamir::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::NotEnoughShares => write!(f, "Not enough shares"),
            Error::TooManyShares => write!(f, "Too many shares"),
            Error::SecretTooLong => write!(f, "Secret is too long"),
            Error::SecretTooShort => write!(f, "Secret is too short"),
            Error::SecretLengthNotEven => write!(f, "Secret is not of even length"),
            Error::NotEnoughSerializedBytes => write!(f, "Not enough serialized bytes"),
            Error::InvalidGroupThreshold => write!(f, "Invalid group threshold"),
            Error::InvalidReservedBits => write!(f, "Invalid reserved bits"),
            Error::InvalidMemberThreshold => write!(f, "Invalid member threshold"),
            Error::InvalidSingletonMember => write!(f, "Invalid singleton member"),
            Error::EmptyShareSet => write!(f, "Empty share set"),
            Error::InvalidShareSet => write!(f, "Invalid share set"),
            Error::DuplicateMemberIndex => write!(f, "Duplicate member index"),
            Error::NotEnoughGroups => write!(f, "Not enough groups"),
            Error::ShamirError(ref e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}
