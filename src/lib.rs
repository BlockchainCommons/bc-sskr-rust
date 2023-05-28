pub const MIN_SECRET_LEN: usize = bc_shamir::MIN_SECRET_LEN;
pub const MAX_SECRET_LEN: usize = bc_shamir::MAX_SECRET_LEN;
pub const MAX_SHARE_COUNT: usize = bc_shamir::MAX_SHARE_COUNT;
pub const METADATA_LENGTH_BYTES: usize = 5;
pub const MIN_SERIALIZE_LENGTH_BYTES: usize = METADATA_LENGTH_BYTES + MIN_SECRET_LEN;

mod encoding;
pub use encoding::{sskr_generate, sskr_combine};

mod share;
pub use share::SSKRShare;

mod secret;
pub use secret::Secret;

mod spec;
pub use spec::{Spec, GroupSpec};

mod error;
pub use error::Error;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}
