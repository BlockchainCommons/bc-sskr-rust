use crate::{Error, Result, MIN_SECRET_LEN, MAX_SECRET_LEN};

/// A secret to be split into shares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Creates a new `Secret` instance with the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - The secret data to be split into shares.
    ///
    /// # Errors
    ///
    /// Returns an error if the length of the secret is less than `MIN_SECRET_LEN`, greater than `MAX_SECRET_LEN`,
    /// or not even.
    pub fn new<T>(data: T) -> Result<Self>
    where
        T: AsRef<[u8]>,
    {
        let data = data.as_ref();
        let len = data.len();
        if len < MIN_SECRET_LEN {
            return Err(Error::SecretTooShort);
        }
        if len > MAX_SECRET_LEN {
            return Err(Error::SecretTooLong);
        }
        if len & 1 != 0 {
            return Err(Error::SecretLengthNotEven);
        }
        Ok(Self(data.to_vec()))
    }

    /// Returns the length of the secret.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a reference to the secret data.
    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Secret {
    /// Returns a reference to the secret data.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
