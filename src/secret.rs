use crate::{Error, MIN_SECRET_LEN, MAX_SECRET_LEN};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(data: Vec<u8>) -> Result<Self, Error> {
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
        Ok(Self(data))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
