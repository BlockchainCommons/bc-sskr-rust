pub const MIN_SECRET_LEN: usize = bc_shamir::MIN_SECRET_LEN;
pub const MAX_SECRET_LEN: usize = bc_shamir::MAX_SECRET_LEN;
pub const MAX_SHARE_COUNT: usize = bc_shamir::MAX_SHARE_COUNT;
pub const METADATA_LENGTH_BYTES: usize = 5;
pub const MIN_SERIALIZE_LENGTH_BYTES: usize = METADATA_LENGTH_BYTES + MIN_SECRET_LEN;

mod encoding;
pub use encoding::{sskr_generate, sskr_generate_using, sskr_combine};

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

#[cfg(test)]
mod tests {
    use super::*;
    use bc_crypto::RandomNumberGenerator;
    use hex_literal::hex;

    struct FakeRandomNumberGenerator;

    impl RandomNumberGenerator for FakeRandomNumberGenerator {
        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn random_data(&mut self, size: usize) -> Vec<u8> {
            let mut b = vec![0u8; size];
            self.fill_random_data(&mut b);
            b
        }

        fn fill_random_data(&mut self, data: &mut [u8]) {
            let mut b = 0u8;
            data.iter_mut().for_each(|x| {
                *x = b;
                b = b.wrapping_add(17);
            });
        }
    }

    #[test]
    fn test_split_3_5() {
        let mut rng = FakeRandomNumberGenerator;
        let secret = Secret::new(hex!("0ff784df000c4380a5ed683f7e6e3dcf")).unwrap();
        let group = GroupSpec::new(3, 5).unwrap();
        let spec = Spec::new(1, vec![group]).unwrap();
        let shares = sskr_generate_using(&spec, &secret, &mut rng).unwrap();
        let flattened_shares = shares.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(flattened_shares.len(), 5);
        for share in &flattened_shares {
            assert_eq!(share.len(), METADATA_LENGTH_BYTES + secret.len());
            println!("share: {}", hex::encode(share));
        }

        let recovered_share_indexes = vec![1, 2, 4];
        let recovered_shares = recovered_share_indexes.iter().map(|index| flattened_shares[*index].clone()).collect::<Vec<_>>();
        let recovered_secret = sskr_combine(&recovered_shares).unwrap();
        assert_eq!(recovered_secret, secret);
    }
}