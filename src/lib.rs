#![doc(html_root_url = "https://docs.rs/sskr/0.5.0")]
#![warn(rust_2018_idioms)]

//! # Introduction
//!
//! Sharded Secret Key Reconstruction (SSKR) is a protocol for splitting a *secret* into a set of *shares* across one or more *groups*, such that the secret can be reconstructed from any combination of shares totaling or exceeding a *threshold* number of shares within each group and across all groups. SSKR is a generalization of Shamir's Secret Sharing (SSS) that allows for multiple groups and multiple thresholds.
//!
//! # Getting Started
//!
//! ```toml
//! [dependencies]
//! sskr = "0.5.0"
//! ```
//!
//! # Example
//!
//! ```
//! # use sskr::{Secret, GroupSpec, Spec, sskr_generate, sskr_combine};
//! let secret_string = b"my secret belongs to me.";
//! let secret = Secret::new(secret_string).unwrap();
//!
//! // Split the secret into 2 groups, the first requiring 2 of three shares
//! // and the second requiring 3 of 5 shares. A group threshold of 2 is
//! // specified, meaning that a quorum from both groups are necessary to
//! // reconstruct the secret.
//!
//! let group1 = GroupSpec::new(2, 3).unwrap();
//! let group2 = GroupSpec::new(3, 5).unwrap();
//! let spec = Spec::new(2, vec![group1, group2]).unwrap();
//!
//! // The result is a vector of groups, each containing a vector of shares,
//! // each of which is a vector of bytes.
//! let shares: Vec<Vec<Vec<u8>>> = sskr_generate(&spec, &secret).unwrap();
//!
//! assert_eq!(shares.len(), 2);
//! assert_eq!(shares[0].len(), 3);
//! assert_eq!(shares[1].len(), 5);
//!
//! // Now, recover the secret from a quorum of shares from each group.
//!
//! let recovered_shares = vec![
//!     // Two shares from the first group.
//!     shares[0][0].clone(),
//!     shares[0][2].clone(),
//!
//!     // Three shares from the second group.
//!     shares[1][0].clone(),
//!     shares[1][1].clone(),
//!     shares[1][4].clone(),
//! ];
//!
//! let recovered_secret = sskr_combine(&recovered_shares).unwrap();
//! assert_eq!(recovered_secret, secret);
//! ```

/// The minimum length of a secret.
pub const MIN_SECRET_LEN: usize = bc_shamir::MIN_SECRET_LEN;

/// The maximum length of a secret.
pub const MAX_SECRET_LEN: usize = bc_shamir::MAX_SECRET_LEN;

/// The maximum number of shares that can be generated from a secret.
pub const MAX_SHARE_COUNT: usize = bc_shamir::MAX_SHARE_COUNT;

/// The maximum number of groups in a split.
pub const MAX_GROUPS_COUNT: usize = MAX_SHARE_COUNT;

/// The number of bytes used to encode the metadata for a share.
pub const METADATA_SIZE_BYTES: usize = 5;

/// The minimum number of bytes required to encode a share.
pub const MIN_SERIALIZE_SIZE_BYTES: usize = METADATA_SIZE_BYTES + MIN_SECRET_LEN;

mod encoding;
pub use encoding::{ sskr_generate, sskr_generate_using, sskr_combine };

mod share;

mod secret;
pub use secret::Secret;

mod spec;
pub use spec::{ Spec, GroupSpec };

mod error;
pub use error::SSKRError;

#[cfg(test)]
mod tests {
    use super::*;
    use bc_rand::{rng_next_in_closed_range, RandomNumberGenerator};
    use hex_literal::hex;
    use rand::{CryptoRng, RngCore};

    #[derive(Debug)]
    struct FakeRandomNumberGenerator;

    impl RngCore for FakeRandomNumberGenerator {
        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            unimplemented!()
        }

        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand::Error> {
            unimplemented!()
        }
    }

    // Testing purposes only!
    impl CryptoRng for FakeRandomNumberGenerator {}

    impl RandomNumberGenerator for FakeRandomNumberGenerator {
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
            assert_eq!(share.len(), METADATA_SIZE_BYTES + secret.len());
            println!("share: {}", hex::encode(share));
        }

        let recovered_share_indexes = [1, 2, 4];
        let recovered_shares = recovered_share_indexes
            .iter()
            .map(|index| flattened_shares[*index].clone())
            .collect::<Vec<_>>();
        let recovered_secret = sskr_combine(&recovered_shares).unwrap();
        assert_eq!(recovered_secret, secret);
    }

    #[test]
    fn test_split_2_7() {
        let mut rng = FakeRandomNumberGenerator;
        let secret = Secret::new(
            hex!("204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a")
        ).unwrap();
        let group = GroupSpec::new(2, 7).unwrap();
        let spec = Spec::new(1, vec![group]).unwrap();
        let shares = sskr_generate_using(&spec, &secret, &mut rng).unwrap();
        // println!("shares: {:?}", shares);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].len(), 7);
        let flattened_shares = shares.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(flattened_shares.len(), 7);
        for share in &flattened_shares {
            assert_eq!(share.len(), METADATA_SIZE_BYTES + secret.len());
            // println!("share: {}", hex::encode(share));
        }

        let recovered_share_indexes = [3, 4];
        let recovered_shares = recovered_share_indexes
            .iter()
            .map(|index| flattened_shares[*index].clone())
            .collect::<Vec<_>>();
        let recovered_secret = sskr_combine(&recovered_shares).unwrap();
        assert_eq!(recovered_secret, secret);
    }

    #[test]
    fn test_split_2_3_2_3() {
        let mut rng = FakeRandomNumberGenerator;
        let secret = Secret::new(
            hex!("204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a")
        ).unwrap();
        let group1 = GroupSpec::new(2, 3).unwrap();
        let group2 = GroupSpec::new(2, 3).unwrap();
        let spec = Spec::new(2, vec![group1, group2]).unwrap();
        let shares = sskr_generate_using(&spec, &secret, &mut rng).unwrap();
        // println!("shares: {:?}", shares);
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].len(), 3);
        assert_eq!(shares[1].len(), 3);
        let flattened_shares = shares.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(flattened_shares.len(), 6);
        for share in &flattened_shares {
            assert_eq!(share.len(), METADATA_SIZE_BYTES + secret.len());
            // println!("share: {}", hex::encode(share));
        }

        let recovered_share_indexes = [0, 1, 3, 5];
        let recovered_shares = recovered_share_indexes
            .iter()
            .map(|index| flattened_shares[*index].clone())
            .collect::<Vec<_>>();
        let recovered_secret = sskr_combine(&recovered_shares).unwrap();
        assert_eq!(recovered_secret, secret);
    }

    fn fisher_yates_shuffle<T>(slice: &mut [T], rng: &mut impl RandomNumberGenerator) {
        let mut i = slice.len();
        while i > 1 {
            i -= 1;
            let j = rng_next_in_closed_range(rng, &(0..=i));
            slice.swap(i, j);
        }
    }

    #[test]
    fn test_shuffle() {
        let mut rng = bc_rand::make_fake_random_number_generator();
        let mut v = (0..100).collect::<Vec<_>>();
        fisher_yates_shuffle(&mut v, &mut rng);
        assert_eq!(v.len(), 100);
        assert_eq!(
            v,
            [
                79, 70, 40, 53, 25, 30, 31, 88, 10, 1, 45, 54, 81, 58, 55, 59, 69, 78, 65, 47, 75, 61,
                0, 72, 20, 9, 80, 13, 73, 11, 60, 56, 19, 42, 33, 12, 36, 38, 6, 35, 68, 77, 50, 18,
                97, 49, 98, 85, 89, 91, 15, 71, 99, 67, 84, 23, 64, 14, 57, 48, 62, 29, 28, 94, 44, 8,
                66, 34, 43, 21, 63, 16, 92, 95, 27, 51, 26, 86, 22, 41, 93, 82, 7, 87, 74, 37, 46, 3,
                96, 24, 90, 39, 32, 17, 76, 4, 83, 2, 52, 5,
            ]
        );
    }

    struct RecoverSpec {
        secret: Secret,
        spec: Spec,
        shares: Vec<Vec<Vec<u8>>>,
        recovered_group_indexes: Vec<usize>,
        recovered_member_indexes: Vec<Vec<usize>>,
        recovered_shares: Vec<Vec<u8>>,
    }

    impl RecoverSpec {
        fn new(
            secret: Secret,
            spec: Spec,
            shares: Vec<Vec<Vec<u8>>>,
            rng: &mut impl RandomNumberGenerator
        ) -> Self {
            let mut group_indexes = (0..spec.group_count()).collect::<Vec<_>>();
            fisher_yates_shuffle(&mut group_indexes, rng);
            let recovered_group_indexes = group_indexes[..spec.group_threshold()].to_vec();
            let mut recovered_member_indexes = Vec::new();
            for group_index in &recovered_group_indexes {
                let group = &spec.groups()[*group_index];
                let mut member_indexes = (0..group.member_count()).collect::<Vec<_>>();
                fisher_yates_shuffle(&mut member_indexes, rng);
                let recovered_member_indexes_for_group =
                    member_indexes[..group.member_threshold()].to_vec();
                recovered_member_indexes.push(recovered_member_indexes_for_group);
            }

            let mut recovered_shares = Vec::new();
            for (i, recovered_group_index) in recovered_group_indexes.iter().enumerate() {
                let group_shares = &shares[*recovered_group_index];
                for recovered_member_index in &recovered_member_indexes[i] {
                    let member_share = &group_shares[*recovered_member_index];
                    recovered_shares.push(member_share.clone());
                }
            }
            fisher_yates_shuffle(&mut recovered_shares, rng);

            Self {
                secret,
                spec,
                shares,
                recovered_group_indexes,
                recovered_member_indexes,
                recovered_shares,
            }
        }

        fn print(&self) {
            println!("---");
            println!("secret: {}", hex::encode(self.secret.data()));
            println!("spec: {:?}", self.spec);
            println!("shares: {:?}", self.shares);
            println!("recovered_group_indexes: {:?}", self.recovered_group_indexes);
            println!("recovered_member_indexes: {:?}", self.recovered_member_indexes);
            println!("recovered_shares: {:?}", &self.recovered_shares);
        }

        fn recover(&self) {
            let success = match sskr_combine(&self.recovered_shares) {
                Ok(recovered_secret) => recovered_secret == self.secret,
                Err(e) => {
                    println!("error: {:?}", e);
                    false
                }
            };

            if !success {
                self.print();
                panic!();
            }
        }
    }

    fn one_fuzz_test(rng: &mut impl RandomNumberGenerator) {
        let secret_len = rng_next_in_closed_range(rng, &(MIN_SECRET_LEN..=MAX_SECRET_LEN)) & !1;
        let secret = Secret::new(rng.random_data(secret_len)).unwrap();
        let group_count = rng_next_in_closed_range(rng, &(1..=MAX_GROUPS_COUNT));
        let group_specs = (0..group_count)
            .map(|_| {
                let member_count = rng_next_in_closed_range(rng, &(1..=MAX_SHARE_COUNT));
                let member_threshold = rng_next_in_closed_range(rng, &(1..=member_count));
                GroupSpec::new(member_threshold, member_count).unwrap()
            })
            .collect::<Vec<_>>();
        let group_threshold = rng_next_in_closed_range(rng, &(1..=group_count));
        let spec = Spec::new(group_threshold, group_specs).unwrap();
        let shares = sskr_generate_using(&spec, &secret, rng).unwrap();

        let recover_spec = RecoverSpec::new(secret, spec, shares, rng);
        recover_spec.recover();
    }

    #[test]
    fn fuzz_test() {
        let mut rng = bc_rand::make_fake_random_number_generator();
        // let mut rng = bc_rand::SecureRandomNumberGenerator;
        for _ in 0..100 {
            one_fuzz_test(&mut rng);
        }
    }

    #[test]
    fn test_readme_deps() {
        version_sync::assert_markdown_deps_updated!("README.md");
    }

    #[test]
    fn test_html_root_url() {
        version_sync::assert_html_root_url_updated!("src/lib.rs");
    }

    #[test]
    fn example_encode() {
        use crate::{ Secret, GroupSpec, Spec, sskr_generate, sskr_combine };

        let secret_string = b"my secret belongs to me.";
        let secret = Secret::new(secret_string).unwrap();

        // Split the secret into 2 groups, the first requiring 2 of three shares
        // and the second requiring 3 of 5 shares. A group threshold of 2 is
        // specified, meaning that a quorum from both groups are necessary to
        // reconstruct the secret.

        let group1 = GroupSpec::new(2, 3).unwrap();
        let group2 = GroupSpec::new(3, 5).unwrap();
        let spec = Spec::new(2, vec![group1, group2]).unwrap();

        // The result is a vector of groups, each containing a vector of shares,
        // each of which is a vector of bytes.
        let shares: Vec<Vec<Vec<u8>>> = sskr_generate(&spec, &secret).unwrap();

        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].len(), 3);
        assert_eq!(shares[1].len(), 5);

        // Now, recover the secret from a quorum of shares from each group.

        let recovered_shares = vec![
            // Two shares from the first group.
            shares[0][0].clone(),
            shares[0][2].clone(),

            // Three shares from the second group.
            shares[1][0].clone(),
            shares[1][1].clone(),
            shares[1][4].clone()
        ];

        let recovered_secret = sskr_combine(&recovered_shares).unwrap();
        assert_eq!(recovered_secret, secret);
    }

    /// Test fix for [#1](https://github.com/BlockchainCommons/bc-sskr-rust/issues/1).
    #[test]
    fn example_encode_3() {
        use crate::{ SSKRError, Secret, GroupSpec, Spec, sskr_generate, sskr_combine };
        use std::str::from_utf8;

        const TEXT: &str = "my secret belongs to me.";

        fn roundtrip(m: usize, n: usize) -> Result<Secret, SSKRError> {
            let secret = Secret::new(TEXT).unwrap();
            let spec = Spec::new(1, vec![GroupSpec::new(m, n).unwrap()]).unwrap();
            let shares: Vec<Vec<Vec<u8>>> = sskr_generate(&spec, &secret).unwrap();
            sskr_combine(&shares.iter().flatten().collect::<Vec<&Vec<u8>>>())
        }

        // Good, uses a 2/3 group
        {
            let result = roundtrip(2, 3);
            assert_eq!(from_utf8(result.unwrap().data()).unwrap(), TEXT);
        }

        // Still ok, uses a 1/1 group
        {
            let result = roundtrip(1, 1);
            assert_eq!(from_utf8(result.unwrap().data()).unwrap(), TEXT);
        }

        // Fixed, uses a 1/3 group
        {
            let result = roundtrip(1, 3);
            assert_eq!(from_utf8(result.unwrap().data()).unwrap(), TEXT);
        }
    }

    /// Test fix for [seedtool-cli #6](https://github.com/BlockchainCommons/seedtool-cli-rust/issues/6).
    #[test]
    fn example_encode_4() {
        use crate::{ Secret, GroupSpec, Spec, sskr_generate, sskr_combine };
        use std::str::from_utf8;

        const TEXT: &str = "my secret belongs to me.";
        let secret = Secret::new(TEXT).unwrap();
        let spec = Spec::new(1, vec![GroupSpec::new(2, 3).unwrap(), GroupSpec::new(2, 3).unwrap()]).unwrap();
        let groupd_shares: Vec<Vec<Vec<u8>>> = sskr_generate(&spec, &secret).unwrap();
        let flattened_shares = groupd_shares.into_iter().flatten().collect::<Vec<Vec<u8>>>();
        // The group threshold is 1, but we're providing an additional share from the second group.
        // This was previously causing an error, because the second group could not be decoded.
        // The correct behavior is to ignore any group's shares that cannot be decoded.
        let recovered_share_indexes = [0, 1, 3];
        let recovered_shares = recovered_share_indexes
            .iter()
            .map(|index| flattened_shares[*index].clone())
            .collect::<Vec<Vec<u8>>>();
        let recovered_secret = sskr_combine(&recovered_shares).unwrap();
        assert_eq!(from_utf8(recovered_secret.data()).unwrap(), TEXT);
    }
}
