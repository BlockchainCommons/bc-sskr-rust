use bc_shamir::MAX_SHARE_COUNT;

use crate::SSKRError;

/// A specification for an SSKR split.
#[derive(Debug, PartialEq)]
pub struct Spec {
    group_threshold: usize,
    groups: Vec<GroupSpec>,
}

impl Spec {
    /// Creates a new `Spec` instance with the given group threshold and groups.
    ///
    /// # Arguments
    ///
    /// * `group_threshold` - The minimum number of groups required to
    ///   reconstruct the secret.
    /// * `groups` - The list of `GroupSpec` instances that define the groups
    ///   and their members.
    ///
    /// # Errors
    ///
    /// Returns an error if the group threshold is zero, if the group threshold
    /// is greater than the number of groups, or if the number of groups is
    /// greater than the maximum share count.
    pub fn new(group_threshold: usize, groups: Vec<GroupSpec>) -> Result<Self, SSKRError> {
        if group_threshold == 0 {
            return Err(SSKRError::GroupThresholdInvalid);
        }
        if group_threshold > groups.len() {
            return Err(SSKRError::GroupThresholdInvalid);
        }
        if groups.len() > MAX_SHARE_COUNT {
            return Err(SSKRError::GroupCountInvalid);
        }
        Ok(Self {
            group_threshold,
            groups,
        })
    }

    /// Returns the group threshold.
    pub fn group_threshold(&self) -> usize {
        self.group_threshold
    }

    /// Returns a slice of the group specifications.
    pub fn groups(&self) -> &[GroupSpec] {
        &self.groups
    }

    /// Returns the number of groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Returns the total number of shares across all groups.
    pub fn share_count(&self) -> usize {
        self.groups.iter().map(|g| g.member_count()).sum()
    }
}

/// A specification for a group of shares within an SSKR split.
#[derive(Debug, PartialEq)]
pub struct GroupSpec {
    member_threshold: usize,
    member_count: usize,
}

impl GroupSpec {
    /// Creates a new `GroupSpec` instance with the given member threshold and
    /// count.
    ///
    /// # Arguments
    ///
    /// * `member_threshold` - The minimum number of member shares required to
    ///   reconstruct the secret within the group.
    /// * `member_count` - The total number of member shares in the group.
    ///
    /// # Errors
    ///
    /// Returns an error if the member count is zero, if the member count is
    /// greater than the maximum share count, or if the member threshold is
    /// greater than the member count.
    pub fn new(member_threshold: usize, member_count: usize) -> Result<Self, SSKRError> {
        if member_count == 0 {
            return Err(SSKRError::MemberCountInvalid);
        }
        if member_count > MAX_SHARE_COUNT {
            return Err(SSKRError::MemberCountInvalid);
        }
        if member_threshold > member_count {
            return Err(SSKRError::MemberThresholdInvalid);
        }
        Ok(Self { member_threshold, member_count })
    }

    /// Returns the member share threshold for this group.
    pub fn member_threshold(&self) -> usize {
        self.member_threshold
    }

    /// Returns the number of member shares in this group.
    pub fn member_count(&self) -> usize {
        self.member_count
    }
}
