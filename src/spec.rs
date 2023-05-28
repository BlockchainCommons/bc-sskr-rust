use bc_shamir::MAX_SHARE_COUNT;

use crate::Error;

#[derive(Debug, PartialEq)]
pub struct Spec {
    group_threshold: usize,
    groups: Vec<GroupSpec>,
}

impl Spec {
    pub fn new(group_threshold: usize, groups: Vec<GroupSpec>) -> Result<Self, Error> {
        if group_threshold == 0 {
            return Err(Error::NotEnoughShares);
        }
        if group_threshold > groups.len() {
            return Err(Error::InvalidGroupThreshold);
        }
        if groups.len() > MAX_SHARE_COUNT {
            return Err(Error::TooManyShares);
        }
        Ok(Self {
            group_threshold,
            groups,
        })
    }

    pub fn group_threshold(&self) -> usize {
        self.group_threshold
    }

    pub fn groups(&self) -> &[GroupSpec] {
        &self.groups
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub fn share_count(&self) -> usize {
        self.groups.iter().map(|g| g.member_count()).sum()
    }
}

#[derive(Debug, PartialEq)]
pub struct GroupSpec {
    member_threshold: usize,
    member_count: usize,
}

impl GroupSpec {
    pub fn new(member_threshold: usize, member_count: usize) -> Result<Self, Error> {
        if member_count == 0 {
            return Err(Error::NotEnoughShares);
        }
        if member_count > MAX_SHARE_COUNT {
            return Err(Error::TooManyShares);
        }
        if member_threshold > member_count {
            return Err(Error::InvalidGroupThreshold);
        }
        Ok(Self { member_threshold, member_count })
    }

    pub fn member_threshold(&self) -> usize {
        self.member_threshold
    }

    pub fn member_count(&self) -> usize {
        self.member_count
    }
}
