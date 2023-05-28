use crate::Secret;

#[derive(Debug, Clone)]
pub struct SSKRShare {
    identifier: u16,
    group_index: usize,
    group_threshold: usize,
    group_count: usize,
    member_index: usize,
    member_threshold: usize,
    value: Secret,
}

impl SSKRShare {
    pub fn new(
        identifier: u16,
        group_index: usize,
        group_threshold: usize,
        group_count: usize,
        member_index: usize,
        member_threshold: usize,
        value: Secret,
    ) -> Self {
        Self {
            identifier,
            group_index,
            group_threshold,
            group_count,
            member_index,
            member_threshold,
            value,
        }
    }

    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    pub fn group_index(&self) -> usize {
        self.group_index
    }

    pub fn group_threshold(&self) -> usize {
        self.group_threshold
    }

    pub fn group_count(&self) -> usize {
        self.group_count
    }

    pub fn member_index(&self) -> usize {
        self.member_index
    }

    pub fn member_threshold(&self) -> usize {
        self.member_threshold
    }

    pub fn value(&self) -> &Secret {
        &self.value
    }
}
