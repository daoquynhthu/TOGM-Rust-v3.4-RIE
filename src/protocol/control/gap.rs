//! Group Access Protocol (GAP).
//!
//! Manages group policies, member additions, and removals.
//! Compliant with TOGM Whitepaper Section 7.2 (Access Control).

use crate::protocol::ProtocolError;
use crate::protocol::group_permissions::permissions::PermissionManager;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// Operations supported by GAP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapOperation {
    /// Add a new member (requires Admin/Owner).
    AddMember { user_id: [u8; 32], role: u8 },
    /// Remove an existing member (requires Admin/Owner).
    RemoveMember { user_id: [u8; 32] },
    /// Update group policy (e.g., threshold change).
    UpdatePolicy { new_threshold: u8 },
}

/// Holds the group's membership and policy state.
pub struct GroupState {
    pub members: BTreeSet<[u8; 32]>,
    pub threshold: u8,
}

impl GroupState {
    pub fn new(initial_members: Vec<[u8; 32]>, threshold: u8) -> Self {
        let mut members = BTreeSet::new();
        for m in initial_members {
            members.insert(m);
        }
        Self { members, threshold }
    }
}

/// Handles group administration logic.
pub struct GroupAdminProtocol {
    /// Local user ID (hash of public key).
    #[allow(dead_code)]
    local_user_id: [u8; 32],
    /// The current group state (in-memory for now).
    pub state: GroupState,
}

impl GroupAdminProtocol {
    /// Creates a new GAP handler.
    pub fn new(local_user_id: [u8; 32], initial_members: Vec<[u8; 32]>, threshold: u8) -> Self {
        Self { 
            local_user_id,
            state: GroupState::new(initial_members, threshold)
        }
    }

    /// Processes a GAP operation request.
    /// 
    /// # Arguments
    /// * `op` - The operation to perform.
    /// * `sender_id` - The ID of the user requesting the operation.
    /// * `perm_manager` - Reference to permission manager for ACL checks.
    pub fn process_request(
        &mut self, 
        op: &GapOperation, 
        sender_id: &[u8; 32], 
        perm_manager: &PermissionManager
    ) -> Result<(), ProtocolError> {
        
        // 1. Verify Permissions
        if !perm_manager.can_perform(sender_id, op) {
            return Err(ProtocolError::PermissionDenied);
        }

        // 2. Execute Logic
        match op {
            GapOperation::AddMember { user_id, role } => {
                log::info!("GAP: Adding member {:?} with role {}", user_id, role);
                if self.state.members.contains(user_id) {
                    // Idempotent or error? Let's say idempotent for now.
                } else {
                    self.state.members.insert(*user_id);
                    // Trigger DKG/PSS would happen here in full implementation
                }
            }
            GapOperation::RemoveMember { user_id } => {
                log::info!("GAP: Removing member {:?}", user_id);
                if !self.state.members.remove(user_id) {
                    // Member not found, maybe warning?
                }
                // Trigger DKG/PSS would happen here
            }
            GapOperation::UpdatePolicy { new_threshold } => {
                 log::info!("GAP: Updating policy to k={}", new_threshold);
                 // Validate threshold vs member count
                 if *new_threshold == 0 || *new_threshold as usize > self.state.members.len() {
                     return Err(ProtocolError::InvalidPayload); // Or InvalidPolicy
                 }
                 self.state.threshold = *new_threshold;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gap_add_member() {
        let admin_id = [1u8; 32];
        let user_id = [2u8; 32];
        let new_member = [3u8; 32];
        
        let mut gap = GroupAdminProtocol::new(admin_id, vec![admin_id, user_id], 2);
        let perms = PermissionManager::new(vec![admin_id]);
        
        // Admin adds member
        let op = GapOperation::AddMember { user_id: new_member, role: 1 };
        gap.process_request(&op, &admin_id, &perms).unwrap();
        
        assert!(gap.state.members.contains(&new_member));
        assert_eq!(gap.state.members.len(), 3);
        
        // Non-admin tries to add
        let op2 = GapOperation::AddMember { user_id: [4u8; 32], role: 1 };
        let err = gap.process_request(&op2, &user_id, &perms);
        assert_eq!(err, Err(ProtocolError::PermissionDenied));
    }
    
    #[test]
    fn test_gap_remove_member() {
        let admin_id = [1u8; 32];
        let target_id = [2u8; 32];
        
        let mut gap = GroupAdminProtocol::new(admin_id, vec![admin_id, target_id], 2);
        let perms = PermissionManager::new(vec![admin_id]);
        
        let op = GapOperation::RemoveMember { user_id: target_id };
        gap.process_request(&op, &admin_id, &perms).unwrap();
        
        assert!(!gap.state.members.contains(&target_id));
    }
    
    #[test]
    fn test_gap_update_policy() {
        let admin_id = [1u8; 32];
        let mut gap = GroupAdminProtocol::new(admin_id, vec![admin_id], 1);
        let perms = PermissionManager::new(vec![admin_id]);
        
        let op = GapOperation::UpdatePolicy { new_threshold: 1 }; // Valid
        gap.process_request(&op, &admin_id, &perms).unwrap();
        assert_eq!(gap.state.threshold, 1);
        
        let op_invalid = GapOperation::UpdatePolicy { new_threshold: 5 }; // Invalid > members
        let err = gap.process_request(&op_invalid, &admin_id, &perms);
        assert_eq!(err, Err(ProtocolError::InvalidPayload));
    }
}

