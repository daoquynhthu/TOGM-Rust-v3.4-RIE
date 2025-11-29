//! Permissions Management.
//!
//! Fine-grained permission checks for group actions.
//! Implements simple ACL logic.

use crate::protocol::control::gap::GapOperation;

/// Manages group permissions.
pub struct PermissionManager {
    /// Admin IDs (for v3.4 simple Logic).
    admins: alloc::vec::Vec<[u8; 32]>,
}

impl PermissionManager {
    /// Creates a new PermissionManager with initial admins.
    pub fn new(initial_admins: alloc::vec::Vec<[u8; 32]>) -> Self {
        Self { admins: initial_admins }
    }

    /// Checks if an action is permitted.
    pub fn can_perform(&self, user_id: &[u8; 32], op: &GapOperation) -> bool {
        // Simple Logic: Only Admins can perform GAP operations
        match op {
            GapOperation::AddMember { .. } 
            | GapOperation::RemoveMember { .. } 
            | GapOperation::UpdatePolicy { .. } => {
                self.is_admin(user_id)
            }
        }
    }

    /// Checks if a user is an admin.
    pub fn is_admin(&self, user_id: &[u8; 32]) -> bool {
        self.admins.contains(user_id)
    }
}

