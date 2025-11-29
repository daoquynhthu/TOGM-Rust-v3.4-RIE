//! Protocol State Machine.
//!
//! Manages the high-level state of the TOGM node.
//! strictly enforces state transitions to ensure security and consistency.
//!
//! # States
//! - **Offline**: Initial state, no network activity.
//! - **Bootstrapping**: Participating in group formation or joining (Section 6).
//! - **Active**: Normal operation, sending/receiving messages.
//! - **ConsensusPending**: Waiting for critical consensus (DBAP) (Section 8).
//! - **Recovery**: Restoring from backup or fetching history.
//! - **Lockdown**: Security violation detected (Iron Laws triggered), keys zeroized.
//!
//! # Whitepaper Compliance
//! - Section 8: System States and Transitions.

use super::ProtocolError;
use alloc::vec::Vec;
use alloc::boxed::Box;

/// Possible states of the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initial state, disconnected.
    Offline,
    /// Establishing group or joining.
    Bootstrapping,
    /// Normal operational state.
    Active,
    /// Waiting for consensus (e.g., DBAP binary attestation).
    ConsensusPending,
    /// Recovering state/history.
    Recovery,
    /// Security lockdown; requires manual intervention or restart.
    Lockdown,
}

/// Observer trait for state changes.
pub trait StateObserver: Send + Sync {
    fn on_state_change(&self, from: State, to: State);
}

/// RAII guard for state transitions.
/// If dropped without `commit()`, it rolls back the state.
pub struct StateTransition<'a> {
    sm: &'a mut StateMachine,
    original_state: State,
    committed: bool,
}

impl<'a> StateTransition<'a> {
    /// Commits the state transition.
    pub fn commit(mut self) {
        self.committed = true;
        self.sm.notify_observers(self.original_state, self.sm.current_state);
    }
}

impl<'a> Drop for StateTransition<'a> {
    fn drop(&mut self) {
        if !self.committed {
            log::warn!("Rolling back state: {:?} -> {:?}", self.sm.current_state, self.original_state);
            self.sm.current_state = self.original_state;
        }
    }
}

/// The Protocol State Machine.
pub struct StateMachine {
    current_state: State,
    observers: Vec<Box<dyn StateObserver>>,
}

impl StateMachine {
    /// Creates a new state machine in the Offline state.
    pub fn new() -> Self {
        Self {
            current_state: State::Offline,
            observers: Vec::new(),
        }
    }

    /// Returns the current state.
    pub fn state(&self) -> State {
        self.current_state
    }
    
    /// Adds a state observer.
    pub fn add_observer(&mut self, observer: Box<dyn StateObserver>) {
        self.observers.push(observer);
    }
    
    fn notify_observers(&self, from: State, to: State) {
        for obs in &self.observers {
            obs.on_state_change(from, to);
        }
    }

    /// Begins a transactional state update.
    /// Returns a guard that must be committed.
    fn begin_transition(&mut self, new_state: State) -> StateTransition<'_> {
        let original_state = self.current_state;
        log::info!("State transition: {:?} -> {:?}", original_state, new_state);
        self.current_state = new_state;
        StateTransition {
            sm: self,
            original_state,
            committed: false,
        }
    }

    /// Transitions to the Bootstrapping state.
    pub fn start_bootstrap(&mut self) -> Result<(), ProtocolError> {
        match self.current_state {
            State::Offline | State::Recovery => {
                let trans = self.begin_transition(State::Bootstrapping);
                trans.commit();
                Ok(())
            }
            State::Bootstrapping => Ok(()), // Idempotent
            _ => Err(ProtocolError::InvalidState),
        }
    }

    /// Transitions to the Active state (bootstrap/recovery complete).
    pub fn set_active(&mut self) -> Result<(), ProtocolError> {
        match self.current_state {
            State::Bootstrapping | State::Recovery | State::ConsensusPending => {
                let trans = self.begin_transition(State::Active);
                trans.commit();
                Ok(())
            }
            State::Active => Ok(()),
            _ => Err(ProtocolError::InvalidState),
        }
    }

    /// Transitions to ConsensusPending (DBAP triggered).
    pub fn start_consensus(&mut self) -> Result<(), ProtocolError> {
        match self.current_state {
            State::Active => {
                let trans = self.begin_transition(State::ConsensusPending);
                trans.commit();
                Ok(())
            }
            State::ConsensusPending => Ok(()),
            _ => Err(ProtocolError::InvalidState),
        }
    }

    /// Transitions to Recovery state.
    pub fn start_recovery(&mut self) -> Result<(), ProtocolError> {
        match self.current_state {
            State::Offline | State::Active => {
                let trans = self.begin_transition(State::Recovery);
                trans.commit();
                Ok(())
            }
            State::Recovery => Ok(()),
            _ => Err(ProtocolError::InvalidState),
        }
    }

    /// Triggers a security lockdown.
    ///
    /// This transition is allowed from ANY state.
    pub fn trigger_lockdown(&mut self) -> Result<(), ProtocolError> {
        let trans = self.begin_transition(State::Lockdown);
        trans.commit();
        Ok(())
    }

    /// Unlocks the state machine from Lockdown (requires admin proof).
    ///
    /// # Arguments
    /// * `admin_proof` - A cryptographic proof authorizing the unlock (placeholder).
    pub fn unlock_with_admin_key(&mut self, _admin_proof: &[u8]) -> Result<(), ProtocolError> {
        if self.current_state != State::Lockdown {
             return Err(ProtocolError::InvalidState);
        }
        
        // In a real implementation, verify admin_proof here.
        // if !verify(admin_proof) { return Err(ProtocolError::PermissionDenied); }
        
        let trans = self.begin_transition(State::Offline);
        trans.commit();
        Ok(())
    }

    /// Resets to Offline (e.g., user disconnect).
    pub fn disconnect(&mut self) -> Result<(), ProtocolError> {
        if self.current_state == State::Lockdown {
             return Err(ProtocolError::InvalidState);
        }
        let trans = self.begin_transition(State::Offline);
        trans.commit();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let sm = StateMachine::new();
        assert_eq!(sm.state(), State::Offline);
    }

    #[test]
    fn test_valid_flow() {
        let mut sm = StateMachine::new();
        
        // Offline -> Bootstrapping
        sm.start_bootstrap().unwrap();
        assert_eq!(sm.state(), State::Bootstrapping);
        
        // Bootstrapping -> Active
        sm.set_active().unwrap();
        assert_eq!(sm.state(), State::Active);
        
        // Active -> ConsensusPending
        sm.start_consensus().unwrap();
        assert_eq!(sm.state(), State::ConsensusPending);
        
        // ConsensusPending -> Active
        sm.set_active().unwrap();
        assert_eq!(sm.state(), State::Active);
        
        // Active -> Offline
        sm.disconnect().unwrap();
        assert_eq!(sm.state(), State::Offline);
    }

    #[test]
    fn test_invalid_transitions() {
        let mut sm = StateMachine::new();
        
        // Offline -> Active (Direct jump not allowed)
        assert_eq!(sm.set_active(), Err(ProtocolError::InvalidState));
        
        // Offline -> ConsensusPending
        assert_eq!(sm.start_consensus(), Err(ProtocolError::InvalidState));
    }

    #[test]
    fn test_lockdown() {
        let mut sm = StateMachine::new();
        sm.start_bootstrap().unwrap();
        
        sm.trigger_lockdown().unwrap();
        assert_eq!(sm.state(), State::Lockdown);
        
        // Cannot recover from lockdown via standard methods
        assert_eq!(sm.disconnect(), Err(ProtocolError::InvalidState));
        assert_eq!(sm.set_active(), Err(ProtocolError::InvalidState));
        
        // Admin unlock
        sm.unlock_with_admin_key(&[]).unwrap();
        assert_eq!(sm.state(), State::Offline);
    }
    
    #[test]
    fn test_transaction_rollback() {
        let mut sm = StateMachine::new();
        assert_eq!(sm.state(), State::Offline);
        
        {
            let _trans = sm.begin_transition(State::Bootstrapping);
            // Cannot borrow sm immutably here while _trans has mutable borrow
            // assert_eq!(sm.state(), State::Bootstrapping); 
            // Drop without commit
        }
        
        assert_eq!(sm.state(), State::Offline);
    }
}
