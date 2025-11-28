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

/// The Protocol State Machine.
pub struct StateMachine {
    current_state: State,
}

impl StateMachine {
    /// Creates a new state machine in the Offline state.
    pub fn new() -> Self {
        Self {
            current_state: State::Offline,
        }
    }

    /// Returns the current state.
    pub fn state(&self) -> State {
        self.current_state
    }

    /// Transitions to the Bootstrapping state.
    pub fn start_bootstrap(&mut self) -> Result<(), ProtocolError> {
        match self.current_state {
            State::Offline | State::Recovery => {
                self.current_state = State::Bootstrapping;
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
                self.current_state = State::Active;
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
                self.current_state = State::ConsensusPending;
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
                self.current_state = State::Recovery;
                Ok(())
            }
            State::Recovery => Ok(()),
            _ => Err(ProtocolError::InvalidState),
        }
    }

    /// Triggers a security lockdown.
    ///
    /// This transition is allowed from ANY state.
    pub fn trigger_lockdown(&mut self) {
        self.current_state = State::Lockdown;
    }

    /// Resets to Offline (e.g., user disconnect).
    pub fn disconnect(&mut self) -> Result<(), ProtocolError> {
        if self.current_state == State::Lockdown {
             return Err(ProtocolError::InvalidState);
        }
        self.current_state = State::Offline;
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
        
        sm.trigger_lockdown();
        assert_eq!(sm.state(), State::Lockdown);
        
        // Cannot recover from lockdown via standard methods
        assert_eq!(sm.disconnect(), Err(ProtocolError::InvalidState));
        assert_eq!(sm.set_active(), Err(ProtocolError::InvalidState));
    }
}
