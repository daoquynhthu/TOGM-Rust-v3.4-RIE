//! Bootstrap Protocol.
//!
//! Handles the initialization of a TOGM group, including:
//! - Peer discovery and connection.
//! - Threshold Key Generation (DKG).
//! - State synchronization.
//!
//! # Whitepaper Compliance
//! - Section 6: Bootstrap Orchestration (Async n-t startup, 3-8min).

pub mod stages;
pub mod orchestrator;
pub mod local;
pub mod member_extend;
