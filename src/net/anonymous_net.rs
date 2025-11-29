use crate::net::NetError;
use alloc::vec::Vec;
use alloc::string::String;

/// Interface for anonymous network providers (Tor, I2P, etc.)
/// 
/// This trait abstracts the underlying transport layer, allowing the protocol
/// to operate over any anonymous network.
pub trait AnonymousNet: Send + Sync {
    /// Connect to a remote address.
    fn connect(&self, addr: &str) -> Result<(), NetError>;

    /// Listen on a local address.
    fn listen(&self, addr: &str) -> Result<(), NetError>;

    /// Send data to the connected peer.
    fn send(&self, data: &[u8]) -> Result<(), NetError>;

    /// Receive data from the connected peer.
    fn receive(&self) -> Result<Vec<u8>, NetError>;

    /// Get the local address of this node.
    fn address(&self) -> Result<String, NetError>;
}
