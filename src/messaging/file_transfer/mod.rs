pub mod chunker;
pub mod receiver;
pub mod sender;

#[derive(Debug, Clone, Copy)]
pub enum TransferState {
    Idle,
    Negotiating,
    Transferring,
    Completed,
    Failed,
}
