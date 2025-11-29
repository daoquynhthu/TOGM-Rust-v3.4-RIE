use super::TransferState;
use crate::messaging::MessagingError;
use alloc::vec::Vec;

pub struct FileReceiver {
    state: TransferState,
    buffer: Vec<u8>,
}

impl FileReceiver {
    pub fn new() -> Self {
        Self {
            state: TransferState::Idle,
            buffer: Vec::new(),
        }
    }

    pub fn receive_chunk(&mut self, chunk: &[u8]) -> Result<(), MessagingError> {
        self.buffer.extend_from_slice(chunk);
        self.state = TransferState::Transferring;
        Ok(())
    }

    pub fn complete(&mut self) {
        self.state = TransferState::Completed;
    }
}
