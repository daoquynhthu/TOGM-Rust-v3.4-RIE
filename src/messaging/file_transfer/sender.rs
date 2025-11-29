use super::TransferState;
use super::chunker::Chunker;

pub struct FileSender {
    state: TransferState,
    chunker: Chunker,
}

impl FileSender {
    pub fn new(chunker: Chunker) -> Self {
        Self {
            state: TransferState::Idle,
            chunker,
        }
    }

    pub fn next_packet(&mut self) -> Option<&[u8]> {
        if let Some(chunk) = self.chunker.next_chunk() {
            self.state = TransferState::Transferring;
            Some(chunk)
        } else {
            self.state = TransferState::Completed;
            None
        }
    }
}
