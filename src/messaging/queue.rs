use crate::messaging::MessagingError;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
// use spin::Mutex; // Assuming no_std environment, but using RefCell for single thread or similar.
// For simplicity in this skeleton, we won't use advanced concurrency primitives yet.

pub struct MessageQueue {
    queue: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl MessageQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, msg: Vec<u8>) -> Result<(), MessagingError> {
        if self.queue.len() >= self.capacity {
            return Err(MessagingError::QueueFull);
        }
        self.queue.push_back(msg);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}
