use alloc::vec::Vec;

pub struct Chunker {
    data: Vec<u8>,
    chunk_size: usize,
    position: usize,
}

impl Chunker {
    pub fn new(data: Vec<u8>, chunk_size: usize) -> Self {
        Self {
            data,
            chunk_size,
            position: 0,
        }
    }

    pub fn next_chunk(&mut self) -> Option<&[u8]> {
        if self.position >= self.data.len() {
            return None;
        }
        let end = core::cmp::min(self.position + self.chunk_size, self.data.len());
        let chunk = &self.data[self.position..end];
        self.position = end;
        Some(chunk)
    }
    
    pub fn total_chunks(&self) -> usize {
        (self.data.len() + self.chunk_size - 1) / self.chunk_size
    }
}
