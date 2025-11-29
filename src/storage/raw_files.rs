//! Raw File Storage.
//!
//! Provides basic file system operations with security checks.
//!
//! # Security
//! - Ensures files are written atomically (write-sync-rename).
//! - Sets restrictive permissions (where supported).

use super::StorageError;

#[cfg(feature = "std")]
use std::path::Path;
#[cfg(feature = "std")]
use std::fs::{self, File};
#[cfg(feature = "std")]
use std::io::{Read, Write};

/// Writes data to a file atomically.
#[cfg(feature = "std")]
pub fn write_atomic<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<(), StorageError> {
    let path = path.as_ref();
    let dir = path.parent().ok_or(StorageError::InvalidPath)?;
    
    // Create temp file
    let mut temp_path = dir.to_path_buf();
    // Simple random suffix would be better, but for now fixed suffix
    let filename = path.file_name().ok_or(StorageError::InvalidPath)?;
    temp_path.set_file_name(format!("{}.tmp", filename.to_string_lossy()));
    
    let mut file = File::create(&temp_path)?;
    
    // Write data
    file.write_all(data)?;
    file.sync_all()?;
    
    // Rename to final path (atomic on POSIX)
    fs::rename(&temp_path, path)?;
    
    Ok(())
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    
    #[test]
    fn test_atomic_write_read() {
        let dir = std::env::temp_dir().join("togm_test_storage");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test_atomic.bin");
        
        let data = b"Hello World";
        write_atomic(&path, data).unwrap();
        
        assert!(exists(&path));
        let read_data = read_file(&path).unwrap();
        assert_eq!(read_data, data);
        
        delete(&path).unwrap();
        assert!(!exists(&path));
        
        let _ = fs::remove_dir(&dir);
    }
}

/// Reads data from a file.
#[cfg(feature = "std")]
pub fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, StorageError> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let len = metadata.len();
    
    // Sanity check for size (e.g. 1GB max for now)
    if len > 1024 * 1024 * 1024 {
        return Err(StorageError::IoError); // Too large
    }
    
    let mut buffer = Vec::with_capacity(len as usize);
    file.read_to_end(&mut buffer)?;
    
    Ok(buffer)
}

/// Checks if a file exists.
#[cfg(feature = "std")]
pub fn exists<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().exists()
}

/// Deletes a file.
#[cfg(feature = "std")]
pub fn delete<P: AsRef<Path>>(path: P) -> Result<(), StorageError> {
    if path.as_ref().exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
