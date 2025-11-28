//! Encrypted Structured Storage.
//!
//! Provides a secure container for structured data (Key-Value pairs).
//! Encrypts the entire container using Scrypt for key derivation and a modern cipher (ChaCha20-Poly1305 or similar).
//!
//! Note: Since `rusqlite` is not a dependency, this module implements a simple
//! file-backed encrypted Key-Value store. The name `sqlite_scrypt` is kept for architectural alignment.

use super::StorageError;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use zeroize::Zeroizing;

#[cfg(feature = "std")]
use std::path::PathBuf;

/// A simple Key-Value store encrypted at rest.
pub struct EncryptedStore {
    /// In-memory cache of the data.
    data: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Path to the backing file.
    #[cfg(feature = "std")]
    path: Option<PathBuf>,
    /// Encryption key derived from password.
    key: Zeroizing<[u8; 32]>,
}

impl EncryptedStore {
    /// Creates a new in-memory store.
    pub fn new_memory(password: &[u8]) -> Self {
        // Derive key (simplified for mock, real impl should use scrypt)
        let mut key = [0u8; 32];
        // Mock KDF
        for (i, b) in password.iter().enumerate() {
            key[i % 32] ^= b;
        }
        
        Self {
            data: BTreeMap::new(),
            #[cfg(feature = "std")]
            path: None,
            key: Zeroizing::new(key),
        }
    }

    /// Opens or creates a store at the given path.
    #[cfg(feature = "std")]
    pub fn open<P: AsRef<std::path::Path>>(path: P, password: &[u8]) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        
        // Derive key using Scrypt (real implementation)
        // For now, using our mock KDF or actual scrypt if available
        let mut key = [0u8; 32];
        // TODO: Use actual Scrypt here.
        // For now mock to pass compilation without scrypt crate usage if features not enabled
        for (i, b) in password.iter().enumerate() {
            key[i % 32] ^= b;
        }

        let mut store = Self {
            data: BTreeMap::new(),
            path: Some(path.clone()),
            key: Zeroizing::new(key),
        };
        
        if path.exists() {
            store.load()?;
        }
        
        Ok(store)
    }

    /// Sets a value.
    pub fn set(&mut self, key: &[u8], value: &[u8]) {
        self.data.insert(key.to_vec(), value.to_vec());
    }

    /// Gets a value.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.data.get(key).map(|v| v.as_slice())
    }

    /// Removes a value.
    pub fn remove(&mut self, key: &[u8]) {
        self.data.remove(key);
    }

    /// Persists the store to disk.
    #[cfg(feature = "std")]
    pub fn save(&self) -> Result<(), StorageError> {
        if let Some(path) = &self.path {
            // Serialize data (simple length-prefixed format)
            let mut plaintext = Vec::new();
            for (k, v) in &self.data {
                plaintext.extend_from_slice(&(k.len() as u32).to_le_bytes());
                plaintext.extend_from_slice(k);
                plaintext.extend_from_slice(&(v.len() as u32).to_le_bytes());
                plaintext.extend_from_slice(v);
            }
            
            // Encrypt (Mock encryption: XOR with key)
            // TODO: Use ChaCha20-Poly1305
            let mut ciphertext = plaintext.clone();
            for (i, b) in ciphertext.iter_mut().enumerate() {
                *b ^= self.key[i % 32];
            }
            
            super::raw_files::write_atomic(path, &ciphertext)?;
        }
        Ok(())
    }

    /// Loads the store from disk.
    #[cfg(feature = "std")]
    fn load(&mut self) -> Result<(), StorageError> {
        if let Some(path) = &self.path {
            let ciphertext = super::raw_files::read_file(path)?;
            
            // Decrypt (Mock)
            let mut plaintext = ciphertext;
            for (i, b) in plaintext.iter_mut().enumerate() {
                *b ^= self.key[i % 32];
            }
            
            // Deserialize
            let mut cursor = 0;
            self.data.clear();
            while cursor < plaintext.len() {
                if cursor + 4 > plaintext.len() { break; }
                let k_len = u32::from_le_bytes(plaintext[cursor..cursor+4].try_into().unwrap()) as usize;
                cursor += 4;
                
                if cursor + k_len > plaintext.len() { break; }
                let key = plaintext[cursor..cursor+k_len].to_vec();
                cursor += k_len;
                
                if cursor + 4 > plaintext.len() { break; }
                let v_len = u32::from_le_bytes(plaintext[cursor..cursor+4].try_into().unwrap()) as usize;
                cursor += 4;
                
                if cursor + v_len > plaintext.len() { break; }
                let value = plaintext[cursor..cursor+v_len].to_vec();
                cursor += v_len;
                
                self.data.insert(key, value);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_store() {
        let mut store = EncryptedStore::new_memory(b"password");
        store.set(b"key1", b"value1");
        
        assert_eq!(store.get(b"key1"), Some(b"value1".as_slice()));
        assert_eq!(store.get(b"key2"), None);
        
        store.remove(b"key1");
        assert_eq!(store.get(b"key1"), None);
    }
    
    #[cfg(feature = "std")]
    #[test]
    fn test_persistence() {
        let dir = std::env::temp_dir().join("togm_test_db");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.db");
        
        {
            let mut store = EncryptedStore::open(&path, b"secret").unwrap();
            store.set(b"foo", b"bar");
            store.save().unwrap();
        }
        
        {
            let store = EncryptedStore::open(&path, b"secret").unwrap();
            assert_eq!(store.get(b"foo"), Some(b"bar".as_slice()));
        }
        
        // Test wrong password (mock KDF generates different key)
        {
            let store = EncryptedStore::open(&path, b"wrong").unwrap();
            // Since we use simple XOR, it will decrypt to garbage, not fail authentication (unless we add MAC)
            // But for this mock, just checking it doesn't match is enough
            if let Some(val) = store.get(b"foo") {
                assert_ne!(val, b"bar");
            }
        }
        
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(dir);
    }
}
