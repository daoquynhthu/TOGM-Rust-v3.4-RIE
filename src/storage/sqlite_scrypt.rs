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
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use rand_core::{RngCore, OsRng};

#[cfg(feature = "std")]
use std::path::PathBuf;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

fn get_scrypt_params() -> scrypt::Params {
    scrypt::Params::new(14, 8, 1, 32).expect("Valid params")
}

/// A simple Key-Value store encrypted at rest.
pub struct EncryptedStore {
    /// In-memory cache of the data.
    data: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Path to the backing file.
    #[cfg(feature = "std")]
    path: Option<PathBuf>,
    /// Encryption key derived from password.
    key: Zeroizing<[u8; 32]>,
    /// Salt used for key derivation.
    salt: [u8; SALT_LEN],
}

impl EncryptedStore {
    /// Creates a new in-memory store.
    pub fn new_memory(password: &[u8]) -> Self {
        // Use a fixed salt for memory-only store
        let mut salt = [0u8; SALT_LEN];
        let prefix = b"TOGM_MEMORY_STORE_SALT";
        salt[..prefix.len()].copy_from_slice(prefix);
        
        let mut key = Zeroizing::new([0u8; 32]);
        scrypt::scrypt(password, &salt, &get_scrypt_params(), &mut *key).expect("Scrypt failed");
        
        Self {
            data: BTreeMap::new(),
            #[cfg(feature = "std")]
            path: None,
            key,
            salt,
        }
    }

    /// Opens or creates a store at the given path.
    #[cfg(feature = "std")]
    pub fn open<P: AsRef<std::path::Path>>(path: P, password: &[u8]) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        
        let mut salt = [0u8; SALT_LEN];
        let mut file_exists = path.exists();
        
        if file_exists {
            // Read salt from file header
             match std::fs::File::open(&path) {
                Ok(mut f) => {
                    use std::io::Read;
                    // Try to read salt
                    if f.read_exact(&mut salt).is_err() {
                        // If file is too short/empty or read fails, treat as corrupted or new?
                        // If it's empty, we can treat as new.
                        if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
                            file_exists = false;
                        } else {
                             return Err(StorageError::IoError);
                        }
                    }
                },
                Err(_) => return Err(StorageError::IoError),
            }
        }
        
        if !file_exists {
            // Generate new salt
            OsRng.fill_bytes(&mut salt);
        }

        let mut key = Zeroizing::new([0u8; 32]);
        scrypt::scrypt(password, &salt, &get_scrypt_params(), &mut *key).map_err(|_| StorageError::CryptoError)?;

        let mut store = Self {
            data: BTreeMap::new(),
            path: Some(path.clone()),
            key,
            salt,
        };
        
        if file_exists {
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
            // 1. Serialize data
            let mut plaintext = Vec::new();
            for (k, v) in &self.data {
                plaintext.extend_from_slice(&(k.len() as u32).to_le_bytes());
                plaintext.extend_from_slice(k);
                plaintext.extend_from_slice(&(v.len() as u32).to_le_bytes());
                plaintext.extend_from_slice(v);
            }
            
            // 2. Encrypt
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.key));
            let mut nonce_bytes = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            
            let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
                .map_err(|_| StorageError::CryptoError)?;
                
            // 3. Write to file: Salt || Nonce || Ciphertext
            use std::io::Write;
            let mut file = std::fs::File::create(path).map_err(|_| StorageError::IoError)?;
            file.write_all(&self.salt).map_err(|_| StorageError::IoError)?;
            file.write_all(&nonce_bytes).map_err(|_| StorageError::IoError)?;
            file.write_all(&ciphertext).map_err(|_| StorageError::IoError)?;
            file.flush().map_err(|_| StorageError::IoError)?;
        }
        Ok(())
    }

    /// Loads the store from disk.
    #[cfg(feature = "std")]
    fn load(&mut self) -> Result<(), StorageError> {
        if let Some(path) = &self.path {
             use std::io::Read;
             let mut file = std::fs::File::open(path).map_err(|_| StorageError::IoError)?;
             
             let mut content = Vec::new();
             file.read_to_end(&mut content).map_err(|_| StorageError::IoError)?;
             
             if content.len() < SALT_LEN + NONCE_LEN {
                 // File too short, maybe empty? If empty, data is empty.
                 if content.is_empty() {
                     return Ok(());
                 }
                 return Err(StorageError::IoError);
             }
             
             // Verify salt matches (optional sanity check, but we used it to derive key already)
             let file_salt = &content[..SALT_LEN];
             if file_salt != self.salt {
                 // This theoretically shouldn't happen if we opened the same file we read salt from,
                 // unless it changed between open() and load().
                 return Err(StorageError::CryptoError);
             }
             
             let nonce_bytes = &content[SALT_LEN..SALT_LEN + NONCE_LEN];
             let ciphertext = &content[SALT_LEN + NONCE_LEN..];
             
             let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.key));
             let nonce = Nonce::from_slice(nonce_bytes);
             
             let plaintext = cipher.decrypt(nonce, ciphertext)
                .map_err(|_| StorageError::CryptoError)?; // Decryption failure (wrong key/mac)
                
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
        
        // Test wrong password (AEAD should fail authentication)
        {
            let result = EncryptedStore::open(&path, b"wrong");
            assert!(result.is_err(), "Should fail with wrong password due to MAC mismatch");
        }
        
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(dir);
    }
}
