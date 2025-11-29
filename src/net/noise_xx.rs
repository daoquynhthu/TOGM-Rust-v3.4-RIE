use crate::net::NetError;
use alloc::vec::Vec;
use x25519_dalek::{StaticSecret, PublicKey};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit}; 
use rand_core::OsRng;
use blake3::Hasher;
use zeroize::{Zeroize, Zeroizing};

/// Noise_XX_25519_ChaChaPoly_BLAKE3 Implementation
/// 
/// Handshake Pattern:
///   -> e
///   <- e, ee, s, es
///   -> s, se
pub struct NoiseState {
    static_priv: StaticSecret,
    static_pub: PublicKey,
    remote_static: Option<PublicKey>,
    ephemeral_priv: Option<StaticSecret>,
    remote_ephemeral: Option<PublicKey>,
    handshake_hash: [u8; 32],
    chaining_key: Zeroizing<[u8; 32]>,
    cipher_state: Option<(ChaCha20Poly1305, u64)>, // (Key, Nonce)
}

impl Drop for NoiseState {
    fn drop(&mut self) {
        self.handshake_hash.zeroize();
        // static_priv and ephemeral_priv are zeroized by x25519_dalek on drop
        // chaining_key is Zeroizing
    }
}

impl NoiseState {
    pub fn new(static_priv: StaticSecret) -> Self {
        let static_pub = PublicKey::from(&static_priv);
        let mut hasher = Hasher::new();
        hasher.update(b"Noise_XX_25519_ChaChaPoly_BLAKE3");
        let h = hasher.finalize();
        
        Self {
            static_priv,
            static_pub,
            remote_static: None,
            ephemeral_priv: None,
            remote_ephemeral: None,
            handshake_hash: *h.as_bytes(),
            chaining_key: Zeroizing::new(*h.as_bytes()), // Initial ck is usually hash(protocol_name)
            cipher_state: None,
        }
    }

    /// Initialize initiator handshake (Message 1: -> e)
    pub fn initiate_handshake(&mut self) -> Result<Vec<u8>, NetError> {
        // Generate ephemeral key
        let ephemeral_priv = StaticSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral_priv);
        
        // Mix hash with e (public key)
        self.mix_hash(ephemeral_pub.as_bytes());
        
        // Send e (cleartext)
        let mut msg = Vec::new();
        msg.extend_from_slice(ephemeral_pub.as_bytes());
        
        // Initial payload is empty for basic handshake
        let payload = &[]; 
        self.mix_hash(payload);
        // No encryption for first message payload in XX
        msg.extend_from_slice(payload);

        self.ephemeral_priv = Some(ephemeral_priv);
        Ok(msg)
    }

    /// Process responder handshake (Message 1: -> e)
    /// Responder receives Message 1
    pub fn receive_initiation(&mut self, msg: &[u8]) -> Result<(), NetError> {
        if msg.len() < 32 {
            return Err(NetError::HandshakeFailed);
        }
        
        let mut re_bytes = [0u8; 32];
        re_bytes.copy_from_slice(&msg[0..32]);
        let remote_ephemeral = PublicKey::from(re_bytes);
        
        self.mix_hash(remote_ephemeral.as_bytes());
        self.remote_ephemeral = Some(remote_ephemeral);
        
        // Process payload (empty)
        let payload = &msg[32..];
        self.mix_hash(payload);
        
        Ok(())
    }

    /// Responder generates Message 2: <- e, ee, s, es
    pub fn respond_handshake(&mut self) -> Result<Vec<u8>, NetError> {
        // Generate ephemeral key
        let ephemeral_priv = StaticSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral_priv);
        
        // Mix hash with e (responder's ephemeral)
        self.mix_hash(ephemeral_pub.as_bytes());
        
        let mut msg = Vec::new();
        msg.extend_from_slice(ephemeral_pub.as_bytes());
        
        // ECDH(ee) = DH(ephemeral_priv, remote_ephemeral)
        // Clone/Copy remote_ephemeral to avoid holding immutable borrow of self
        let remote_ephemeral = *self.remote_ephemeral.as_ref().ok_or(NetError::HandshakeFailed)?;
        let ee = ephemeral_priv.diffie_hellman(&remote_ephemeral);
        self.mix_key(ee.as_bytes());
        
        // Encrypt static key (s)
        // Copy bytes to avoid holding borrow
        let static_pub_bytes = *self.static_pub.as_bytes();
        let encrypted_s = self.encrypt_and_hash(&static_pub_bytes)?;
        msg.extend_from_slice(&encrypted_s);
        
        // ECDH(es) = DH(static_priv, remote_ephemeral)
        let es = self.static_priv.diffie_hellman(&remote_ephemeral);
        self.mix_key(es.as_bytes());
        
        // Encrypt payload (empty)
        let encrypted_payload = self.encrypt_and_hash(&[])?;
        msg.extend_from_slice(&encrypted_payload);
        
        self.ephemeral_priv = Some(ephemeral_priv);
        Ok(msg)
    }

    /// Initiator processes Message 2: <- e, ee, s, es
    pub fn process_response(&mut self, msg: &[u8]) -> Result<(), NetError> {
        if msg.len() < 32 {
            return Err(NetError::HandshakeFailed);
        }
        
        // Read e (remote ephemeral)
        let mut re_bytes = [0u8; 32];
        re_bytes.copy_from_slice(&msg[0..32]);
        let remote_ephemeral = PublicKey::from(re_bytes);
        self.mix_hash(remote_ephemeral.as_bytes());
        self.remote_ephemeral = Some(remote_ephemeral);
        
        // ECDH(ee)
        // Scope the access to ephemeral_priv to avoid conflict with mix_key
        let ee = {
            let ephemeral_priv = self.ephemeral_priv.as_ref().ok_or(NetError::HandshakeFailed)?;
            ephemeral_priv.diffie_hellman(&remote_ephemeral)
        };
        self.mix_key(ee.as_bytes());
        
        // Decrypt static key (s)
        let offset = 32;
        // Length of encrypted static key = 32 + 16 (tag) = 48
        if msg.len() < offset + 48 {
            return Err(NetError::HandshakeFailed);
        }
        let encrypted_s = &msg[offset..offset+48];
        let s_bytes = self.decrypt_and_hash(encrypted_s)?;
        if s_bytes.len() != 32 {
            return Err(NetError::HandshakeFailed);
        }
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&s_bytes);
        let remote_static = PublicKey::from(s_arr);
        self.remote_static = Some(remote_static);
        
        // ECDH(es)
        let es = {
            let ephemeral_priv = self.ephemeral_priv.as_ref().ok_or(NetError::HandshakeFailed)?;
            ephemeral_priv.diffie_hellman(&remote_static)
        };
        self.mix_key(es.as_bytes());
        
        // Decrypt payload
        let payload_offset = offset + 48;
        let encrypted_payload = &msg[payload_offset..];
        let _payload = self.decrypt_and_hash(encrypted_payload)?;
        
        Ok(())
    }

    /// Initiator generates Message 3: -> s, se
    pub fn finish_initiator(&mut self) -> Result<Vec<u8>, NetError> {
        let mut msg = Vec::new();
        
        // Encrypt static key (s)
        let static_pub_bytes = *self.static_pub.as_bytes();
        let encrypted_s = self.encrypt_and_hash(&static_pub_bytes)?;
        msg.extend_from_slice(&encrypted_s);
        
        // ECDH(se) = DH(static_priv, remote_ephemeral)
        let remote_ephemeral = *self.remote_ephemeral.as_ref().ok_or(NetError::HandshakeFailed)?;
        let se = self.static_priv.diffie_hellman(&remote_ephemeral);
        self.mix_key(se.as_bytes());
        
        // Encrypt payload (empty)
        let encrypted_payload = self.encrypt_and_hash(&[])?;
        msg.extend_from_slice(&encrypted_payload);
        
        // Split for transport
        self.split();
        
        Ok(msg)
    }

    /// Responder processes Message 3: -> s, se
    pub fn finalize_handshake(&mut self, msg: &[u8]) -> Result<(), NetError> {
        // Decrypt static key (s)
        // Length = 32 + 16 = 48
        if msg.len() < 48 {
            return Err(NetError::HandshakeFailed);
        }
        let encrypted_s = &msg[0..48];
        let s_bytes = self.decrypt_and_hash(encrypted_s)?;
        
        if s_bytes.len() != 32 {
            return Err(NetError::HandshakeFailed);
        }
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&s_bytes);
        self.remote_static = Some(PublicKey::from(s_arr));
        
        // ECDH(se)
        let remote_static = self.remote_static.unwrap();
        let ephemeral_priv = self.ephemeral_priv.as_ref().ok_or(NetError::HandshakeFailed)?;
        let se = ephemeral_priv.diffie_hellman(&remote_static);
        self.mix_key(se.as_bytes());
        
        // Decrypt payload
        let encrypted_payload = &msg[48..];
        let _payload = self.decrypt_and_hash(encrypted_payload)?;
        
        // Split for transport
        self.split();
        
        Ok(())
    }

    // Helpers
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Hasher::new();
        hasher.update(&self.handshake_hash);
        hasher.update(data);
        self.handshake_hash = *hasher.finalize().as_bytes();
    }
    
    fn mix_key(&mut self, input_key_material: &[u8]) {
        // KDF step using BLAKE3 to simulate HKDF(ck, input_key_material, 2)
        // Output 1: New chaining key
        let mut hasher_ck = Hasher::new();
        hasher_ck.update(&*self.chaining_key);
        hasher_ck.update(input_key_material);
        hasher_ck.update(b"chaining_key"); // Domain separation
        self.chaining_key = Zeroizing::new(*hasher_ck.finalize().as_bytes());

        // Output 2: Encryption key (temp_k)
        let mut hasher_k = Hasher::new();
        hasher_k.update(&*self.chaining_key);
        hasher_k.update(input_key_material);
        hasher_k.update(b"encryption_key"); // Domain separation
        let temp_k_bytes = *hasher_k.finalize().as_bytes();

        // Initialize cipher state with temp_k
        let key = chacha20poly1305::Key::from_slice(&temp_k_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        self.cipher_state = Some((cipher, 0)); // Reset nonce to 0
    }
    
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetError> {
        if let Some((cipher, mut nonce_val)) = self.cipher_state.take() {
            // Prepare nonce (96-bit, little-endian, padded with zeros)
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..].copy_from_slice(&nonce_val.to_le_bytes());
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            
            // Encrypt
            let ciphertext_res = cipher.encrypt(nonce, plaintext);
            
            if ciphertext_res.is_err() {
                self.cipher_state = Some((cipher, nonce_val));
                return Err(NetError::EncryptionError);
            }
            let ciphertext = ciphertext_res.unwrap();
                
            // Update hash with ciphertext
            self.mix_hash(&ciphertext);
            
            // Increment nonce
            nonce_val += 1;
            
            // Restore state
            self.cipher_state = Some((cipher, nonce_val));
            
            Ok(ciphertext)
        } else {
             // If no key set, ciphertext = plaintext (Noise spec)
             self.mix_hash(plaintext);
             Ok(plaintext.to_vec())
        }
    }
    
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NetError> {
        if let Some((cipher, mut nonce_val)) = self.cipher_state.take() {
            // Update hash with ciphertext (before decryption check in Noise spec? No, spec says mix_hash(ciphertext))
            self.mix_hash(ciphertext);

            // Prepare nonce
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..].copy_from_slice(&nonce_val.to_le_bytes());
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            
            // Decrypt
            let plaintext_res = cipher.decrypt(nonce, ciphertext);
            
            if plaintext_res.is_err() {
                 self.cipher_state = Some((cipher, nonce_val));
                 return Err(NetError::DecryptionError);
            }
            let plaintext = plaintext_res.unwrap();
            
            // Increment nonce
            nonce_val += 1;
            
            // Restore state
            self.cipher_state = Some((cipher, nonce_val));
            
            Ok(plaintext)
        } else {
            // No encryption
            self.mix_hash(ciphertext);
            Ok(ciphertext.to_vec())
        }
    }
    
    fn split(&mut self) {
        // Split chaining key into two cipher keys
        // temp_k1, temp_k2 = HKDF(ck, zero_len, 2)
        
        // Simulating with BLAKE3
        let mut hasher_k1 = Hasher::new();
        hasher_k1.update(&*self.chaining_key);
        hasher_k1.update(b"split_key_1");
        let k1_bytes = *hasher_k1.finalize().as_bytes();
        
        // For simplicity in this unified state struct, we only keep one key (k1)
        // effectively making it a half-duplex or shared-key channel for testing.
        // In a real production system, we would return two TransportState objects:
        // one for sending (k1) and one for receiving (k2), or vice versa depending on role.
        
        let key = chacha20poly1305::Key::from_slice(&k1_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        self.cipher_state = Some((cipher, 0));
    }

    /// Encrypts a transport message (post-handshake).
    pub fn encrypt_transport(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetError> {
        // In transport phase, we don't update the handshake hash anymore, just use the cipher state.
        // However, our encrypt_and_hash does both.
        // For strict Noise compliance, transport messages don't update h.
        // But we reused the method for testing.
        // Let's implement a dedicated transport encrypt.
        
        if let Some((cipher, mut nonce_val)) = self.cipher_state.take() {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..].copy_from_slice(&nonce_val.to_le_bytes());
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            
            let ciphertext_res = cipher.encrypt(nonce, plaintext);
            
            if ciphertext_res.is_err() {
                self.cipher_state = Some((cipher, nonce_val));
                return Err(NetError::EncryptionError);
            }
            let ciphertext = ciphertext_res.unwrap();
            
            nonce_val += 1;
            self.cipher_state = Some((cipher, nonce_val));
            
            Ok(ciphertext)
        } else {
            Err(NetError::HandshakeFailed) // No key established
        }
    }

    /// Decrypts a transport message (post-handshake).
    pub fn decrypt_transport(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NetError> {
        if let Some((cipher, mut nonce_val)) = self.cipher_state.take() {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..].copy_from_slice(&nonce_val.to_le_bytes());
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            
            let plaintext_res = cipher.decrypt(nonce, ciphertext);
            
            if plaintext_res.is_err() {
                self.cipher_state = Some((cipher, nonce_val));
                return Err(NetError::DecryptionError);
            }
            let plaintext = plaintext_res.unwrap();
            
            nonce_val += 1;
            self.cipher_state = Some((cipher, nonce_val));
            
            Ok(plaintext)
        } else {
             Err(NetError::HandshakeFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_noise_handshake() {
        // Setup Initiator
        let i_static = StaticSecret::random_from_rng(OsRng);
        let mut initiator = NoiseState::new(i_static);

        // Setup Responder
        let r_static = StaticSecret::random_from_rng(OsRng);
        let _r_public = PublicKey::from(&r_static);
        let mut responder = NoiseState::new(r_static);

        // 1. Initiator -> Responder (e)
        let msg1 = initiator.initiate_handshake().unwrap();
        responder.receive_initiation(&msg1).unwrap();

        // 2. Responder -> Initiator (e, ee, s, es)
        let msg2 = responder.respond_handshake().unwrap();
        initiator.process_response(&msg2).unwrap();

        // 3. Initiator -> Responder (s, se)
        let msg3 = initiator.finish_initiator().unwrap();
        responder.finalize_handshake(&msg3).unwrap();
        
        // Check if handshake finished (both have keys)
        assert!(initiator.cipher_state.is_some());
        assert!(responder.cipher_state.is_some());
        
        // Verify Transport (Encrypt/Decrypt)
        let plaintext = b"Hello World";
        let ciphertext = initiator.encrypt_transport(plaintext).unwrap();
        
        let decrypted = responder.decrypt_transport(&ciphertext).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
        
        // Verify Reply
        let reply_plain = b"Reply";
        let reply_cipher = responder.encrypt_transport(reply_plain).unwrap();
        let reply_decrypted = initiator.decrypt_transport(&reply_cipher).unwrap();
        
        assert_eq!(reply_plain, &reply_decrypted[..]);
    }
}
