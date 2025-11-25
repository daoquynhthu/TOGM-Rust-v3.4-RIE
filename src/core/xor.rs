#![forbid(unsafe_code)]
// Constant-time XOR engine.
// - Processes data in 64/32/16/8-byte blocks followed by a byte tail.
// - No unsafe and no secret-dependent branching; keystream length checks are enforced at callers.
// - Used by `otp_engine` for high-throughput one-time pad operations.

/// Constant-time XOR over `input` with `keystream`, writing into `out`.
/// Requires: `out.len() == input.len()` and `keystream.len() >= input.len()`.
#[inline(always)]
pub fn xor(input: &[u8], keystream: &[u8], out: &mut [u8]) {
    let len = out.len();
    let mut i = 0;

    while i + 64 <= len {
        let mut a0 = [0u8; 8];
        let mut a1 = [0u8; 8];
        let mut a2 = [0u8; 8];
        let mut a3 = [0u8; 8];
        let mut a4 = [0u8; 8];
        let mut a5 = [0u8; 8];
        let mut a6 = [0u8; 8];
        let mut a7 = [0u8; 8];
        let mut b0 = [0u8; 8];
        let mut b1 = [0u8; 8];
        let mut b2 = [0u8; 8];
        let mut b3 = [0u8; 8];
        let mut b4 = [0u8; 8];
        let mut b5 = [0u8; 8];
        let mut b6 = [0u8; 8];
        let mut b7 = [0u8; 8];
        a0.copy_from_slice(&input[i..i + 8]);
        a1.copy_from_slice(&input[i + 8..i + 16]);
        a2.copy_from_slice(&input[i + 16..i + 24]);
        a3.copy_from_slice(&input[i + 24..i + 32]);
        a4.copy_from_slice(&input[i + 32..i + 40]);
        a5.copy_from_slice(&input[i + 40..i + 48]);
        a6.copy_from_slice(&input[i + 48..i + 56]);
        a7.copy_from_slice(&input[i + 56..i + 64]);
        b0.copy_from_slice(&keystream[i..i + 8]);
        b1.copy_from_slice(&keystream[i + 8..i + 16]);
        b2.copy_from_slice(&keystream[i + 16..i + 24]);
        b3.copy_from_slice(&keystream[i + 24..i + 32]);
        b4.copy_from_slice(&keystream[i + 32..i + 40]);
        b5.copy_from_slice(&keystream[i + 40..i + 48]);
        b6.copy_from_slice(&keystream[i + 48..i + 56]);
        b7.copy_from_slice(&keystream[i + 56..i + 64]);
        let x0 = u64::from_ne_bytes(a0) ^ u64::from_ne_bytes(b0);
        let x1 = u64::from_ne_bytes(a1) ^ u64::from_ne_bytes(b1);
        let x2 = u64::from_ne_bytes(a2) ^ u64::from_ne_bytes(b2);
        let x3 = u64::from_ne_bytes(a3) ^ u64::from_ne_bytes(b3);
        let x4 = u64::from_ne_bytes(a4) ^ u64::from_ne_bytes(b4);
        let x5 = u64::from_ne_bytes(a5) ^ u64::from_ne_bytes(b5);
        let x6 = u64::from_ne_bytes(a6) ^ u64::from_ne_bytes(b6);
        let x7 = u64::from_ne_bytes(a7) ^ u64::from_ne_bytes(b7);
        out[i..i + 8].copy_from_slice(&x0.to_ne_bytes());
        out[i + 8..i + 16].copy_from_slice(&x1.to_ne_bytes());
        out[i + 16..i + 24].copy_from_slice(&x2.to_ne_bytes());
        out[i + 24..i + 32].copy_from_slice(&x3.to_ne_bytes());
        out[i + 32..i + 40].copy_from_slice(&x4.to_ne_bytes());
        out[i + 40..i + 48].copy_from_slice(&x5.to_ne_bytes());
        out[i + 48..i + 56].copy_from_slice(&x6.to_ne_bytes());
        out[i + 56..i + 64].copy_from_slice(&x7.to_ne_bytes());
        i += 64;
    }

    while i + 32 <= len {
        let mut a0 = [0u8; 8];
        let mut a1 = [0u8; 8];
        let mut a2 = [0u8; 8];
        let mut a3 = [0u8; 8];
        let mut b0 = [0u8; 8];
        let mut b1 = [0u8; 8];
        let mut b2 = [0u8; 8];
        let mut b3 = [0u8; 8];
        a0.copy_from_slice(&input[i..i + 8]);
        a1.copy_from_slice(&input[i + 8..i + 16]);
        a2.copy_from_slice(&input[i + 16..i + 24]);
        a3.copy_from_slice(&input[i + 24..i + 32]);
        b0.copy_from_slice(&keystream[i..i + 8]);
        b1.copy_from_slice(&keystream[i + 8..i + 16]);
        b2.copy_from_slice(&keystream[i + 16..i + 24]);
        b3.copy_from_slice(&keystream[i + 24..i + 32]);
        let x0 = u64::from_ne_bytes(a0) ^ u64::from_ne_bytes(b0);
        let x1 = u64::from_ne_bytes(a1) ^ u64::from_ne_bytes(b1);
        let x2 = u64::from_ne_bytes(a2) ^ u64::from_ne_bytes(b2);
        let x3 = u64::from_ne_bytes(a3) ^ u64::from_ne_bytes(b3);
        out[i..i + 8].copy_from_slice(&x0.to_ne_bytes());
        out[i + 8..i + 16].copy_from_slice(&x1.to_ne_bytes());
        out[i + 16..i + 24].copy_from_slice(&x2.to_ne_bytes());
        out[i + 24..i + 32].copy_from_slice(&x3.to_ne_bytes());
        i += 32;
    }

    while i + 16 <= len {
        let mut a0 = [0u8; 8];
        let mut a1 = [0u8; 8];
        let mut b0 = [0u8; 8];
        let mut b1 = [0u8; 8];
        a0.copy_from_slice(&input[i..i + 8]);
        a1.copy_from_slice(&input[i + 8..i + 16]);
        b0.copy_from_slice(&keystream[i..i + 8]);
        b1.copy_from_slice(&keystream[i + 8..i + 16]);
        let x0 = u64::from_ne_bytes(a0) ^ u64::from_ne_bytes(b0);
        let x1 = u64::from_ne_bytes(a1) ^ u64::from_ne_bytes(b1);
        out[i..i + 8].copy_from_slice(&x0.to_ne_bytes());
        out[i + 8..i + 16].copy_from_slice(&x1.to_ne_bytes());
        i += 16;
    }

    while i + 8 <= len {
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        a.copy_from_slice(&input[i..i + 8]);
        b.copy_from_slice(&keystream[i..i + 8]);
        let x = u64::from_ne_bytes(a) ^ u64::from_ne_bytes(b);
        out[i..i + 8].copy_from_slice(&x.to_ne_bytes());
        i += 8;
    }

    while i < len {
        out[i] = input[i] ^ keystream[i];
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_roundtrip() {
        let data = (0..100).map(|i| i as u8).collect::<Vec<u8>>();
        let key = (0..100).map(|i| (i as u8).wrapping_mul(3)).collect::<Vec<u8>>();
        let mut out = vec![0u8; 100];
        xor(&data, &key, &mut out);
        let mut back = vec![0u8; 100];
        xor(&out, &key, &mut back);
        assert_eq!(back, data);
    }
}
