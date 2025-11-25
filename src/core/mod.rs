extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

pub mod gf256;
pub mod otp_engine;
pub mod masterpad;
pub mod ratchet;
pub mod sip64;
pub mod universal_hash;
pub mod xor;

#[no_mangle]
pub extern "C" fn xor_example(a: *const u8, len: usize) -> *mut u8 {
    let slice_a = unsafe { core::slice::from_raw_parts(a, len) };
    let result = slice_a.iter().map(|&x| x ^ 0xFF).collect::<Vec<u8>>();
    Box::into_raw(result.into_boxed_slice()) as *mut u8
}
