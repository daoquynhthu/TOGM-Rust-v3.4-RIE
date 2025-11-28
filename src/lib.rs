#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
use core::panic::PanicInfo;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop {} }

pub mod core;
pub mod entropy;
pub mod mpc;
pub mod pad;
pub mod protocol;
pub mod storage;
