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
pub mod net;
pub mod messaging;
pub mod history;
pub mod group_history;
pub mod binary_verify;
pub mod recovery;
pub mod platform;
pub mod contacts;
pub mod audit;
pub mod iron_laws;
pub mod watchdog;
pub mod config;

#[cfg(not(feature = "std"))]
#[no_mangle]
pub extern "C" fn togm_version() -> u32 {
    0x030400
}

#[cfg(feature = "std")]
#[no_mangle]
pub extern "C" fn togm_version_std() -> u32 {
    0x030400
}
