#![no_std]
extern crate alloc;

use alloc::vec::Vec;

// 最小 panic_handler
use core::panic::PanicInfo;
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// TOGM Core API - 生成 C 绑定
pub mod core {
    #[no_mangle]
    pub extern "C" fn xor_example(a: *const u8, len: usize) -> *mut u8 {
        // 示例：简单 XOR，cbindgen 会生成 extern "C" 声明
        let slice_a = unsafe { std::slice::from_raw_parts(a, len) };
        let result = slice_a.iter().map(|&x| x ^ 0xFF).collect::<Vec<u8>>();
        Box::into_raw(result.into_boxed_slice()) as *mut u8
    }
}