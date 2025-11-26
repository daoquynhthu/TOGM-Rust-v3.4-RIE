use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use blake3::Hasher;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // 生成 genesis_hash.rs
    let lib_path = Path::new(&crate_dir).join("src/lib.rs");
    if !lib_path.exists() {
        panic!("src/lib.rs missing; create the file before building");
    }
    let lib_content = fs::read(&lib_path).expect("Failed to read src/lib.rs");
    let mut hasher = Hasher::new();
    hasher.update(&lib_content);
    let hash = hasher.finalize();
    let genesis_code = format!("pub const GENESIS_HASH: [u8; 32] = {:?};", hash.as_bytes());
    let genesis_path = out_dir.join("genesis_hash.rs");
    fs::write(&genesis_path, genesis_code).expect("Failed to write genesis_hash.rs");

    // 生成 cbindgen 头
    let bindings = cbindgen::generate(&crate_dir).expect("cbindgen generation failed");
    
    let header_path = Path::new("include/togm.h");
    if let Err(e) = fs::create_dir_all(header_path.parent().unwrap()) {
        println!("cargo:warning=Failed to create include/ directory: {}", e);
    }
    
    if !bindings.write_to_file(header_path) {
        println!("cargo:warning=Failed to write togm.h: check permissions or src/lib.rs content");
    } else {
        println!("cargo:info=togm.h generated successfully");
    }

    // Cargo 指令
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=build.rs");
}