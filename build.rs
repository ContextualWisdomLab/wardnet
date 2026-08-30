//! Compile the libcoraza C-ABI fixture used by in-process engine tests.
//!
//! Production loads operator-supplied libcoraza (`CORAZA_LIB_PATH`). CI stays
//! hermetic: this stub implements the same exported symbols without Go.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/coraza_abi_stub.rs");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let output = stub_output_path(&out_dir);
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let source = PathBuf::from(&manifest_dir).join("src/coraza_abi_stub.rs");

    let mut cmd = Command::new(&rustc);
    cmd.arg("--crate-type")
        .arg("cdylib")
        .arg("--crate-name")
        .arg("coraza_abi_stub")
        .arg("--edition")
        .arg("2024")
        .arg("-D")
        .arg("warnings")
        .arg("-C")
        .arg("opt-level=0")
        .arg("-o")
        .arg(&output)
        .arg(&source);

    if let (Ok(host), Ok(target)) = (std::env::var("HOST"), std::env::var("TARGET"))
        && host != target
    {
        cmd.arg("--target").arg(target);
    }

    let status = cmd.status().unwrap_or_else(|error| {
        panic!("failed to spawn rustc for libcoraza ABI stub: {error}");
    });
    if !status.success() {
        panic!("rustc failed to build libcoraza ABI stub: {status}");
    }

    println!(
        "cargo:rustc-env=WARDNET_CORAZA_ABI_STUB={}",
        output.display()
    );
}

fn stub_output_path(out_dir: &str) -> PathBuf {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let filename = match os.as_str() {
        "windows" => "coraza_abi_stub.dll",
        "macos" => "libcoraza_abi_stub.dylib",
        _ => "libcoraza_abi_stub.so",
    };
    PathBuf::from(out_dir).join(filename)
}
