//! Build script for xray-geodata.
//!
//! Compiles `proto/geodat.proto` via prost-build, producing Rust types
//! under the `xray.geodata` package namespace.

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let proto_dir = Path::new(&manifest_dir).join("proto");
    let proto_file = proto_dir.join("geodat.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());

    prost_build::Config::new()
        .compile_protos(&[&proto_file], &[&proto_dir])?;

    Ok(())
}
