use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let proto_dir: PathBuf = Path::new(&manifest)
        .join("..")
        .join("..")
        .join("protos");

    let mut proto_files: Vec<PathBuf> = Vec::new();
    collect_protos(&proto_dir, &mut proto_files)?;
    proto_files.sort();

    if proto_files.is_empty() {
        eprintln!("cargo:warning=No .proto files found in {}", proto_dir.display());
        return Ok(());
    }

    println!("cargo:rerun-if-changed={}", proto_dir.display());

    prost_build::Config::new()
        .compile_protos(
            &proto_files.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
            &[&proto_dir],
        )?;

    Ok(())
}

fn collect_protos(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_protos(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "proto") {
            files.push(path);
        }
    }
    Ok(())
}
