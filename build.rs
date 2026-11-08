use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run_check(
    root: &PathBuf,
    label: &str,
    program: &str,
    args: &[&str],
) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not start {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{label} failed with status {}\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(())
}

fn main() {
    let root = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo did not set CARGO_MANIFEST_DIR"),
    );

    for path in [
        "abi/check_abi_consistency.py",
        "abi/layout_check.c",
        "abi/wabrix_shared_memory.h",
        "src/headers/mod.rs",
        "src/shared_memory.rs",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=WABRIX_API_ABI_VERBOSE");
    let verbose = env::var_os("WABRIX_API_ABI_VERBOSE").is_some();

    if let Err(error) = run_check(
        &root,
        "C/Rust ABI numeric consistency",
        "python3",
        &["abi/check_abi_consistency.py"],
    ) {
        panic!("{error}");
    }

    if verbose {
        println!("cargo:warning=C/Rust ABI numeric consistency passed");
    }

    let c_compiler = env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    if let Err(error) = run_check(
        &root,
        "C shared-memory ABI layout",
        &c_compiler,
        &[
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "abi",
            "-fsyntax-only",
            "abi/layout_check.c",
        ],
    ) {
        panic!("{error}");
    }

    if verbose {
        println!("cargo:warning=C shared-memory ABI layout passed");
    }
}
