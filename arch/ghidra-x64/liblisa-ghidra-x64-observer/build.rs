use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let project_dir = env::var("PROJECT_DIR").unwrap();
    let ghidraemu_dir = format!("{}/notes/instructions/ghidraemu", project_dir);
    let libsla_dir = format!("{}/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp", project_dir);

    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search={}", ghidraemu_dir);
    println!("cargo:rustc-link-search={}", libsla_dir);

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    println!("cargo:rustc-link-lib=ghidraemu");
    println!("cargo:rustc-link-lib=sla_dbg");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=z");

    println!("cargo:rerun-if-changed={}/libghidraemu.h", ghidraemu_dir);
    println!("cargo:rerun-if-changed={}/libghidraemu.cc", ghidraemu_dir);
    println!("cargo:rerun-if-changed={}/Makefile", ghidraemu_dir);

    Command::new("make")
        .current_dir(&ghidraemu_dir)
        .status()
        .expect("Failed to build ghidraemu");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(format!("{}/libghidraemu.h", ghidraemu_dir))
        .clang_args(["-x", "c++"])
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
