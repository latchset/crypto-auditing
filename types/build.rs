// SPDX-License-Identifier: GPL-2.0

use std::{env, path::PathBuf};

const HDR: &str = "../agent/src/bpf/audit.h";

fn main() {
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(HDR)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .constified_enum_module("audit_event_type_t")
        .constified_enum_module("audit_data_type_t")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    println!("cargo:rerun-if-changed={}", HDR);
}
