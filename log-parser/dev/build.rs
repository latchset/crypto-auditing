// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The crypto-auditing developers.

//! Build script for `crypto-auditing-log-parser-dev`, which generates the
//! test fixtures of `crypto-auditing-log-parser` from the event sequences
//! defined in [scenarios.rs](scenarios.rs).

use std::env;
use std::fs;
use std::path::Path;

mod scenarios;

/// Writes `content` to `path` unless it is already up-to-date, so
/// that the build script is not rerun needlessly
fn write(path: &Path, content: &[u8]) {
    println!("cargo:rerun-if-changed={}", path.display());
    if fs::read(path).ok().as_deref() == Some(content) {
        return;
    }
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir).unwrap_or_else(|e| panic!("unable to create `{}`: {e}", dir.display()));
    fs::write(path, content)
        .unwrap_or_else(|e| panic!("unable to write `{}`: {e}", path.display()));
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=scenarios.rs");

    let crate_dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();

    let dir = crate_dir.join("fixtures").join("logs");
    for (name, trace) in [
        ("implicit-context", scenarios::implicit_context()),
        ("since-until", scenarios::since_until()),
    ] {
        let trace = trace.unwrap_or_else(|e| panic!("unable to generate {name} trace: {e}"));
        write(
            &dir.join(name).join("audit.cborseq"),
            &trace
                .to_log_file()
                .unwrap_or_else(|e| panic!("unable to serialize {name} log file: {e}")),
        );
    }
}
