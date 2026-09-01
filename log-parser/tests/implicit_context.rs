// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The crypto-auditing developers.

use anyhow::{Result, bail};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn target_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .map(|mut path| {
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path
        })
        .unwrap()
}

fn run_query() -> Result<Vec<u8>> {
    let query_path = target_dir().join("crau-query");
    let mut command = Command::new(&query_path);

    let command = command
        .arg("-c")
        .arg(fixture_dir().join("conf").join("query.conf"))
        .arg("--log-file")
        .arg(
            fixture_dir()
                .join("logs")
                .join("implicit-context")
                .join("audit.cborseq"),
        );

    let output = command.output()?;
    if !output.status.success() {
        match output.status.code() {
            Some(code) => bail!("crau-query exited with status code: {code}"),
            None => bail!("crau-query terminated by signal"),
        }
    }

    Ok(output.stdout)
}

#[test]
fn test_implicit_context() {
    let output = run_query().expect("crau-query should run");
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("implicit-context")
            .join("audit.json"),
    )
    .expect("should read implicit-context/audit.json");
    assert_eq!(output, expected);
}
