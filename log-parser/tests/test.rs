// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The crypto-auditing developers.

use anyhow::{Result, bail};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const START_TIME: &str = "2026-02-25 08:13:23JST";
const BOOT_TIME: u64 = 1771970837;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("fixtures")
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

fn run_query(since: Option<String>, until: Option<String>) -> Result<Vec<u8>> {
    let query_path = target_dir().join("crau-query");
    let mut command = Command::new(&query_path);

    let mut command = command
        .arg("-c")
        .arg(fixture_dir().join("conf").join("query.conf"))
        .arg("--log-file")
        .arg(
            fixture_dir()
                .join("logs")
                .join("since-until")
                .join("audit.cborseq"),
        )
        .arg("--boot-time")
        .arg(BOOT_TIME.to_string());

    if let Some(since) = since {
        command = command.arg("--since").arg(&since);
    }

    if let Some(until) = until {
        command = command.arg("--until").arg(&until)
    }

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
fn test_since_until() {
    let output = run_query(None, None).expect("crau-query should run");
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("none.json"),
    )
    .expect("should read since-until/none.json");
    assert_eq!(output, expected);

    let output =
        run_query(Some(format!("{START_TIME} + 1 mins")), None).expect("crau-query should run");
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("since.json"),
    )
    .expect("should read since-until/since.json");
    assert_eq!(output, expected);

    let output = run_query(
        Some(format!("{START_TIME} + 1 mins")),
        Some(format!("{START_TIME} + 2 mins")),
    )
    .expect("crau-query should run");
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("since-until.json"),
    )
    .expect("should read since-until/since-until.json");
    assert_eq!(output, expected);

    let output =
        run_query(None, Some(format!("{START_TIME} + 2 mins"))).expect("crau-query should run");
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("until.json"),
    )
    .expect("should read since-until/until.json");
    assert_eq!(output, expected);
}
