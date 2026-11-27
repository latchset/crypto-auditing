// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The crypto-auditing developers.

use anyhow::{Result, bail};
use similar_asserts::assert_eq;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const START_TIME: &str = "2026-02-25 08:13:23JST";
const BOOT_TIME: u64 = 1771970837;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn run_query(
    since: Option<String>,
    until: Option<String>,
    event_window: Option<u64>,
) -> Result<Vec<u8>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_crau-query"));

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

    if let Some(event_window) = event_window {
        command = command.arg("--event-window").arg(event_window.to_string())
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
    let output = run_query(None, None, None).expect("crau-query should run");
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("none.json"),
    )
    .expect("should read since-until/none.json");
    let output = String::from_utf8(output).expect("should be in valid UTF-8");
    let expected = String::from_utf8(expected).expect("should be in valid UTF-8");
    assert_eq!(output, expected);

    let output = run_query(Some(format!("{START_TIME} + 1 mins")), None, None)
        .expect("crau-query should run");
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("since.json"),
    )
    .expect("should read since-until/since.json");
    let output = String::from_utf8(output).expect("should be in valid UTF-8");
    let expected = String::from_utf8(expected).expect("should be in valid UTF-8");
    assert_eq!(output, expected);

    let output = run_query(
        Some(format!("{START_TIME} + 1 mins")),
        Some(format!("{START_TIME} + 2 mins")),
        None,
    )
    .expect("crau-query should run");
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("since-until.json"),
    )
    .expect("should read since-until/since-until.json");
    let output = String::from_utf8(output).expect("should be in valid UTF-8");
    let expected = String::from_utf8(expected).expect("should be in valid UTF-8");
    assert_eq!(output, expected);

    let output = run_query(None, Some(format!("{START_TIME} + 2 mins")), None)
        .expect("crau-query should run");
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("until.json"),
    )
    .expect("should read since-until/until.json");
    let output = String::from_utf8(output).expect("should be in valid UTF-8");
    let expected = String::from_utf8(expected).expect("should be in valid UTF-8");
    assert_eq!(output, expected);
}

#[test]
fn test_event_window() {
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("none.json"),
    )
    .expect("should read since-until/none.json");
    let expected = String::from_utf8(expected).expect("should be in valid UTF-8");

    // The handshakes are a minute apart from each other, so the
    // output should be the same whether they are flushed one by one
    // or all at once
    for event_window in [100, 10_000, 3_600_000] {
        let output = run_query(None, None, Some(event_window)).expect("crau-query should run");
        let output = String::from_utf8(output).expect("should be in valid UTF-8");
        assert_eq!(output, expected, "event window {event_window}");
    }
}

#[test]
fn test_event_window_until() {
    let expected = fs::read(
        fixture_dir()
            .join("logs")
            .join("since-until")
            .join("until.json"),
    )
    .expect("should read since-until/until.json");
    let expected = String::from_utf8(expected).expect("should be in valid UTF-8");

    // The log is read only until the event window has passed the
    // end of the range, which shouldn't affect the output
    for event_window in [100, 10_000, 3_600_000] {
        let output = run_query(
            None,
            Some(format!("{START_TIME} + 2 mins")),
            Some(event_window),
        )
        .expect("crau-query should run");
        let output = String::from_utf8(output).expect("should be in valid UTF-8");
        assert_eq!(output, expected, "event window {event_window}");
    }
}
