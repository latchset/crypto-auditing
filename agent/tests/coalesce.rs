// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2023 The crypto-auditing developers.

extern crate agenttest;
use agenttest::*;

use crypto_auditing::types::EventGroup;
use probe::probe;
use serde_cbor::de::Deserializer;
use std::env;
use std::panic;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

#[test]
fn test_probe_coalesce() {
    bump_memlock_rlimit().expect("unable to bump memlock rlimit");

    let agent_path = agent_path();
    let log_dir = tempdir().expect("unable to create temporary directory");
    let log_path = log_dir.path().join("agent.log");
    let mut process = Command::new(&agent_path)
        .arg("-c")
        .arg(fixture_dir().join("agent.conf"))
        .arg("--log-file")
        .arg(&log_path)
        .arg("--library")
        .arg(&env::current_exe().unwrap())
        .arg("--coalesce-window")
        .arg("1000")
        .spawn()
        .expect("unable to spawn agent");

    // Wait until the agent process starts up
    for _ in 0..5 {
        if log_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(log_path.exists());

    let result = panic::catch_unwind(|| {
        let foo = String::from("foo\0");
        let bar = String::from("bar\0");
        let baz = String::from("baz\0");

        let (_link, object) =
            attach_bpf(&process, &agent_path).expect("unable to attach agent.bpf.o");
        let map = object.map("ringbuf").expect("unable to get ringbuf map");

        let timeout = Duration::from_secs(10);

        let result = with_ringbuffer(
            map,
            || {
                probe!(crypto_auditing, new_context, 1, 2);
                probe!(crypto_auditing, word_data, 1, foo.as_ptr(), 3);
                probe!(crypto_auditing, string_data, 1, bar.as_ptr(), bar.as_ptr());
                probe!(
                    crypto_auditing,
                    blob_data,
                    1,
                    baz.as_ptr(),
                    baz.as_ptr(),
                    baz.len()
                );
            },
            timeout,
        )
        .expect("unable to exercise probe points");
        assert_eq!(result, 4);
        let result = with_ringbuffer(
            map,
            || {
                probe!(crypto_auditing, new_context, 4, 5);
            },
            timeout,
        )
        .expect("unable to exercise probe points");
        assert_eq!(result, 1);

        let log_file = std::fs::File::open(&log_path)
            .expect(&format!("unable to read file `{}`", log_path.display()));

        let groups: Result<Vec<_>, _> = Deserializer::from_reader(&log_file)
            .into_iter::<EventGroup>()
            .collect();
        let groups = groups.expect("error deserializing");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].events().len(), 4);
        assert_eq!(groups[1].events().len(), 1);
    });

    process.kill().expect("unable to kill agent");

    assert!(result.is_ok());
}
