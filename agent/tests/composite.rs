// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2023 The crypto-auditing developers.

extern crate agenttest;
use agenttest::*;

use crypto_auditing::types::{Event, EventGroup};
use libc::{c_long, c_uchar, c_void};
use probe::probe;
use serde_cbor::de::Deserializer;
use std::env;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

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

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("fixtures")
}

struct AgentProcess(Child);

impl Drop for AgentProcess {
    fn drop(&mut self) {
        self.0.kill().expect("unable to kill event-broker");
    }
}

#[repr(C)]
struct EventData {
    key_ptr: *const c_uchar,
    value_ptr: *const c_void,
    value_size: c_long,
}

#[test]
fn test_probe_composite() {
    bump_memlock_rlimit().expect("unable to bump memlock rlimit");

    let agent_path = target_dir().join("crypto-auditing-agent");
    let log_dir = tempdir().expect("unable to create temporary directory");
    let log_path = log_dir.path().join("agent.log");
    let process = Command::new(&agent_path)
        .arg("-c")
        .arg(fixture_dir().join("conf").join("agent.conf"))
        .arg("--log-file")
        .arg(&log_path)
        .arg("--library")
        .arg(&env::current_exe().unwrap())
        .spawn()
        .expect("unable to spawn agent");

    // Make sure the agent process will be killed at exit
    let process = AgentProcess(process);

    // Wait until the agent starts up
    for _ in 0..5 {
        if log_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(log_path.exists());

    let foo = String::from("foo\0");
    let bar = String::from("bar\0");
    let baz = String::from("baz\0");
    let events = vec![
        EventData {
            key_ptr: foo.as_ptr(),
            value_ptr: 3 as *const c_void,
            value_size: -2,
        },
        EventData {
            key_ptr: bar.as_ptr(),
            value_ptr: bar.as_ptr() as *const c_void,
            value_size: -1,
        },
        EventData {
            key_ptr: baz.as_ptr(),
            value_ptr: baz.as_ptr() as *const c_void,
            value_size: baz.len() as i64,
        },
    ];

    let mut storage = MaybeUninit::uninit();
    let (_link, skel) =
        attach_bpf(&process.0, &agent_path, &mut storage).expect("unable to attach agent.bpf.o");

    let timeout = Duration::from_secs(10);

    let result = with_ringbuffer(
        &skel.maps.ringbuf,
        || {
            probe!(crypto_auditing, new_context, 1, 2);
        },
        timeout,
    )
    .expect("unable to exercise probe points");
    assert_eq!(result, 1);

    let result = with_ringbuffer(
        &skel.maps.ringbuf,
        || {
            probe!(crypto_auditing, data, 1, events.as_ptr(), events.len());
        },
        timeout,
    )
    .expect("unable to exercise probe points");
    assert_eq!(result, 1);

    let result = with_ringbuffer(
        &skel.maps.ringbuf,
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
    assert_eq!(groups.len(), 5);
    assert_eq!(groups[0].events().len(), 1);
    assert!(matches!(groups[0].events()[0], Event::NewContext { .. }));
    assert_eq!(groups[1].events().len(), 1);
    if let Event::Data { key, .. } = &groups[1].events()[0] {
        assert_eq!(key, "foo");
    } else {
        unreachable!();
    }
    assert_eq!(groups[2].events().len(), 1);
    if let Event::Data { key, .. } = &groups[2].events()[0] {
        assert_eq!(key, "bar");
    } else {
        unreachable!();
    }
    assert_eq!(groups[3].events().len(), 1);
    if let Event::Data { key, .. } = &groups[3].events()[0] {
        assert_eq!(key, "baz");
    } else {
        unreachable!();
    }
    assert_eq!(groups[4].events().len(), 1);
    assert!(matches!(groups[4].events()[0], Event::NewContext { .. }));
}
