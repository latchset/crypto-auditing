// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2023 The crypto-auditing developers.

use crypto_auditing::event_broker::Client;
use futures::stream::StreamExt;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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

struct EventBrokerProcess(Child);

impl Drop for EventBrokerProcess {
    fn drop(&mut self) {
        self.0.kill().expect("unable to kill event-broker");
    }
}

#[tokio::test]
async fn test_event_broker() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()
        .expect("unable to initialize subscriber");

    let event_broker_path = target_dir().join("crypto-auditing-event-broker");
    let test_dir = tempdir().expect("unable to create temporary directory");

    let log_path = test_dir.path().join("agent.log");
    let _log_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("unable to write log file");

    let socket_path = test_dir.path().join("audit.sock");

    let process = Command::new(&event_broker_path)
        .arg("-c")
        .arg(fixture_dir().join("conf").join("event-broker.conf"))
        .arg("--log-file")
        .arg(&log_path)
        .arg("--socket-path")
        .arg(&socket_path)
        .spawn()
        .expect("unable to spawn event-broker");

    let _process = EventBrokerProcess(process);

    // Wait until the agent starts up
    for _ in 0..5 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(socket_path.exists());

    let client = Client::new()
        .scopes(&vec!["tls".to_string()])
        .address(&socket_path);

    let (_handle, mut reader) = client.start().await.expect("unable to start client");

    // Append more data to log file, from a separate process
    let mut child = std::process::Command::new("cp")
        .arg(&fixture_dir().join("normal").join("output.cborseq"))
        .arg(&log_path)
        .spawn()
        .expect("unable to spawn cp");

    assert!(reader.next().await.is_some());
    child.wait().expect("unable to wait child to complete");
}
