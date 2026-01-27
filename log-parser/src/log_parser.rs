// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result};
use clap::Parser;
use crypto_auditing::types::{ContextTracker, EventGroup};
use serde_cbor::de::Deserializer;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(about = "Primary log parser for crypto-auditing")]
struct Cli {
    /// Path to log file to parse
    log_path: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let log_file = std::fs::File::open(&cli.log_path)
        .with_context(|| format!("unable to read file `{}`", cli.log_path.display()))?;
    let mut tracker = ContextTracker::new(None);
    for group in Deserializer::from_reader(&log_file).into_iter::<EventGroup>() {
        tracker.handle_event_group(&group?);
    }
    let root_contexts: Vec<_> = tracker.flush(None).into_iter().collect();
    println!("{}", serde_json::to_string_pretty(&root_contexts).unwrap());
    Ok(())
}
