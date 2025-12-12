// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result};
use crypto_auditing::types::{ContextTracker, EventGroup};
use pager::Pager;
use serde_cbor::de::Deserializer;
use std::io::{self, Write};

mod config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::Config::new()?;
    Pager::new().skip_on_notty().setup();

    let log_file = std::fs::File::open(&config.log_file)
        .with_context(|| format!("unable to read file `{}`", config.log_file.display()))?;

    let mut tracker = ContextTracker::new(None);
    for group in Deserializer::from_reader(&log_file).into_iter::<EventGroup>() {
        tracker.handle_event_group(&group?);
    }
    let root_contexts: Vec<_> = tracker.flush(None).into_iter().collect();
    let content = serde_json::to_string_pretty(&root_contexts)?;
    if let Err(e) = io::stdout().write_all(content.as_bytes()) {
        if e.kind() != io::ErrorKind::BrokenPipe {
            return Err(Box::new(e));
        }
    }
    Ok(())
}
