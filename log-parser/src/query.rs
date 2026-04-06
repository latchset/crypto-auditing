// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result};
use crypto_auditing::types::{ContextTracker, EventData, EventGroup};
use pager::Pager;
use serde_cbor::de::Deserializer;
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod config;

fn get_boot_time_from_metadata(group: &EventGroup) -> Option<SystemTime> {
    for event in group.events() {
        if let Some(data) = event.data("boot_time") {
            match data {
                EventData::Word(secs) => {
                    return Some(UNIX_EPOCH + Duration::from_secs(*secs as u64));
                }
                _ => (),
            }
        }
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::Config::new()?;
    Pager::new().setup();

    let log_file = std::fs::File::open(&config.log_file)
        .with_context(|| format!("unable to read file `{}`", config.log_file.display()))?;

    let mut groups = Deserializer::from_reader(&log_file)
        .into_iter::<EventGroup>()
        .peekable();

    // Figure out the system boot time, first from the config, and
    // then from the metadata group in the log
    let boot_time = if let Some(secs) = config.boot_time {
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    } else if let Some(Ok(group)) = groups.peek()
        && group.is_metadata()
    {
        let boot_time = get_boot_time_from_metadata(&group);
        // Skip the metadata group
        groups.next();
        boot_time
    } else {
        None
    };

    let mut tracker = ContextTracker::new(boot_time);
    for group in groups {
        tracker.handle_event_group(&group?);
    }
    let root_contexts: Vec<_> = tracker
        .flush(None)
        .into_iter()
        .filter(|c| match (&config.since, &config.until) {
            (Some(since), Some(until)) => c.start >= since.into() && c.end <= until.into(),
            (Some(since), None) => c.start >= since.into(),
            (None, Some(until)) => c.end <= until.into(),
            (None, None) => true,
        })
        .collect();
    let content = serde_json::to_string_pretty(&root_contexts)?;
    if let Err(e) = io::stdout().write_all(content.as_bytes()) {
        if e.kind() != io::ErrorKind::BrokenPipe {
            return Err(Box::new(e));
        }
    }
    Ok(())
}
