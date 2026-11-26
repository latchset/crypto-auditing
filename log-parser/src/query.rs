// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result};
use crypto_auditing::{
    ContextTracker,
    schema::Schema,
    types::{EventData, EventGroup},
};
use jiff::Zoned;
use pager::Pager;
use serde_cbor::de::Deserializer;
use std::io::{self, Write};
use std::ops::Bound;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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

fn to_bound(time: &Option<Zoned>) -> Bound<SystemTime> {
    time.as_ref()
        .map_or(Bound::Unbounded, |time| Bound::Included(time.into()))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::Config::new()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let log_file = std::fs::File::open(&config.log_file)
        .with_context(|| format!("unable to read file `{}`", config.log_file.display()))?;

    let mut groups = Deserializer::from_reader(&log_file)
        .into_iter::<EventGroup>()
        .peekable();

    let metadata = if let Some(Ok(group)) = groups.peek()
        && group.is_metadata()
    {
        groups
            .next()
            .map(|group| group.expect("should be a metadata group"))
    } else {
        None
    };

    // Figure out the system boot time, first from the config, and
    // then from the metadata group in the log
    let boot_time = if let Some(secs) = config.boot_time {
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    } else if let Some(metadata) = metadata {
        get_boot_time_from_metadata(&metadata)
    } else {
        None
    };

    let mut tracker = ContextTracker::new(boot_time);
    let schema = Schema::builtin();
    tracker.set_schema(schema);
    tracker.set_range((to_bound(&config.since), to_bound(&config.until)));

    // Periodically flush the contexts started more than the event
    // window ago, so the tracker does not have to keep all the
    // contexts in the log.  Unlike the monitor, the timestamps
    // recorded in the log are used instead of the system time.
    let mut root_contexts = Vec::new();
    let mut next_flush = None;
    for group in groups {
        tracker.handle_event_group(&group?);

        let Some(now) = tracker.latest() else {
            continue;
        };
        match next_flush {
            Some(next_flush) if now < next_flush => continue,
            Some(_) => {
                if let Some(before) = now.checked_sub(config.event_window) {
                    root_contexts.extend(tracker.flush(before));
                }
            }
            None => (),
        }
        next_flush = now.checked_add(config.event_window);
    }
    root_contexts.extend(tracker.flush_all());
    let content = serde_json::to_string_pretty(&root_contexts)?;

    Pager::new().setup();

    if let Err(e) = io::stdout().write_all(content.as_bytes()) {
        if e.kind() != io::ErrorKind::BrokenPipe {
            return Err(Box::new(e));
        }
    }
    Ok(())
}
