// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result};
use clap::Parser;
use crypto_auditing::types::{ContextID, Event, EventData, EventGroup};
use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};
use serde_cbor::de::Deserializer;
use serde_with::{hex::Hex, serde_as};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

fn only_values<K, V, S>(source: &BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    V: Serialize,
{
    let mut seq = serializer.serialize_seq(Some(source.len()))?;
    for value in source.values() {
        seq.serialize_element(value)?;
    }
    seq.end()
}

#[serde_as]
#[derive(Default, Serialize)]
struct Context {
    #[serde_as(as = "Hex")]
    context: ContextID,
    #[serde_as(as = "Hex")]
    origin: Vec<u8>,
    #[serde_as(as = "serde_with::DurationNanoSeconds<u64>")]
    start: Duration,
    #[serde_as(as = "serde_with::DurationNanoSeconds<u64>")]
    end: Duration,
    events: BTreeMap<String, EventData>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(serialize_with = "only_values")]
    spans: BTreeMap<ContextID, Rc<RefCell<Context>>>,
}

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
    let mut all_contexts: BTreeMap<ContextID, Rc<RefCell<Context>>> = BTreeMap::new();
    let mut root_contexts = Vec::new();
    for group in Deserializer::from_reader(&log_file).into_iter::<EventGroup>() {
        let group = group?;
        for event in group.events() {
            match event {
                Event::NewContext {
                    parent: parent_context,
                    origin,
                } => {
                    let context = Rc::new(RefCell::new(Context {
                        context: *group.context(),
                        origin: origin.to_owned(),
                        start: group.start(),
                        end: group.end(),
                        ..Default::default()
                    }));
                    if let Some(parent) = all_contexts.get(&parent_context[..]) {
                        parent
                            .borrow_mut()
                            .spans
                            .insert(*group.context(), context.clone());
                    } else {
                        root_contexts.push(context.clone());
                    }
                    all_contexts.insert(*group.context(), context);
                }
                Event::Data { key, value } => {
                    if !all_contexts.contains_key(group.context()) {
                        // Either this library did not do a new_context for this context, or the
                        // log we have is truncated at the beginning. Just assume that this context
                        // has no parent and create a new one so we don't loose the information in
                        // this message.
                        let context_obj = Rc::new(RefCell::new(Context {
                            context: *group.context(),
                            start: group.start(),
                            end: group.end(),
                            ..Default::default()
                        }));
                        root_contexts.push(context_obj.clone());
                        all_contexts.insert(*group.context(), context_obj);
                    }
                    if let Some(parent) = all_contexts.get(group.context()) {
                        parent
                            .borrow_mut()
                            .events
                            .insert(key.to_string(), value.clone());
                    }
                }
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&root_contexts).unwrap());
    Ok(())
}
