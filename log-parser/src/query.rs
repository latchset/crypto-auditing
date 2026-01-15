// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result};
use crypto_auditing::types::{Context, ContextID, Event, EventGroup};
use pager::Pager;
use serde_cbor::de::Deserializer;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::rc::Rc;

mod config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::Config::new()?;
    Pager::new().setup();

    let log_file = std::fs::File::open(&config.log_file)
        .with_context(|| format!("unable to read file `{}`", config.log_file.display()))?;
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
    let content = serde_json::to_string_pretty(&root_contexts)?;
    if let Err(e) = io::stdout().write_all(content.as_bytes()) {
        if e.kind() != io::ErrorKind::BrokenPipe {
            return Err(Box::new(e));
        }
    }
    Ok(())
}
