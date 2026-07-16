// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::types::{Context, Event, EventGroup};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;

#[derive(Debug)]
pub struct ContextTracker {
    all_contexts: Vec<Rc<RefCell<Context>>>,
    root_contexts: Vec<Rc<RefCell<Context>>>,
    boot_time: SystemTime,
}

impl ContextTracker {
    pub fn new(boot_time: Option<SystemTime>) -> Self {
        Self {
            all_contexts: Vec::new(),
            root_contexts: Vec::new(),
            boot_time: boot_time.unwrap_or_else(|| {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(System::boot_time()))
                    .unwrap()
            }),
        }
    }

    pub fn flush(&mut self, before: Option<SystemTime>) -> impl IntoIterator<Item = Context> {
        let mut removed = Vec::new();
        let not_expired = |context: &Rc<RefCell<Context>>| matches!(before, Some(before) if context.borrow().start > before);
        self.root_contexts.retain(|context| {
            if not_expired(context) {
                true
            } else {
                removed.push(context.clone());
                false
            }
        });
        self.all_contexts.retain(|context| not_expired(context));
        removed
            .into_iter()
            .map(|context| Rc::into_inner(context).unwrap().into_inner())
    }

    pub fn handle_event_group(&mut self, group: &EventGroup) -> usize {
        let start = self
            .boot_time
            .checked_add(group.start())
            .unwrap_or(UNIX_EPOCH);
        let end = self
            .boot_time
            .checked_add(group.end())
            .unwrap_or(UNIX_EPOCH);
        let mut count = 0;
        for event in group.events() {
            match event {
                Event::NewContext {
                    parent: parent_context,
                    origin,
                    executable,
                } => {
                    let context = Rc::new(RefCell::new(Context {
                        id: *group.context(),
                        origin: origin.to_owned(),
                        executable: executable.to_owned(),
                        start,
                        end,
                        events: Default::default(),
                        spans: Default::default(),
                    }));
                    if let Some(parent) = self
                        .all_contexts
                        .iter()
                        .rev()
                        .find(|x| x.borrow().id == parent_context[..])
                    {
                        parent.borrow_mut().spans.push(context.clone());
                    } else {
                        self.root_contexts.push(context.clone());
                        count += 1;
                    }
                    self.all_contexts.push(context);
                }
                Event::Data { key, value } => {
                    if let Some(parent) = self
                        .all_contexts
                        .iter()
                        .rev()
                        .find(|x| x.borrow().id == *group.context())
                    {
                        parent
                            .borrow_mut()
                            .events
                            .insert(key.to_string(), value.clone());
                    } else {
                        // Either this library did not do a new_context for this context, or the
                        // log we have is truncated at the beginning. Just assume that this context
                        // has no parent and create a new one so we don't lose the information in
                        // this message.
                        let context_obj = Rc::new(RefCell::new(Context {
                            id: *group.context(),
                            origin: Default::default(),
                            executable: Default::default(),
                            start,
                            end,
                            events: Default::default(),
                            spans: Default::default(),
                        }));
                        self.root_contexts.push(context_obj.clone());
                        self.all_contexts.push(context_obj);
                        count += 1;
                    }
                }
            }
        }
        count
    }
}
