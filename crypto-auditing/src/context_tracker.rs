// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::types::{Context, ContextId, Event, EventGroup};
use std::cell::RefCell;
use std::rc::{Rc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;

#[derive(Debug)]
pub struct ContextTracker {
    all_contexts: Vec<Weak<RefCell<Context>>>,
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
        let contains = |roots: &Vec<Rc<RefCell<Context>>>, context: &Weak<RefCell<Context>>| {
            context
                .upgrade()
                .filter(|context| {
                    roots
                        .iter()
                        .any(|c| Rc::ptr_eq(c, &context) || c.borrow().contains(&context))
                })
                .is_some()
        };
        self.all_contexts
            .retain(|context| !contains(&removed, context));
        removed
            .into_iter()
            .map(|context| Rc::into_inner(context).unwrap().into_inner())
    }

    fn last_context(&self, id: &ContextId) -> Option<Rc<RefCell<Context>>> {
        self.all_contexts
            .iter()
            .rev()
            .find_map(|context| context.upgrade().filter(|c| c.borrow().id == *id))
    }

    fn resolve_system_time(&self, time: Duration) -> SystemTime {
        self.boot_time.checked_add(time).unwrap_or(UNIX_EPOCH)
    }

    pub fn handle_event_group(&mut self, group: &EventGroup) -> usize {
        let start = self.resolve_system_time(group.start());
        let end = self.resolve_system_time(group.end());
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
                        ..Default::default()
                    }));
                    if let Some(parent) = self.last_context(&parent_context) {
                        self.all_contexts.push(Rc::downgrade(&context));
                        parent.borrow_mut().spans.push(context);
                    } else {
                        self.root_contexts.push(context);
                        count += 1;
                    }
                }
                Event::Data { key, value } => {
                    if let Some(parent) = self.last_context(group.context()) {
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
                            start,
                            end,
                            ..Default::default()
                        }));
                        self.all_contexts.push(Rc::downgrade(&context_obj));
                        self.root_contexts.push(context_obj);
                        count += 1;
                    }
                }
            }
        }
        count
    }
}
