// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::{
    schema::{self, Schema},
    types::{Context, ContextId, Event, EventGroup},
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tracing::{debug, info};

struct Ancestors<'a> {
    parents: &'a HashMap<ContextId, ContextId>,
    current: &'a ContextId,
}

impl<'a> Ancestors<'a> {
    fn new(parents: &'a HashMap<ContextId, ContextId>, current: &'a ContextId) -> Self {
        Self { parents, current }
    }
}

impl<'a> Iterator for Ancestors<'a> {
    type Item = &'a ContextId;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(parent) = self.parents.get(self.current) {
            self.current = parent;
            Some(parent)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct ContextTracker {
    all_contexts: Vec<Weak<RefCell<Context>>>,
    root_contexts: Vec<Rc<RefCell<Context>>>,
    larval_contexts: HashMap<ContextId, Rc<RefCell<Context>>>,
    parents: HashMap<ContextId, ContextId>,
    explicit_parents: HashMap<ContextId, ContextId>,
    schema: Option<Schema>,
    implicit_contexts: HashMap<ContextId, Vec<Weak<RefCell<Context>>>>,
    boot_time: SystemTime,
}

impl ContextTracker {
    pub fn new(boot_time: Option<SystemTime>) -> Self {
        Self {
            all_contexts: Vec::new(),
            root_contexts: Vec::new(),
            larval_contexts: HashMap::new(),
            parents: HashMap::new(),
            explicit_parents: HashMap::new(),
            schema: Default::default(),
            implicit_contexts: Default::default(),
            boot_time: boot_time.unwrap_or_else(|| {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(System::boot_time()))
                    .unwrap()
            }),
        }
    }

    pub fn flush(&mut self, before: Option<SystemTime>) -> impl IntoIterator<Item = Context> {
        let mut removed = Vec::new();
        let mut root_contexts = Vec::new();
        let not_expired = |context: &Rc<RefCell<Context>>| matches!(before, Some(before) if context.borrow().start > before);
        self.root_contexts.retain(|context| {
            if not_expired(context) {
                true
            } else {
                root_contexts.push(context.clone());
                removed.push(context.clone());
                false
            }
        });
        self.larval_contexts.retain(|_id, context| {
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
        self.implicit_contexts
            .values_mut()
            .for_each(|contexts| contexts.retain(|context| !contains(&removed, context)));
        self.implicit_contexts
            .retain(|_id, contexts| !contexts.is_empty());
        self.explicit_parents.retain(|id, _parent_id| {
            self.all_contexts
                .iter()
                .any(|c| c.upgrade().filter(|c| c.borrow().id == *id).is_some())
        });
        self.parents.retain(|id, _parent_id| {
            self.all_contexts
                .iter()
                .any(|c| c.upgrade().filter(|c| c.borrow().id == *id).is_some())
        });
        root_contexts
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

    fn is_potential_parent(
        schema: &Schema,
        parent_context: &Context,
        child_name: &schema::Name,
    ) -> bool {
        parent_context
            .name()
            .map(
                |parent_name| match TryInto::<schema::Name>::try_into(parent_name) {
                    Ok(parent_name) => schema.is_parent(&parent_name, child_name),
                    Err(e) => {
                        debug!(error = %e, "unable to parse parent name");
                        false
                    }
                },
            )
            .unwrap_or(false)
    }

    fn ancestor(
        &self,
        parents: &HashMap<ContextId, ContextId>,
        id: &ContextId,
    ) -> Option<Rc<RefCell<Context>>> {
        Ancestors::new(parents, id).find_map(move |ancestor_id| self.last_context(ancestor_id))
    }

    fn handle_implicit_context(
        &mut self,
        context: Rc<RefCell<Context>>,
        name: &schema::Name,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let id = context.borrow().id;
        let schema = self.schema.as_ref().expect("schema must be set");

        {
            let implicit_contexts = self.implicit_contexts.entry(id).or_default();

            while let Some(c) = implicit_contexts.pop_if(|c| {
                c.upgrade()
                    .filter(|c| !Self::is_potential_parent(schema, &c.borrow(), name))
                    .is_some()
            }) {
                if let Some(c) = c.upgrade() {
                    debug!("{:?} cannot be a parent of {}", c.borrow().name(), name);
                }
            }

            if let Some(last) = implicit_contexts.iter().last() {
                self.all_contexts.push(Rc::downgrade(&context));
                if let Some(last) = last.upgrade() {
                    debug!(
                        "adding {:?} as a child of {:?} (id {:02x?})",
                        context.borrow().name(),
                        last.borrow().name(),
                        &context.borrow().id[..]
                    );
                    implicit_contexts.push(Rc::downgrade(&context));
                    last.borrow_mut().spans.push(context);
                }
                return Ok(false);
            }

            implicit_contexts.push(Rc::downgrade(&context));
        }

        if let Some(parent) = self.ancestor(&self.explicit_parents, &id) {
            debug!(
                "no implicit parent of {:?} found, but explicit parent is {:?} (id {:02x?}, parent_id {:02x?})",
                context.borrow().name(),
                parent.borrow().name(),
                &id[..],
                &parent.borrow().id[..],
            );
            if Self::is_potential_parent(schema, &parent.borrow(), name) {
                return self.add_to_parent(parent, context);
            } else {
                debug!(
                    "schema doesn't allow {:?} to be a child of {:?} (id {:02x?})",
                    context.borrow().name(),
                    parent.borrow().name(),
                    &context.borrow().id[..]
                );
            }
        }

        self.add_to_root(context)
    }

    fn handle_explicit_context(
        &mut self,
        context: Rc<RefCell<Context>>,
        parent_id: ContextId,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if let Some(parent_context) = self.last_context(&parent_id) {
            self.add_to_parent(parent_context, context)
        } else {
            self.add_to_root(context)
        }
    }

    fn add_to_parent(
        &mut self,
        parent_context: Rc<RefCell<Context>>,
        context: Rc<RefCell<Context>>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        debug!(
            "adding {:?} as a child of {:?} (id {:02x?})",
            context.borrow().name(),
            parent_context.borrow().name(),
            &context.borrow().id[..]
        );
        self.all_contexts.push(Rc::downgrade(&context));
        parent_context.borrow_mut().spans.push(context);
        Ok(false)
    }

    fn add_to_root(
        &mut self,
        context: Rc<RefCell<Context>>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        debug!(
            "adding {:?} at top-level (id {:02x?})",
            context.borrow().name(),
            &context.borrow().id[..]
        );
        self.all_contexts.push(Rc::downgrade(&context));
        self.root_contexts.push(context);
        Ok(true)
    }

    // Returns `true` if a root context is created
    fn handle_event(
        &mut self,
        id: &ContextId,
        start: SystemTime,
        end: SystemTime,
        event: &Event,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match event {
            Event::NewContext {
                parent: parent_id,
                origin,
                executable,
            } => {
                let larval_context = Rc::new(RefCell::new(Context {
                    id: *id,
                    origin: origin.to_owned(),
                    executable: executable.to_owned(),
                    start,
                    end,
                    ..Default::default()
                }));
                self.larval_contexts.insert(*id, larval_context);
                if parent_id != id {
                    self.explicit_parents.insert(*id, *parent_id);
                }
                self.parents.insert(*id, *parent_id);
                Ok(false)
            }
            Event::Data { key, value } if key == "name" => {
                let name = value.string().ok_or(schema::ValueError {})?;
                let larval_context = self.larval_contexts.remove(id).unwrap_or_else(|| {
                    Rc::new(RefCell::new(Context {
                        id: *id,
                        start,
                        end,
                        ..Default::default()
                    }))
                });
                larval_context
                    .borrow_mut()
                    .events
                    .insert(key.to_string(), value.clone());
                if let Some(parent_id) = self.parents.remove(id) {
                    if self.schema.is_some() && parent_id == *id {
                        self.handle_implicit_context(larval_context, &name.try_into()?)
                    } else {
                        self.handle_explicit_context(larval_context, parent_id)
                    }
                } else {
                    self.add_to_root(larval_context)
                }
            }
            Event::Data { key, value } => {
                if let Some(context) = self.last_context(id) {
                    context
                        .borrow_mut()
                        .events
                        .insert(key.to_string(), value.clone());
                    Ok(false)
                } else {
                    info!(key = ?key, value = ?value,
                          "event received for {:02x?} but no corresponding context found, skipping", id);
                    Ok(false)
                }
            }
        }
    }

    /// Returns the number of root contexts created from `group`
    pub fn handle_event_group(&mut self, group: &EventGroup) -> usize {
        let start = self.resolve_system_time(group.start());
        let end = self.resolve_system_time(group.end());
        let mut count = 0;
        for event in group.events() {
            match self.handle_event(group.context(), start, end, event) {
                Ok(res) => {
                    if res {
                        count += 1;
                    }
                }
                Err(e) => info!(error = %e, "error while handling event {:#?}",
                                event),
            }
        }
        count
    }

    pub fn set_schema(&mut self, schema: Schema) {
        self.schema = Some(schema);
    }

    pub fn root_context_count(&self) -> usize {
        self.root_contexts.len()
    }

    pub fn context_count(&self) -> usize {
        self.all_contexts.len()
    }
}
