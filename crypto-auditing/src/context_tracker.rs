// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::{
    schema::{self, Schema},
    types::{Context, ContextId, Event, EventGroup},
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tracing::debug;

#[derive(Debug)]
pub struct ContextTracker {
    all_contexts: Vec<Rc<RefCell<Context>>>,
    root_contexts: Vec<Rc<RefCell<Context>>>,
    parents: HashMap<schema::Name, Vec<schema::Name>>,
    pending_contexts: HashMap<ContextId, Rc<RefCell<Context>>>,
    implicit_contexts: HashMap<ContextId, Vec<Rc<RefCell<Context>>>>,
    implicit_counter: u16,
    boot_time: SystemTime,
}

impl ContextTracker {
    pub fn new(boot_time: Option<SystemTime>) -> Self {
        Self {
            all_contexts: Vec::new(),
            root_contexts: Vec::new(),
            pending_contexts: HashMap::new(),
            implicit_contexts: HashMap::new(),
            implicit_counter: 0u16,
            parents: HashMap::new(),
            boot_time: boot_time.unwrap_or_else(|| {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(System::boot_time()))
                    .unwrap()
            }),
        }
    }

    fn extract_parents(&mut self, scope: &schema::Scope, parent: &schema::ContextEvent) {
        let mut children = Vec::new();
        for event in parent.events.iter() {
            if let schema::Event::ContextEvent(child) = event {
                children.push(schema::Name::new(&scope.name, &child.name));
                self.extract_parents(scope, child);
            }
        }
        for child in children {
            self.parents
                .insert(child, vec![schema::Name::new(&scope.name, &parent.name)]);
        }
    }

    fn extract_allowed_children(
        &mut self,
        scope: &schema::Scope,
        parent: &schema::ContextEvent,
        roots: &HashMap<String, Vec<schema::Name>>,
    ) {
        let mut children = Vec::new();
        for pattern in parent.allowed_children.iter() {
            match pattern {
                schema::Pattern {
                    scope: s,
                    context: None,
                } => {
                    if let Some(r) = roots.get(s) {
                        children.append(&mut r.to_vec());
                    }
                }
                schema::Pattern {
                    scope: s,
                    context: Some(c),
                } => {
                    children.push(schema::Name::new(s, c));
                }
            }
        }
        for event in parent.events.iter() {
            match event {
                schema::Event::ContextEvent(child) => {
                    self.extract_allowed_children(scope, child, roots);
                }
                _ => {}
            }
        }
        for child in children {
            if let Some(v) = self.parents.get_mut(&child) {
                v.push(child);
            } else {
                self.parents.insert(
                    child,
                    vec![schema::Name::new(scope.name.as_str(), parent.name.as_str())],
                );
            }
        }
    }

    pub fn set_schema(&mut self, schema: &Schema) {
        // Extract root contexts
        let mut roots: HashMap<String, Vec<schema::Name>> = HashMap::new();
        for scope in schema.scopes.iter() {
            roots.insert(
                scope.name.to_owned(),
                scope
                    .context_events
                    .iter()
                    .map(|c| schema::Name::new(&scope.name, &c.name))
                    .collect(),
            );
        }

        // Recursively extract direct mappings
        for scope in schema.scopes.iter() {
            for context in scope.context_events.iter() {
                self.extract_parents(scope, context);
            }
        }

        // Recursively extract indirect mappings through
        // allowed_children
        for scope in schema.scopes.iter() {
            for context in scope.context_events.iter() {
                self.extract_allowed_children(scope, context, &roots);
            }
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
        self.implicit_contexts
            .values_mut()
            .for_each(|contexts| contexts.retain(|context| not_expired(context)));
        removed
            .into_iter()
            .map(|context| Rc::into_inner(context).unwrap().into_inner())
    }

    fn is_potential_parent(
        parents: &HashMap<schema::Name, Vec<schema::Name>>,
        context: &Context,
        child_name: &schema::Name,
    ) -> bool {
        if let Some(parent_name) = context.name() {
            match TryInto::<schema::Name>::try_into(parent_name) {
                Ok(parent_name) => {
                    if let Some(parent_names) = parents.get(child_name) {
                        return parent_names.iter().any(|p| *p == parent_name);
                    }
                }
                Err(e) => {
                    debug!(error = %e, "unable to parse parent name");
                }
            }
        }
        false
    }

    fn is_implicit_context(&self, id: &ContextId) -> bool {
        if self.pending_contexts.contains_key(id) {
            return true;
        }
        if let Some(v) = self.implicit_contexts.get(id) {
            return !v.is_empty();
        }
        false
    }

    fn handle_pending_context(
        &mut self,
        context: &Rc<RefCell<Context>>,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let implicit_contexts = self
            .implicit_contexts
            .entry(context.borrow().id)
            .or_insert(Vec::new());

        let name: schema::Name = name.try_into()?;

        while let Some(c) = implicit_contexts
            .pop_if(|c| !Self::is_potential_parent(&self.parents, &c.borrow(), &name))
        {
            debug!("{:?} cannot be a parent of {:?}", c.borrow().name(), name);
        }

        if let Some(last) = implicit_contexts.iter().last() {
            last.borrow_mut().spans.push(context.clone());
            debug!(
                "adding {:?} as a child of {:?} (id {:02x?})",
                context.borrow().name(),
                last.borrow().name(),
                &context.borrow().id[..]
            );
        } else {
            debug!(
                "adding {:?} at top-level (id {:02x?})",
                context.borrow().name(),
                &context.borrow().id[..]
            );
            self.root_contexts.push(context.clone());
        }

        implicit_contexts.push(context.clone());

        Ok(())
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

                    if &context.borrow().id == parent_context {
                        self.pending_contexts
                            .insert(context.borrow().id, context.clone());
                    } else {
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
                    }
                    self.all_contexts.push(context);
                }
                Event::Data { key, value } => {
                    if self.is_implicit_context(group.context()) {
                        if key == "name"
                            && let Some(name) = value.string()
                            && let Some(pending_context) =
                                self.pending_contexts.remove(group.context())
                        {
                            pending_context
                                .borrow_mut()
                                .events
                                .insert(key.to_string(), value.clone());

                            match self.handle_pending_context(&pending_context, name) {
                                Ok(()) => {
                                    // Modify the last two bytes to
                                    // make the context ID unique
                                    // among implicit context events.
                                    pending_context.borrow_mut().id[14..]
                                        .copy_from_slice(&u16::to_le_bytes(self.implicit_counter));
                                    self.implicit_counter += 1;
                                    count += 1
                                }

                                Err(e) => debug!(error = %e, "unable to handle pending context"),
                            }
                        } else {
                            if let Some(implicit_contexts) =
                                self.implicit_contexts.get_mut(group.context())
                            {
                                if let Some(last) = implicit_contexts.iter().last() {
                                    last.borrow_mut()
                                        .events
                                        .insert(key.to_string(), value.clone());
                                }
                            }
                        }
                    } else {
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
        }
        count
    }
}
