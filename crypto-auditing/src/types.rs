// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use serde::{
    Deserialize, Serialize,
    ser::{SerializeSeq, Serializer},
};
use serde_with::{hex::Hex, serde_as};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub type ContextId = [u8; 16];

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
#[derive(Debug, Serialize)]
pub struct Context {
    #[serde_as(as = "Hex")]
    #[serde(rename = "context")]
    pub id: ContextId,
    #[serde_as(as = "Hex")]
    pub origin: Vec<u8>,
    #[serde_as(as = "serde_with::TimestampSecondsWithFrac<f64>")]
    pub start: SystemTime,
    #[serde_as(as = "serde_with::TimestampSecondsWithFrac<f64>")]
    pub end: SystemTime,
    pub events: BTreeMap<String, EventData>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(serialize_with = "only_values")]
    pub spans: BTreeMap<ContextId, Rc<RefCell<Context>>>,
}

#[derive(Debug)]
pub struct ContextTracker {
    all_contexts: BTreeMap<ContextId, Rc<RefCell<Context>>>,
    root_contexts: Vec<Rc<RefCell<Context>>>,
    boot_time: SystemTime,
}

impl ContextTracker {
    pub fn new(boot_time: Option<SystemTime>) -> Self {
        Self {
            all_contexts: BTreeMap::new(),
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
        self.root_contexts.retain(|context| {
            if let Some(before) = before
                && context.borrow().start > before
            {
                true
            } else {
                self.all_contexts.remove(&context.borrow().id[..]);
                removed.push(context.clone());
                false
            }
        });
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
                } => {
                    let context = Rc::new(RefCell::new(Context {
                        id: *group.context(),
                        origin: origin.to_owned(),
                        start,
                        end,
                        events: Default::default(),
                        spans: Default::default(),
                    }));
                    if let Some(parent) = self.all_contexts.get(&parent_context[..]) {
                        parent
                            .borrow_mut()
                            .spans
                            .insert(*group.context(), context.clone());
                    } else {
                        self.root_contexts.push(context.clone());
                        count += 1;
                    }
                    self.all_contexts.insert(*group.context(), context);
                }
                Event::Data { key, value } => {
                    if !self.all_contexts.contains_key(group.context()) {
                        // Either this library did not do a new_context for this context, or the
                        // log we have is truncated at the beginning. Just assume that this context
                        // has no parent and create a new one so we don't lose the information in
                        // this message.
                        let context_obj = Rc::new(RefCell::new(Context {
                            id: *group.context(),
                            origin: Default::default(),
                            start,
                            end,
                            events: Default::default(),
                            spans: Default::default(),
                        }));
                        self.root_contexts.push(context_obj.clone());
                        self.all_contexts.insert(*group.context(), context_obj);
                        count += 1;
                    }
                    if let Some(parent) = self.all_contexts.get(group.context()) {
                        parent
                            .borrow_mut()
                            .events
                            .insert(key.to_string(), value.clone());
                    }
                }
            }
        }
        count
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum EventData {
    Word(i64),
    String(String),
    Blob(
        #[serde_as(as = "serde_with::Bytes")] Vec<u8>, // TODO: try ArrayVec?
    ),
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Event {
    NewContext {
        #[serde_as(as = "serde_with::Bytes")]
        parent: ContextId,
        #[serde_as(as = "serde_with::Bytes")]
        origin: Vec<u8>,
    },
    Data {
        key: String,
        value: EventData,
    },
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EventGroup {
    #[serde_as(as = "serde_with::Bytes")]
    context: ContextId,
    #[serde_as(as = "serde_with::DurationNanoSeconds<u64>")]
    start: Duration,
    #[serde_as(as = "serde_with::DurationNanoSeconds<u64>")]
    end: Duration,
    events: Vec<Event>,
}

fn format_context_id(pid_tgid: u64, context: i64) -> ContextId {
    let mut result: ContextId = Default::default();
    result[..8].copy_from_slice(&u64::to_le_bytes(pid_tgid));
    result[8..].copy_from_slice(&i64::to_le_bytes(context));
    result
}

impl EventGroup {
    /// Returns the context ID associated with the event group
    pub fn context(&self) -> &ContextId {
        &self.context
    }

    /// Returns the start time of the event group
    pub fn start(&self) -> Duration {
        self.start
    }

    /// Returns the end time of the event group
    pub fn end(&self) -> Duration {
        self.end
    }

    /// Returns the events contained in the event group
    pub fn events(&self) -> &Vec<Event> {
        &self.events
    }

    /// Returns true if this event group is associated with the given process ID
    pub fn matches_pid(&self, pid: libc::pid_t) -> bool {
        (u64::from_le_bytes(self.context()[..8].try_into().unwrap()) & 0xffffffff)
            == <i32 as TryInto<u64>>::try_into(pid).unwrap()
    }

    /// Returns encrypted context ID associated with the event group
    pub fn encrypt_context<F>(&mut self, f: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(&mut ContextId) -> Result<(), Box<dyn std::error::Error>>,
    {
        f(&mut self.context)?;

        if let Some(Event::NewContext { parent, .. }) = self.events.last_mut() {
            f(parent)?;
        }
        Ok(())
    }

    /// Merges this event group with another which shares the same context ID
    pub fn coalesce(&mut self, other: &mut Self) {
        self.end = other.end;
        self.events.append(&mut other.events);
    }

    /// Removes events which do not match the given scopes
    pub fn events_filtered(&mut self, scopes: &[String]) {
        self.events.retain(|event| match event {
            Event::NewContext { .. } => true,
            Event::Data { key, .. } => scopes
                .iter()
                .any(|scope| !key.contains("::") || key.starts_with(&format!("{}::", scope))),
        });
    }

    /// Deserializes an event group from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let header = bytes.as_ptr() as *mut audit_event_header_st;
        let context =
            unsafe { format_context_id((*header).pid_tgid.into(), (*header).context.into()) };
        let ktime = unsafe { Duration::from_nanos((*header).ktime.into()) };
        let event = match unsafe { (*header).type_ } {
            audit_event_type_t::AUDIT_EVENT_NEW_CONTEXT => {
                let raw_new_context = bytes.as_ptr() as *mut audit_new_context_event_st;
                let parent = unsafe {
                    format_context_id((*header).pid_tgid.into(), (*raw_new_context).parent.into())
                };
                let origin = unsafe {
                    (&(*raw_new_context).origin)[..(*raw_new_context).origin_size as usize].to_vec()
                };
                EventGroup {
                    context,
                    start: ktime,
                    end: ktime,
                    events: vec![Event::NewContext { parent, origin }],
                }
            }
            audit_event_type_t::AUDIT_EVENT_DATA => unsafe {
                let data = bytes.as_ptr() as *mut audit_data_event_st;
                match (*data).type_ {
                    audit_data_type_t::AUDIT_DATA_WORD => {
                        let raw_word_data = bytes.as_ptr() as *mut audit_word_data_event_st;
                        let key = CStr::from_ptr((*raw_word_data).base.key.as_ptr());
                        EventGroup {
                            context,
                            start: ktime,
                            end: ktime,
                            events: vec![Event::Data {
                                key: key.to_str()?.to_string(),
                                value: EventData::Word((*raw_word_data).value.into()),
                            }],
                        }
                    }
                    audit_data_type_t::AUDIT_DATA_STRING => {
                        let raw_string_data = bytes.as_ptr() as *mut audit_blob_data_event_st;
                        let key = CStr::from_ptr((*raw_string_data).base.key.as_ptr());
                        let len = (*raw_string_data).size as usize;
                        let string = std::str::from_utf8(&(&(*raw_string_data).value)[..len - 1])?
                            .to_string();
                        EventGroup {
                            context,
                            start: ktime,
                            end: ktime,
                            events: vec![Event::Data {
                                key: key.to_str()?.to_string(),
                                value: EventData::String(string),
                            }],
                        }
                    }
                    audit_data_type_t::AUDIT_DATA_BLOB => {
                        let raw_blob_data = bytes.as_ptr() as *mut audit_blob_data_event_st;
                        let key = CStr::from_ptr((*raw_blob_data).base.key.as_ptr());
                        let len = (*raw_blob_data).size as usize;
                        let data = (&(*raw_blob_data).value)[..len].to_vec();
                        EventGroup {
                            context,
                            start: ktime,
                            end: ktime,
                            events: vec![Event::Data {
                                key: key.to_str()?.to_string(),
                                value: EventData::Blob(data),
                            }],
                        }
                    }
                    _ => unreachable!(),
                }
            },
            _ => unreachable!(),
        };
        Ok(event)
    }
}
