// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::ffi::CStr;
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub type ContextID = [u8; 16];

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
        parent: ContextID,
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
    context: ContextID,
    #[serde_as(as = "serde_with::DurationNanoSeconds<u64>")]
    start: Duration,
    #[serde_as(as = "serde_with::DurationNanoSeconds<u64>")]
    end: Duration,
    events: Vec<Event>,
}

fn format_context(pid_tgid: u64, context: i64) -> ContextID {
    let mut result: ContextID = Default::default();
    result[..8].copy_from_slice(&u64::to_le_bytes(pid_tgid));
    result[8..].copy_from_slice(&i64::to_le_bytes(context));
    result
}

impl EventGroup {
    /// Returns the context ID associated with the event group
    pub fn context(&self) -> &ContextID {
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
        F: Fn(&mut ContextID) -> Result<(), Box<dyn std::error::Error>>,
    {
        f(&mut self.context)?;

        if let Some(Event::NewContext { ref mut parent, .. }) = self.events.last_mut() {
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
        self.events = self
            .events
            .iter()
            .cloned()
            .filter(|event| match event {
                Event::NewContext { .. } => true,
                Event::Data { key, .. } => scopes
                    .iter()
                    .any(|scope| !key.contains("::") || key.starts_with(&format!("{}::", scope))),
            })
            .collect();
    }

    /// Deserializes an event group from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let header = bytes.as_ptr() as *mut audit_event_header_st;
        let context = unsafe { format_context((*header).pid_tgid, (*header).context) };
        let ktime = unsafe { Duration::from_nanos((*header).ktime) };
        let event = match unsafe { (*header).type_ } {
            audit_event_type_t::AUDIT_EVENT_NEW_CONTEXT => {
                let raw_new_context = bytes.as_ptr() as *mut audit_new_context_event_st;
                let parent =
                    unsafe { format_context((*header).pid_tgid, (*raw_new_context).parent) };
                let origin = unsafe {
                    (*raw_new_context).origin[..(*raw_new_context).origin_size as usize].to_vec()
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
                                value: EventData::Word((*raw_word_data).value),
                            }],
                        }
                    }
                    audit_data_type_t::AUDIT_DATA_STRING => {
                        let raw_string_data = bytes.as_ptr() as *mut audit_blob_data_event_st;
                        let key = CStr::from_ptr((*raw_string_data).base.key.as_ptr());
                        let len = (*raw_string_data).size as usize;
                        let string =
                            std::str::from_utf8(&(*raw_string_data).value[..len - 1])?.to_string();
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
                        let data = (*raw_blob_data).value[..len].to_vec();
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
