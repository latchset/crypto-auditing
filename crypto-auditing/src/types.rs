// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use serde::{Deserialize, Serialize, ser::Serializer};
use serde_with::{hex::Hex, serde_as};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::rc::Rc;
use std::time::{Duration, SystemTime};
use sysinfo::System;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub type ContextId = [u8; 16];

/// Context ID associated with `EventGroup` representing metadata
pub const METADATA_CONTEXT_ID: ContextId = [0; 16];

fn to_string_lossy<S>(source: &CString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&source.to_string_lossy())
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct Context {
    #[serde_as(as = "Hex")]
    #[serde(rename = "context")]
    pub id: ContextId,
    #[serde_as(as = "Hex")]
    pub origin: Vec<u8>,
    #[serde(serialize_with = "to_string_lossy")]
    pub executable: CString,
    #[serde_as(as = "serde_with::TimestampSecondsWithFrac<f64>")]
    pub start: SystemTime,
    #[serde_as(as = "serde_with::TimestampSecondsWithFrac<f64>")]
    pub end: SystemTime,
    pub events: BTreeMap<String, EventData>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub spans: Vec<Rc<RefCell<Context>>>,
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
        #[serde(default)]
        executable: CString,
    },
    Data {
        key: String,
        value: EventData,
    },
}

impl Event {
    pub fn data(&self, needle: &str) -> Option<&EventData> {
        match self {
            Self::Data { key, value } if key == needle => Some(value),
            _ => None,
        }
    }
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
    /// Returns a new `EventGroup` with metadata events
    pub fn metadata() -> Self {
        let events = vec![
            Event::Data {
                key: "version".to_string(),
                value: EventData::Word(1),
            },
            Event::Data {
                key: "boot_time".to_string(),
                value: EventData::Word(System::boot_time() as i64),
            },
        ];

        Self {
            context: METADATA_CONTEXT_ID,
            start: Default::default(),
            end: Default::default(),
            events,
        }
    }

    /// Returns true if this is a metadata group
    pub fn is_metadata(&self) -> bool {
        self.context == METADATA_CONTEXT_ID
    }

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
                let executable =
                    unsafe { CStr::from_ptr((&(*raw_new_context).executable).as_ptr()).to_owned() };
                EventGroup {
                    context,
                    start: ktime,
                    end: ktime,
                    events: vec![Event::NewContext {
                        parent,
                        origin,
                        executable,
                    }],
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
