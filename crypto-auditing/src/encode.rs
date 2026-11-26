// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The crypto-auditing developers.

//! Encoding of the raw records emitted by the BPF program, the
//! inverse of [`EventGroup::from_bytes`](crate::types::EventGroup::from_bytes).
//!
//! This is useful for generating test fixtures or debugging without
//! running the agent against an instrumented library.  The functions
//! are named after the corresponding USDT probe points.

use crate::types::{
    audit_blob_data_event_st, audit_data_type_t, audit_event_header_st, audit_event_type_t,
    audit_new_context_event_st, audit_release_context_event_st, audit_word_data_event_st,
};
use std::mem::{MaybeUninit, size_of};
use std::os::raw::c_char;
use std::ptr::addr_of_mut;
use std::time::Duration;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    #[error("{field} is too long (maximum {max} bytes)")]
    TooLong { field: &'static str, max: usize },
    #[error("{field} contains a NUL character")]
    ContainsNul { field: &'static str },
}

/// Common fields of all raw records
#[derive(Clone, Copy, Debug)]
pub struct Header {
    /// Thread group ID in the upper 32 bits, and thread ID in the
    /// lower 32 bits, as returned by `bpf_get_current_pid_tgid`
    pub pid_tgid: u64,
    /// Context the record is associated with
    pub context: i64,
    /// Time since the system boot
    pub ktime: Duration,
}

/// Returns a zero-initialized `T`; fields are only ever written
/// through raw pointers afterwards, so that padding bytes stay zero
/// and the result can be viewed as bytes
fn zeroed<T>() -> MaybeUninit<T> {
    MaybeUninit::zeroed()
}

fn into_bytes<T>(value: MaybeUninit<T>) -> Vec<u8> {
    // SAFETY: all bytes of `value` are initialized by `zeroed`
    unsafe { std::slice::from_raw_parts(value.as_ptr() as *const u8, size_of::<T>()) }.to_vec()
}

/// Copies `src` into `dst` as a NUL-terminated string
fn copy_c_string(field: &'static str, dst: &mut [c_char], src: &str) -> Result<(), EncodeError> {
    if src.len() >= dst.len() {
        return Err(EncodeError::TooLong {
            field,
            max: dst.len() - 1,
        });
    }
    if src.as_bytes().contains(&0) {
        return Err(EncodeError::ContainsNul { field });
    }
    for (d, s) in dst.iter_mut().zip(src.as_bytes()) {
        *d = *s as c_char;
    }
    Ok(())
}

fn copy_bytes(field: &'static str, dst: &mut [u8], src: &[u8]) -> Result<(), EncodeError> {
    if src.len() > dst.len() {
        return Err(EncodeError::TooLong {
            field,
            max: dst.len(),
        });
    }
    dst[..src.len()].copy_from_slice(src);
    Ok(())
}

/// Fills the header of a zeroed record
///
/// # Safety
///
/// `p` must point to a header inside a zeroed record of `size` bytes
unsafe fn write_header(
    p: *mut audit_event_header_st,
    size: usize,
    type_: audit_event_type_t::Type,
    header: &Header,
) {
    unsafe {
        addr_of_mut!((*p).size).write(size as _);
        addr_of_mut!((*p).type_).write(type_);
        addr_of_mut!((*p).pid_tgid).write(header.pid_tgid as _);
        addr_of_mut!((*p).context).write(header.context as _);
        addr_of_mut!((*p).ktime).write(header.ktime.as_nanos() as _);
    }
}

/// Encodes a `new_context` record; `origin` is the build ID of the
/// library emitting the event
pub fn new_context(
    header: &Header,
    parent: i64,
    origin: &[u8],
    executable: &str,
) -> Result<Vec<u8>, EncodeError> {
    let mut record = zeroed::<audit_new_context_event_st>();
    let p = record.as_mut_ptr();
    // SAFETY: `p` points to a zeroed record
    unsafe {
        write_header(
            addr_of_mut!((*p).header),
            size_of::<audit_new_context_event_st>(),
            audit_event_type_t::AUDIT_EVENT_NEW_CONTEXT,
            header,
        );
        addr_of_mut!((*p).parent).write(parent as _);
        copy_bytes("origin", &mut *addr_of_mut!((*p).origin), origin)?;
        addr_of_mut!((*p).origin_size).write(origin.len() as _);
        copy_c_string(
            "executable",
            &mut *addr_of_mut!((*p).executable),
            executable,
        )?;
    }
    Ok(into_bytes(record))
}

/// Encodes a `release_context` record
pub fn release_context(header: &Header) -> Vec<u8> {
    let mut record = zeroed::<audit_release_context_event_st>();
    let p = record.as_mut_ptr();
    // SAFETY: `p` points to a zeroed record
    unsafe {
        write_header(
            addr_of_mut!((*p).header),
            size_of::<audit_release_context_event_st>(),
            audit_event_type_t::AUDIT_EVENT_RELEASE_CONTEXT,
            header,
        );
    }
    into_bytes(record)
}

/// Encodes a `word_data` record
pub fn word_data(header: &Header, key: &str, value: i64) -> Result<Vec<u8>, EncodeError> {
    let mut record = zeroed::<audit_word_data_event_st>();
    let p = record.as_mut_ptr();
    // SAFETY: `p` points to a zeroed record
    unsafe {
        write_header(
            addr_of_mut!((*p).base.header),
            size_of::<audit_word_data_event_st>(),
            audit_event_type_t::AUDIT_EVENT_DATA,
            header,
        );
        addr_of_mut!((*p).base.type_).write(audit_data_type_t::AUDIT_DATA_WORD);
        copy_c_string("key", &mut *addr_of_mut!((*p).base.key), key)?;
        addr_of_mut!((*p).value).write(value as _);
    }
    Ok(into_bytes(record))
}

fn blob_like_data(
    header: &Header,
    type_: audit_data_type_t::Type,
    key: &str,
    value: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    let mut record = zeroed::<audit_blob_data_event_st>();
    let p = record.as_mut_ptr();
    // SAFETY: `p` points to a zeroed record
    unsafe {
        write_header(
            addr_of_mut!((*p).base.header),
            size_of::<audit_blob_data_event_st>(),
            audit_event_type_t::AUDIT_EVENT_DATA,
            header,
        );
        addr_of_mut!((*p).base.type_).write(type_);
        copy_c_string("key", &mut *addr_of_mut!((*p).base.key), key)?;
        copy_bytes("value", &mut *addr_of_mut!((*p).value), value)?;
        addr_of_mut!((*p).size).write(value.len() as _);
    }
    Ok(into_bytes(record))
}

/// Encodes a `string_data` record
pub fn string_data(header: &Header, key: &str, value: &str) -> Result<Vec<u8>, EncodeError> {
    if value.as_bytes().contains(&0) {
        return Err(EncodeError::ContainsNul { field: "value" });
    }
    // The size includes the terminating NUL
    let mut value = value.as_bytes().to_vec();
    value.push(0);
    let type_ = audit_data_type_t::AUDIT_DATA_STRING;
    blob_like_data(header, type_, key, &value)
}

/// Encodes a `blob_data` record
pub fn blob_data(header: &Header, key: &str, value: &[u8]) -> Result<Vec<u8>, EncodeError> {
    blob_like_data(header, audit_data_type_t::AUDIT_DATA_BLOB, key, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Event, EventData, EventGroup, KEY_SIZE, VALUE_SIZE};

    const HEADER: Header = Header {
        pid_tgid: (1234 << 32) | 1235,
        context: 0x7f00_1234_5678,
        ktime: Duration::from_nanos(123_456_789),
    };

    fn decode(bytes: &[u8]) -> EventGroup {
        let group = EventGroup::from_bytes(bytes).expect("should decode");
        let mut context = [0u8; 16];
        context[..8].copy_from_slice(&HEADER.context.to_le_bytes());
        context[8..].copy_from_slice(&HEADER.pid_tgid.to_le_bytes());
        assert_eq!(group.context(), &context);
        assert_eq!(group.start(), HEADER.ktime);
        assert_eq!(group.end(), HEADER.ktime);
        assert_eq!(group.events().len(), 1);
        group
    }

    #[test]
    fn test_new_context() {
        let bytes = new_context(&HEADER, -1, &[1, 2, 3], "gnutls-cli").unwrap();
        match &decode(&bytes).events()[0] {
            Event::NewContext {
                parent,
                origin,
                executable,
            } => {
                assert_eq!(parent[..8], [0xff; 8]);
                assert_eq!(parent[8..], HEADER.pid_tgid.to_le_bytes());
                assert_eq!(origin, &[1, 2, 3]);
                assert_eq!(executable.to_str().unwrap(), "gnutls-cli");
            }
            event => panic!("unexpected event {event:?}"),
        }
    }

    #[test]
    fn test_release_context() {
        let group = decode(&release_context(&HEADER));
        assert!(matches!(group.events()[0], Event::ReleaseContext {}));
    }

    #[test]
    fn test_word_data() {
        let bytes = word_data(&HEADER, "tls::group", -4588).unwrap();
        match &decode(&bytes).events()[0] {
            Event::Data {
                key,
                value: EventData::Word(value),
            } => {
                assert_eq!(key, "tls::group");
                assert_eq!(*value, -4588);
            }
            event => panic!("unexpected event {event:?}"),
        }
    }

    #[test]
    fn test_string_data() {
        let bytes = string_data(&HEADER, "name", "tls::handshake_client").unwrap();
        match &decode(&bytes).events()[0] {
            Event::Data {
                key,
                value: EventData::String(value),
            } => {
                assert_eq!(key, "name");
                assert_eq!(value, "tls::handshake_client");
            }
            event => panic!("unexpected event {event:?}"),
        }
    }

    #[test]
    fn test_blob_data() {
        let blob = [0u8, 1, 2, 0, 255];
        let bytes = blob_data(&HEADER, "pk::public_key", &blob).unwrap();
        match &decode(&bytes).events()[0] {
            Event::Data {
                key,
                value: EventData::Blob(value),
            } => {
                assert_eq!(key, "pk::public_key");
                assert_eq!(value, &blob);
            }
            event => panic!("unexpected event {event:?}"),
        }
    }

    #[test]
    fn test_limits() {
        let key = "k".repeat(KEY_SIZE as usize - 1);
        assert!(word_data(&HEADER, &key, 0).is_ok());
        let key = "k".repeat(KEY_SIZE as usize);
        assert_eq!(
            word_data(&HEADER, &key, 0),
            Err(EncodeError::TooLong {
                field: "key",
                max: KEY_SIZE as usize - 1,
            })
        );
        assert_eq!(
            word_data(&HEADER, "a\0b", 0),
            Err(EncodeError::ContainsNul { field: "key" })
        );

        let value = "v".repeat(VALUE_SIZE as usize - 1);
        assert!(string_data(&HEADER, "key", &value).is_ok());
        let value = "v".repeat(VALUE_SIZE as usize);
        assert!(string_data(&HEADER, "key", &value).is_err());
        assert_eq!(
            string_data(&HEADER, "key", "a\0b"),
            Err(EncodeError::ContainsNul { field: "value" })
        );

        let blob = vec![0u8; VALUE_SIZE as usize];
        assert!(blob_data(&HEADER, "key", &blob).is_ok());
        let blob = vec![0u8; VALUE_SIZE as usize + 1];
        assert!(blob_data(&HEADER, "key", &blob).is_err());
    }
}
