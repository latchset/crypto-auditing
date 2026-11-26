// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The crypto-auditing developers.

//! Synthesizes the raw ring buffer records that the BPF program in
//! the agent would emit when an instrumented library hits the USDT
//! probe points.

use crate::encode::{self, EncodeError, Header};
use crate::types::EventGroup;
use std::time::Duration;

#[derive(thiserror::Error, Debug)]
pub enum TraceError {
    #[error("unable to encode record: {0}")]
    Encode(#[from] EncodeError),
    #[error("unable to serialize to CBOR: {0}")]
    Cbor(#[from] serde_cbor::Error),
    #[error("unable to parse record: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, TraceError>;

/// An instrumented library loaded in a process
pub struct Process {
    pid_tgid: u64,
    origin: Vec<u8>,
    executable: &'static str,
}

impl Process {
    /// Creates a single-threaded process with the given PID; `origin`
    /// is the build ID of the library emitting the events, which is
    /// recorded in `new_context` events
    pub fn new(pid: u32, origin: &[u8], executable: &'static str) -> Self {
        Self {
            pid_tgid: ((pid as u64) << 32) | pid as u64,
            origin: origin.to_vec(),
            executable,
        }
    }
}

/// Value of a data event
pub enum Value {
    Word(i64),
    String(&'static str),
}

/// A sequence of raw records, each paired with the elapsed time since
/// the start of tracing, as `crau-agent --trace-file` records them
pub struct Trace {
    boot_time: u64,
    start: Duration,
    now: Duration,
    step: Duration,
    records: Vec<(Duration, Vec<u8>)>,
}

impl Trace {
    /// Creates an empty trace, which starts at `start` after the
    /// system boot at `boot_time` (in seconds since the epoch)
    pub fn new(boot_time: u64, start: Duration) -> Self {
        Self {
            boot_time,
            start,
            now: start,
            step: Duration::from_nanos(500),
            records: Vec::new(),
        }
    }

    /// Advances the clock by `duration`
    pub fn sleep(&mut self, duration: Duration) {
        self.now += duration;
    }

    /// Advances the clock by a step and returns the header for the
    /// next record
    fn header(&mut self, process: &Process, context: i64) -> Header {
        self.now += self.step;
        Header {
            pid_tgid: process.pid_tgid,
            context,
            ktime: self.now,
        }
    }

    fn push(&mut self, record: Vec<u8>) {
        self.records.push((self.now - self.start, record));
    }

    /// Records a `new_context` probe
    pub fn new_context(&mut self, process: &Process, context: i64, parent: i64) -> Result<()> {
        let header = self.header(process, context);
        let record = encode::new_context(&header, parent, &process.origin, process.executable)?;
        self.push(record);
        Ok(())
    }

    /// Records a `release_context` probe
    pub fn release_context(&mut self, process: &Process, context: i64) {
        let header = self.header(process, context);
        self.push(encode::release_context(&header));
    }

    /// Records a `word_data` probe
    pub fn word(&mut self, process: &Process, context: i64, key: &str, value: i64) -> Result<()> {
        let header = self.header(process, context);
        self.push(encode::word_data(&header, key, value)?);
        Ok(())
    }

    /// Records a `string_data` probe
    pub fn string(
        &mut self,
        process: &Process,
        context: i64,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let header = self.header(process, context);
        self.push(encode::string_data(&header, key, value)?);
        Ok(())
    }

    /// Records a context named `name` with the given data, as
    /// instrumented libraries typically do with a sequence of
    /// `new_context`, `string_data` (with "name" as the key), and
    /// `{word,string}_data` probes
    pub fn span(
        &mut self,
        process: &Process,
        context: i64,
        parent: i64,
        name: &str,
        data: &[(&str, Value)],
    ) -> Result<()> {
        self.new_context(process, context, parent)?;
        self.string(process, context, "name", name)?;
        self.data(process, context, data)
    }

    /// Records data events for an existing context
    pub fn data(&mut self, process: &Process, context: i64, data: &[(&str, Value)]) -> Result<()> {
        for (key, value) in data {
            match value {
                Value::Word(value) => self.word(process, context, key, *value)?,
                Value::String(value) => self.string(process, context, key, value)?,
            }
        }
        Ok(())
    }

    /// Serializes the trace in the format of `crau-agent --trace-file`
    pub fn to_trace_file(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for record in &self.records {
            output.extend(serde_cbor::ser::to_vec(record)?);
        }
        Ok(output)
    }

    /// Serializes the trace in the format of `crau-agent --log-file`,
    /// assuming that no coalescing happened
    pub fn to_log_file(&self) -> Result<Vec<u8>> {
        let metadata = EventGroup::metadata_with_boot_time(self.boot_time as i64);
        let mut output = serde_cbor::ser::to_vec(&metadata)?;
        for (_, record) in &self.records {
            let group =
                EventGroup::from_bytes(record).map_err(|e| TraceError::Parse(e.to_string()))?;
            output.extend(serde_cbor::ser::to_vec(&group)?);
        }
        Ok(output)
    }
}
