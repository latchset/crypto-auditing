// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2023 The crypto-auditing developers.

use anyhow::{bail, Result};
use libbpf_rs::{Link, Map, Object, RingBufferBuilder};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::Duration;

mod skel {
    include!(concat!(env!("OUT_DIR"), "/agent.skel.rs"));
}
use skel::*;

pub fn target_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .map(|mut path| {
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path
        })
        .unwrap()
}

pub fn agent_path() -> PathBuf {
    target_dir().join("crypto-auditing-agent")
}

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn attach_bpf(process: &Child, path: impl AsRef<Path>) -> Result<(Link, Object)> {
    let skel_builder = AgentSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;

    let mut progs = skel.progs_mut();
    let prog = progs.event_group();

    let link = prog
        .attach_usdt(
            process.id() as i32,
            path.as_ref(),
            "crypto_auditing_internal_agent",
            "event_group",
        )
        .expect("unable to attach prog");

    Ok((link, skel.obj))
}

// Copied from libbpf-rs/libbpf-rs/tests/test.rs
pub fn with_ringbuffer<F>(map: &Map, action: F, timeout: Duration) -> Result<i64>
where
    F: FnOnce(),
{
    let mut value = 0i64;
    {
        let callback = |data: &[u8]| {
            plain::copy_from_bytes(&mut value, data).expect("Wrong size");
            0
        };

        let mut builder = RingBufferBuilder::new();
        builder.add(map, callback)?;
        let mgr = builder.build()?;

        action();
        mgr.poll(timeout)?;
        mgr.consume()?;
    }

    Ok(value)
}
