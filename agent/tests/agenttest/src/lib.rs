// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2023 The crypto-auditing developers.

use anyhow::{Result, bail};
use libbpf_rs::{
    Link, Map, OpenObject, RingBufferBuilder,
    skel::{OpenSkel, SkelBuilder},
};
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::Child;
use std::time::Duration;

mod skel {
    include!(concat!(env!("OUT_DIR"), "/agent.skel.rs"));
}
use skel::*;

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

pub fn attach_bpf<'obj>(
    process: &'obj Child,
    path: impl AsRef<Path>,
    storage: &'obj mut MaybeUninit<OpenObject>,
) -> Result<(Link, AgentSkel<'obj>)> {
    let skel_builder = AgentSkelBuilder::default();

    let open_skel = skel_builder.open(storage)?;
    let skel = open_skel.load()?;

    let link = skel
        .progs
        .event_group
        .attach_usdt(
            process.id() as i32,
            path.as_ref(),
            "crypto_auditing_internal_agent",
            "event_group",
        )
        .expect("unable to attach prog");

    Ok((link, skel))
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
