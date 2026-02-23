// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result, bail};
use caps::{CapSet, Capability, CapsHashSet};
use core::future::Future;
use crypto_auditing::types::{ContextId, EventGroup};
use libbpf_rs::{
    RingBufferBuilder,
    skel::{OpenSkel, SkelBuilder},
};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use std::io::prelude::*;
use std::mem::MaybeUninit;
use std::path::Path;
use tokio::{
    io::{Interest, unix::AsyncFd},
    runtime,
    sync::mpsc,
    time::Instant,
};
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod config;
mod log_writer;
mod permissions;

mod skel {
    include!(concat!(env!("OUT_DIR"), "/audit.skel.rs"));
}
use skel::*;

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn encrypt_context(key: impl AsRef<[u8]>, context: &ContextId) -> Result<ContextId> {
    let cipher = Cipher::aes_128_ecb();
    let mut encryptor = Crypter::new(cipher, Mode::Encrypt, key.as_ref(), None).unwrap();
    encryptor.pad(false);

    let mut ciphertext = vec![0; context.len() + cipher.block_size()];
    let mut count = encryptor.update(context, &mut ciphertext).unwrap();
    count += encryptor.finalize(&mut ciphertext).unwrap();
    ciphertext.truncate(count);

    Ok(ciphertext.try_into().unwrap())
}

struct Tracer {
    writer: Box<dyn std::io::Write>,
    instant: Instant,
}

impl Tracer {
    fn write(
        &mut self,
        encryption_key: &[u8],
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let trace = serde_cbor::ser::to_vec(&(self.instant.elapsed(), encryption_key, data))?;
        let _ = self.writer.write(&trace)?;
        self.writer.flush()?;
        Ok(())
    }

    fn new(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            writer: Box::new(std::fs::File::create(path.as_ref())?),
            instant: Instant::now(),
        })
    }

    fn empty() -> Result<Self> {
        Ok(Self {
            writer: Box::new(std::io::empty()),
            instant: Instant::now(),
        })
    }
}

#[cfg(feature = "tokio-uring")]
fn start<F: Future>(future: F) -> F::Output {
    tokio_uring::start(future)
}

#[cfg(not(feature = "tokio-uring"))]
fn start<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::Config::new()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let mut tracer = match config.trace_file {
        Some(ref path) => Tracer::new(path)?,
        None => Tracer::empty()?,
    };

    bump_memlock_rlimit()?;

    // Check if we can read a capability set
    caps::read(None, CapSet::Effective)?;

    // First, prepare the capabilities we want to end up with
    let capset = CapsHashSet::from([
        Capability::CAP_BPF,
        Capability::CAP_PERFMON,
        Capability::CAP_SETGID,
        Capability::CAP_SETUID,
    ]);
    // Set only necessary capabilities in effective and permitted sets
    caps::set(None, CapSet::Effective, &capset)?;
    caps::set(None, CapSet::Permitted, &capset)?;

    let skel_builder = AuditSkelBuilder::default();
    let mut storage = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut storage)?;
    let skel = open_skel.load()?;

    let mut links = Vec::new();
    for library in &config.library {
        if let Ok(link) = skel.progs.new_context.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "new_context",
        ) {
            links.push(link);
        }
        if let Ok(link) = skel.progs.word_data.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "word_data",
        ) {
            links.push(link);
        }
        if let Ok(link) = skel.progs.string_data.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "string_data",
        ) {
            links.push(link);
        }
        if let Ok(link) = skel.progs.blob_data.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "blob_data",
        ) {
            links.push(link);
        }
        if let Ok(link) = skel.progs.data.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "data",
        ) {
            links.push(link);
        }
        if let Ok(link) = skel.progs.new_context_with_data.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "new_context_with_data",
        ) {
            links.push(link);
        }
    }

    let cipher = Cipher::aes_128_ecb();
    let mut encryption_key = vec![0; cipher.key_len()];
    rand_bytes(&mut encryption_key)?;

    start(async {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<EventGroup>();
        let handle = runtime::Handle::current();
        let mut builder = RingBufferBuilder::new();
        builder.add(&skel.maps.ringbuf, |data| {
            if let Err(e) = tracer.write(&encryption_key, data) {
                info!(error = %e, "error writing trace");
            }
            match EventGroup::from_bytes(data) {
                Ok(group) => {
                    let event_tx2 = event_tx.clone();
                    handle.spawn(async move {
                        if let Err(e) = event_tx2.send(group) {
                            info!(error = %e, "error sending event group");
                        }
                    });
                }
                Err(e) => info!(error = %e, "error deserializing event group"),
            }
            0
        })?;
        let rb = builder.build()?;

        if let Some((ref user, ref group)) = config.user {
            permissions::run_as(user, group)?;
        }

        // Drop capabilities no longer needed
        caps::drop(None, CapSet::Effective, Capability::CAP_SETGID)?;
        caps::drop(None, CapSet::Effective, Capability::CAP_SETUID)?;
        caps::drop(None, CapSet::Permitted, Capability::CAP_SETGID)?;
        caps::drop(None, CapSet::Permitted, Capability::CAP_SETUID)?;

        let fd = AsyncFd::with_interest(rb.epoll_fd(), Interest::READABLE)?;
        let mut writer = log_writer::LogWriter::from_config(&config).await?;

        loop {
            tokio::select! {
                res = fd.readable() => {
                    match res {
                        Ok(mut guard) => {
                            guard.clear_ready();
                            if let Err(e) = rb.consume() {
                                info!(error = %e, "error polling ringbuf");
                                break;
                            }
                        },
                        Err(e) => {
                            info!(error = %e, "error polling ringbuf");
                            break;
                        },
                    }
                },

                Some(mut group) = event_rx.recv() => {
                    // Ignore groups from ourselves
                    if group.matches_pid(unsafe { libc::getpid() }) {
                        debug!("skipping group as pid matches the self");
                        continue;
                    }

                    // Encrypt context IDs that appear in the event read
                    if let Err(e) = group.encrypt_context(|context: &mut ContextId| {
                        *context = encrypt_context(&encryption_key[..], context)?;
                        Ok(())
                    }) {
                        info!(error = %e, "error encrypting context ID");
                        continue;
                    }

                    writer.push_group(group);
                },

                () = tokio::time::sleep(writer.timeout()) => {},
            }

            if !writer.coalesce_window_elapsed() && !writer.should_rotate() {
                continue;
            }
            if let Err(e) = writer.flush().await {
                info!(error = %e, "error flushing events");
            }
        }

        writer
            .close()
            .await
            .with_context(|| format!("unable to close file `{}`", config.log_file.display()))?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor::de::Deserializer;
    use std::path::Path;
    use tokio::time::Duration;

    // This test assumes input.cborseq (trace file) and output.cborseq
    // (log file) in $CARGO_MANIFEST_DIR/../fixtures/normal.  These
    // files can be generated by exercising the GnuTLS session after
    // starting up the agent with:
    //
    //   sudo target/debug/crau-agent -c agent/fixtures/agent.conf \
    //        --library /usr/lib64/libgnutls.so.30 --user $USER:$GID \
    //        --trace-file fixtures/normal/input.cborseq \
    //        --log-file fixtures/normal/output.cborseq
    //
    #[test]
    fn test_normal() {
        let fixtures_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("fixtures")
            .join("normal");

        let input_file_path = fixtures_path.join("input.cborseq");
        let input_file = std::fs::File::open(&input_file_path).expect("unable to open input file");

        let mut output = Vec::new();
        for res in
            Deserializer::from_reader(&input_file).into_iter::<(Duration, Vec<u8>, Vec<u8>)>()
        {
            let (_duration, encryption_key, buffer) = res.expect("unable to deserialize trace");
            let mut group =
                EventGroup::from_bytes(&buffer).expect("unable to deserialize to EventGroup");
            group
                .encrypt_context(|context: &mut ContextId| {
                    *context = encrypt_context(&encryption_key[..], context)?;
                    Ok(())
                })
                .expect("unable to encrypt context");
            let mut v = serde_cbor::ser::to_vec(&group).expect("unable to serialize to CBOR");
            output.append(&mut v);
        }

        let output_file_path = fixtures_path.join("output.cborseq");
        let expected = std::fs::read(&output_file_path).expect("unable to read output file");
        assert_eq!(expected, output);
    }
}
