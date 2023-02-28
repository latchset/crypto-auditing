// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{bail, Context as _, Result};
use bytes::BytesMut;
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use serde_cbor::{ser::IoWrite, Serializer};
use std::io::prelude::*;
use std::path::PathBuf;
use time::{macros::format_description, OffsetDateTime};
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration, Instant};
use tokio_uring::fs::{rename, File};

mod config;
mod permissions;
mod ringbuf;

mod skel {
    include!(concat!(env!("OUT_DIR"), "/audit.skel.rs"));
}
use skel::*;

use crypto_auditing_types as types;

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

fn to_vec_minimal<T>(value: &T) -> Result<Vec<u8>>
where
    T: serde::Serialize,
{
    let mut vec = Vec::new();
    value.serialize(
        &mut Serializer::new(&mut IoWrite::new(&mut vec))
            .packed_format()
            .legacy_enums(),
    )?;
    Ok(vec)
}

fn encrypt_context(key: impl AsRef<[u8]>, context: &types::ContextID) -> Result<types::ContextID> {
    let cipher = Cipher::aes_128_ecb();
    let mut encryptor = Crypter::new(cipher, Mode::Encrypt, key.as_ref(), None).unwrap();
    encryptor.pad(false);

    let mut ciphertext = vec![0; context.len() + cipher.block_size()];
    let mut count = encryptor.update(context, &mut ciphertext).unwrap();
    count += encryptor.finalize(&mut ciphertext).unwrap();
    ciphertext.truncate(count);

    Ok(ciphertext.try_into().unwrap())
}

fn open_tracer(config: &config::Config) -> Result<Box<dyn std::io::Write>> {
    if let Some(trace_file) = &config.trace_file {
        Ok(Box::new(std::fs::File::create(trace_file)?))
    } else {
        Ok(Box::new(std::io::sink()))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::Config::new()?;
    let mut tracer = open_tracer(&config)?;

    bump_memlock_rlimit()?;

    let skel_builder = AuditSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;

    let mut progs = skel.progs_mut();

    let mut links = Vec::new();
    for library in &config.library {
        let prog = progs.new_context();
        if let Ok(link) = prog.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "new_context",
        ) {
            links.push(link);
        }
        let prog = progs.word_data();
        if let Ok(link) = prog.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "word_data",
        ) {
            links.push(link);
        }
        let prog = progs.string_data();
        if let Ok(link) = prog.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "string_data",
        ) {
            links.push(link);
        }
        let prog = progs.blob_data();
        if let Ok(link) = prog.attach_usdt(
            -1, // any process
            library,
            "crypto_auditing",
            "blob_data",
        ) {
            links.push(link);
        }
    }

    let cipher = Cipher::aes_128_ecb();
    let mut encryption_key = vec![0; cipher.key_len()];
    rand_bytes(&mut encryption_key)?;

    tokio_uring::start(async {
        let mut rb = ringbuf::RingBuffer::new(skel.obj.map_mut("ringbuf").unwrap());

        if let Some((ref user, ref group)) = config.user {
            permissions::run_as(user, group)?;
        }

        let mut file = File::create(&config.log_file)
            .await
            .with_context(|| format!("unable to create file `{}`", config.log_file.display()))?;
        let mut buffer = BytesMut::with_capacity(1024);
        let mut offset = 0u64;
        let mut instant = Instant::now();
        let mut groups: Vec<types::EventGroup> = Vec::new();
        let mut written_events = 0usize;
        let mut pending_events = 0usize;

        loop {
            let d = if groups.is_empty() {
                // No previous event, wait indefinitely
                Duration::MAX
            } else if let Some(window) = config.coalesce_window {
                // --coalesce-window is given, wait during the window
                window
                    .checked_sub(instant.elapsed())
                    .unwrap_or(Duration::ZERO)
            } else {
                // Otherwise, wait indefinitely
                Duration::MAX
            };

            buffer.clear();
            let res = timeout(d, rb.read_buf(&mut buffer)).await;

            // Successfully waited
            if let Ok(res) = res {
                let trace = serde_cbor::ser::to_vec(&(
                    instant.elapsed(),
                    &encryption_key,
                    &buffer.as_ref().to_vec(),
                ))?;
                let _ = tracer.write(&trace)?;
                tracer.flush()?;

                let n = res?;
                if n == 0 {
                    break;
                }

                let mut group = types::EventGroup::from_bytes(&buffer)?;

                // Ignore groups from ourselves
                if group.matches_pid(unsafe { libc::getpid() }) {
                    continue;
                }

                // Encrypt context IDs that appear in the event read
                group.encrypt_context(|context: &mut types::ContextID| {
                    *context = encrypt_context(&encryption_key[..], context)?;
                    Ok(())
                })?;

                // Coalesce the event to the previous one, if possible
                match groups.last_mut() {
                    Some(last)
                        if last.context() == group.context()
                            && !config.coalesce_window_elapsed(&instant)
                            && !config.should_rotate_after(written_events + pending_events) =>
                    {
                        last.coalesce(&mut group)
                    }
                    _ => groups.push(group),
                }
                pending_events += 1;
            }

            if !config.coalesce_window_elapsed(&instant)
                && !config.should_rotate_after(written_events + pending_events)
            {
                continue;
            }

            pending_events = 0;

            // Otherwise flush the groups
            for group in &groups {
                if config.should_rotate_after(written_events) {
                    file.sync_all().await.with_context(|| {
                        format!("unable to sync file `{}`", config.log_file.display())
                    })?;

                    file.close().await.with_context(|| {
                        format!("unable to close file `{}`", config.log_file.display())
                    })?;

                    let now = OffsetDateTime::now_local()?;

                    let mut log_file = PathBuf::from(format!(
                        "{}-{}.0",
                        config.log_file.to_str().unwrap(),
                        now.format(&format_description!("[year]-[month]-[day]"))?,
                    ));
                    let mut counter = 0u64;
                    while log_file.exists() {
                        counter += 1;
                        log_file.set_extension(&counter.to_string());
                    }

                    rename(&config.log_file, &log_file).await.with_context(|| {
                        format!(
                            "unable to rename file `{}` to `{}`",
                            config.log_file.display(),
                            log_file.display(),
                        )
                    })?;

                    file = File::create(&config.log_file).await.with_context(|| {
                        format!("unable to create file `{}`", config.log_file.display())
                    })?;

                    offset = 0;
                    written_events = 0;
                }
                let v = match config.format {
                    config::Format::Normal => serde_cbor::ser::to_vec(&group)?,
                    config::Format::Packed => serde_cbor::ser::to_vec_packed(&group)?,
                    config::Format::Minimal => to_vec_minimal(&group)?,
                };
                let (res, _) = file.write_at(v, offset).await;
                let n = res?;
                offset += n as u64;
                written_events += group.events().len();
            }
            groups.clear();
            instant = Instant::now();
        }

        file.close()
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
            let mut group = types::EventGroup::from_bytes(&buffer)
                .expect("unable to deserialize to types::EventGroup");
            group
                .encrypt_context(|context: &mut types::ContextID| {
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
