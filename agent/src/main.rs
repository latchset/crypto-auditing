// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{bail, Context as _, Result};
use bytes::BytesMut;
use crypto_auditing::types::{ContextID, EventGroup};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use std::io::prelude::*;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

mod config;
mod log_writer;
mod permissions;
mod ringbuf;

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

fn encrypt_context(key: impl AsRef<[u8]>, context: &ContextID) -> Result<ContextID> {
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

        let mut buffer = BytesMut::with_capacity(1024);
        let mut writer = log_writer::LogWriter::from_config(&config).await?;

        loop {
            buffer.clear();
            let res = timeout(writer.timeout(), rb.read_buf(&mut buffer)).await;

            // Successfully waited
            if let Ok(res) = res {
                let trace = serde_cbor::ser::to_vec(&(
                    writer.elapsed(),
                    &encryption_key,
                    &buffer.as_ref().to_vec(),
                ))?;
                let _ = tracer.write(&trace)?;
                tracer.flush()?;

                let n = res?;
                if n == 0 {
                    break;
                }

                let mut group = EventGroup::from_bytes(&buffer)?;

                // Ignore groups from ourselves
                if group.matches_pid(unsafe { libc::getpid() }) {
                    continue;
                }

                // Encrypt context IDs that appear in the event read
                group.encrypt_context(|context: &mut ContextID| {
                    *context = encrypt_context(&encryption_key[..], context)?;
                    Ok(())
                })?;

                writer.push_group(group);
            }

            if !writer.coalesce_window_elapsed() && !writer.should_rotate() {
                continue;
            }

            writer.flush().await?;
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
                .encrypt_context(|context: &mut ContextID| {
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
