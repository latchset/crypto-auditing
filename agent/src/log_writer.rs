// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::config;
use anyhow::{Context as _, Result, bail};
use crypto_auditing::types::EventGroup;
use probe::probe;
use serde_cbor::{Serializer, ser::IoWrite};
use std::path::PathBuf;
use time::{OffsetDateTime, macros::format_description};
use tokio::time::{Duration, Instant};
#[cfg(not(feature = "tokio-uring"))]
use tokio::{
    fs::{File, rename},
    io::AsyncWriteExt,
};
#[cfg(feature = "tokio-uring")]
use tokio_uring::fs::{File, rename};

pub struct LogWriter {
    config: config::Config,
    file: Option<File>,
    offset: u64,
    instant: Instant,
    groups: Vec<EventGroup>,
    written_events: usize,
    pending_events: usize,
}

impl LogWriter {
    pub async fn from_config(config: &config::Config) -> Result<Self> {
        let file = File::create(&config.log_file)
            .await
            .with_context(|| format!("unable to create file `{}`", config.log_file.display()))?;
        Ok(Self {
            config: config.clone(),
            file: Some(file),
            offset: 0u64,
            instant: Instant::now(),
            groups: Vec::default(),
            written_events: 0usize,
            pending_events: 0usize,
        })
    }

    pub fn elapsed(&self) -> Duration {
        self.instant.elapsed()
    }

    pub fn timeout(&self) -> Duration {
        if self.groups.is_empty() {
            // No previous event, wait indefinitely
            Duration::MAX
        } else if let Some(window) = self.config.coalesce_window {
            // --coalesce-window is given, wait during the window
            window
                .checked_sub(self.instant.elapsed())
                .unwrap_or(Duration::ZERO)
        } else {
            // Otherwise, wait indefinitely
            Duration::MAX
        }
    }

    pub fn coalesce_window_elapsed(&self) -> bool {
        self.config
            .coalesce_window
            .map(|window| self.instant.elapsed() > window)
            .unwrap_or(true)
    }

    fn should_rotate_after(&self, nevents: usize) -> bool {
        self.config
            .max_events
            .map(|max_events| nevents > max_events)
            .unwrap_or(false)
    }

    pub fn should_rotate(&self) -> bool {
        self.should_rotate_after(self.written_events + self.pending_events)
    }

    pub fn push_group(&mut self, mut group: EventGroup) {
        // Coalesce the event to the previous one, if possible
        let coalesce_window_elapsed = self.coalesce_window_elapsed();
        let should_rotate = self.should_rotate();
        match self.groups.last_mut() {
            Some(last)
                if last.context() == group.context()
                    && !coalesce_window_elapsed
                    && !should_rotate =>
            {
                last.coalesce(&mut group)
            }
            _ => self.groups.push(group.clone()),
        }
        self.pending_events += 1;
    }

    pub async fn close(&mut self) -> Result<()> {
        let file = self.file.take().unwrap();

        file.sync_all()
            .await
            .with_context(|| format!("unable to sync file `{}`", self.config.log_file.display()))?;

        #[cfg(feature = "tokio-uring")]
        file.close().await.with_context(|| {
            format!("unable to close file `{}`", self.config.log_file.display())
        })?;

        Ok(())
    }

    pub async fn rotate(&mut self) -> Result<()> {
        self.close().await?;

        let now = OffsetDateTime::now_local()?;

        let mut backup_log_file = PathBuf::from(format!(
            "{}-{}.0",
            self.config.log_file.to_str().unwrap(),
            now.format(&format_description!("[year]-[month]-[day]"))?,
        ));
        let mut counter = 0u64;
        while backup_log_file.exists() {
            counter += 1;
            backup_log_file.set_extension(counter.to_string());
        }

        rename(&self.config.log_file, &backup_log_file)
            .await
            .with_context(|| {
                format!(
                    "unable to rename file `{}` to `{}`",
                    self.config.log_file.display(),
                    backup_log_file.display(),
                )
            })?;

        self.file = Some(File::create(&self.config.log_file).await.with_context(|| {
            format!("unable to create file `{}`", self.config.log_file.display())
        })?);

        self.offset = 0;
        self.written_events = 0;

        Ok(())
    }

    #[cfg(feature = "tokio-uring")]
    async fn write_all(&mut self, data: Vec<u8>) -> Result<()> {
        let (res, _) = match self.file {
            Some(ref file) => file.write_at(data, self.offset).await,
            _ => bail!("log file is not opened"),
        };
        let n = res?;
        self.offset += n as u64;
        Ok(())
    }

    #[cfg(not(feature = "tokio-uring"))]
    async fn write_all(&mut self, data: Vec<u8>) -> Result<()> {
        match self.file {
            Some(ref mut file) => file.write_all(&data).await?,
            _ => bail!("log file is not opened"),
        };
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.pending_events = 0;
        for group in self.groups.clone() {
            if self.should_rotate_after(self.written_events) {
                self.rotate().await?;
            }
            let v = match self.config.format {
                config::Format::Normal => serde_cbor::ser::to_vec(&group)?,
                config::Format::Packed => serde_cbor::ser::to_vec_packed(&group)?,
                config::Format::Minimal => to_vec_minimal(&group)?,
            };
            self.write_all(v).await?;
            probe!(
                crypto_auditing_internal_agent,
                event_group,
                group.events().len()
            );
            self.written_events += group.events().len();
        }
        self.groups.clear();
        self.instant = Instant::now();

        Ok(())
    }
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
