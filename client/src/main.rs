// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result};
use crypto_auditing::event_broker::Client;
use futures::StreamExt;
use std::fs::File;
use std::io::{stdout, Write};
use tokio::signal;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod config;

fn get_writer(c: &config::Config) -> Result<Box<dyn Write + Send>> {
    if let Some(path) = &c.output {
        Ok(File::create(path)
            .map(Box::new)
            .with_context(|| format!("unable to create file {}", path.display()))?)
    } else {
        Ok(Box::new(stdout()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::Config::new()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let client = Client::new()
        .address(&config.socket_path)
        .scopes(&config.scope);

    let mut writer = get_writer(&config)?;

    let (_handle, mut reader) = client.start().await?;

    tokio::spawn(async move {
        while let Some(group) = reader.next().await {
            match config.format {
                config::Format::Json => {
                    if let Err(e) = serde_json::to_writer_pretty(&mut writer, &group) {
                        info!(error = %e,
                              "unable to write group");
                    }
                }
                config::Format::Cbor => {
                    if let Err(e) = serde_cbor::ser::to_writer(&mut writer, &group) {
                        info!(error = %e,
                              "unable to write group");
                    }
                }
            }
        }
    });

    signal::ctrl_c().await?;

    Ok(())
}
