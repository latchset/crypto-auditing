// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::Result;
use clap::Parser;
use crypto_auditing::event_broker::{Client, SOCKET_PATH};
use futures::StreamExt;
use std::path::PathBuf;
use tokio::signal;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(about = "Event broker client for crypto-auditing")]
struct Cli {
    /// Path to Unix socket
    #[arg(short, long, default_value = SOCKET_PATH)]
    socket_path: PathBuf,

    #[arg(long)]
    scope: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let client = Client::new().address(&cli.socket_path).scopes(&cli.scope);

    let (_handle, mut reader) = client.start().await?;

    tokio::spawn(async move {
        while let Some(event) = reader.next().await {
            println!("{:?}", &event);
        }
    });

    signal::ctrl_c().await?;

    Ok(())
}
