// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result};
use clap::Parser;
use crypto_auditing::{
    event_broker::SOCKET_PATH,
    types::EventGroup,
};
use futures::{future, stream::StreamExt, try_join};
use inotify::{EventMask, Inotify, WatchMask};
use serde_cbor::de::Deserializer;
use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tarpc::{client, context, tokio_serde::formats::Cbor};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(about = "Event broker server for crypto-auditing")]
struct Cli {
    /// Path to log file to parse
    log_path: PathBuf,
    /// Path to Unix socket
    #[arg(short, long, default_value = SOCKET_PATH)]
    socket_path: PathBuf,
}

mod service;
use service::SubscriberClient;

struct Reader {
    log_path: PathBuf,
}

impl Reader {
    fn new(log_path: impl AsRef<Path>) -> Self {
        let log_path = log_path.as_ref().to_path_buf();
        Self { log_path }
    }

    async fn read(&self, sender: Sender<EventGroup>) -> Result<()> {
        let mut inotify =
            Inotify::init().with_context(|| format!("unable to initialize inotify"))?;
        inotify
            .add_watch(&self.log_path, WatchMask::MODIFY | WatchMask::CREATE)
            .with_context(|| format!("unable to monitor {}", self.log_path.display()))?;
        let mut file = std::fs::File::open(&self.log_path).ok();

        let mut buffer = [0; 1024];
        let mut stream = inotify.event_stream(&mut buffer)?;

        while let Some(event_or_error) = stream.next().await {
            let event = event_or_error?;
            if event.mask.contains(EventMask::CREATE) {
                let new_file = std::fs::File::open(&self.log_path).with_context(|| {
                    format!("unable to read file `{}`", self.log_path.display())
                })?;
                let _old = file.replace(new_file);
            }
            if let Some(ref file) = file {
                for group in Deserializer::from_reader(file).into_iter::<EventGroup>() {
                    sender.send(group?).await?
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Subscription {
    client: SubscriberClient,
    scopes: Vec<String>,
}

#[derive(Clone, Debug)]
struct Publisher {
    socket_path: PathBuf,
    subscriptions: Arc<RwLock<HashMap<RawFd, Subscription>>>,
}

impl Publisher {
    fn new(socket_path: impl AsRef<Path>) -> Self {
        let socket_path = socket_path.as_ref().to_path_buf();
        Self {
            socket_path,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn publish(&self, receiver: Receiver<EventGroup>) -> Result<()> {
        let mut connecting_subscribers =
            tarpc::serde_transport::unix::listen(&self.socket_path, Cbor::default)
                .await?
                .filter_map(|r| future::ready(r.ok()));

        let subscriptions = self.subscriptions.clone();

        tokio::spawn(async move {
            while let Some(conn) = connecting_subscribers.next().await {
                let subscriber_fd = conn.get_ref().as_raw_fd();

                let tarpc::client::NewClient {
                    client: subscriber,
                    dispatch,
                } = SubscriberClient::new(client::Config::default(), conn);

                debug!(socket = subscriber_fd, "subscriber connected");

                let subscriptions2 = subscriptions.clone();
                tokio::spawn(async move {
                    if let Err(e) = dispatch.await {
                        info!(error = %e,
                              "subscriber connection broken");
                    }

                    debug!(socket = %subscriber_fd, "closing connection");
                    subscriptions2.write().unwrap().remove(&subscriber_fd);
                });

                // Populate the scopes
                if let Ok(scopes) = subscriber.scopes(context::current()).await {
                    subscriptions.write().unwrap().insert(
                        subscriber_fd,
                        Subscription {
                            client: subscriber,
                            scopes: scopes.clone(),
                        },
                    );
                }
            }
        });

        let mut stream = ReceiverStream::new(receiver);
        let mut subscriptions;
        while let Some(group) = stream.next().await {
            let mut publications = Vec::new();

            subscriptions = self.subscriptions.read().unwrap().clone();
            for subscription in subscriptions.values() {
                let mut group = group.clone();
                group.events_filtered(&subscription.scopes);
                if !group.events().is_empty() {
                    publications.push(subscription.client.receive(context::current(), group));
                }
            }

            future::join_all(publications).await;
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let reader = Reader::new(&cli.log_path);
    let publisher = Publisher::new(&cli.socket_path);

    let (tx, rx) = mpsc::channel::<EventGroup>(10);
    try_join!(reader.read(tx), publisher.publish(rx),).map(|_| ())
}
