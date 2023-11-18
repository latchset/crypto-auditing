// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

#[cfg(feature = "libsystemd")]
use anyhow::bail;
use anyhow::{Context as _, Result};
use crypto_auditing::types::EventGroup;
use futures::{future, stream::StreamExt, try_join, SinkExt, TryStreamExt};
use inotify::{EventMask, Inotify, WatchMask};
#[cfg(feature = "libsystemd")]
use libsystemd::activation::receive_descriptors;
use serde_cbor::de::Deserializer;
use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
#[cfg(feature = "libsystemd")]
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::net::{unix::OwnedWriteHalf, UnixListener};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_serde::{formats::SymmetricalCbor, SymmetricallyFramed};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod config;

struct Reader {
    log_file: PathBuf,
}

impl Reader {
    fn new(log_file: impl AsRef<Path>) -> Self {
        let log_file = log_file.as_ref().to_path_buf();
        Self { log_file }
    }

    async fn read(&self, sender: Sender<EventGroup>) -> Result<()> {
        let inotify =
            Inotify::init().with_context(|| "unable to initialize inotify".to_string())?;
        inotify
            .watches()
            .add(&self.log_file, WatchMask::MODIFY | WatchMask::CREATE)
            .with_context(|| format!("unable to monitor {}", self.log_file.display()))?;
        let mut file = std::fs::File::open(&self.log_file).ok();

        let mut buffer = [0; 1024];
        let mut stream = inotify.into_event_stream(&mut buffer)?;

        while let Some(event_or_error) = stream.next().await {
            let event = event_or_error?;
            if event.mask.contains(EventMask::CREATE) {
                let new_file = std::fs::File::open(&self.log_file).with_context(|| {
                    format!("unable to read file `{}`", self.log_file.display())
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

#[derive(Debug)]
struct Subscription {
    stream: SymmetricallyFramed<
        FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
        EventGroup,
        SymmetricalCbor<EventGroup>,
    >,
    scopes: Vec<String>,
    errored: bool,
}

#[derive(Debug)]
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

    #[cfg(feature = "libsystemd")]
    fn get_std_listener(&self) -> Result<StdUnixListener> {
        if let Ok(mut descriptors) = receive_descriptors(false) {
            if descriptors.len() > 1 {
                bail!("too many file descriptors");
            } else if descriptors.is_empty() {
                bail!("no file descriptors received");
            }
            let fd = descriptors.pop().unwrap().into_raw_fd();
            Ok(unsafe { StdUnixListener::from_raw_fd(fd) })
        } else {
            Ok(StdUnixListener::bind(&self.socket_path)?)
        }
    }

    #[cfg(not(feature = "libsystemd"))]
    fn get_std_listener(&self) -> Result<StdUnixListener> {
        Ok(StdUnixListener::bind(&self.socket_path)?)
    }

    async fn publish(&self, receiver: Receiver<EventGroup>) -> Result<()> {
        let std_listener = self.get_std_listener()?;
        std_listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(std_listener)?;
        let subscriptions = self.subscriptions.clone();

        tokio::spawn(async move {
            while let Ok((stream, _sock_addr)) = listener.accept().await {
                let subscriber_fd = stream.as_raw_fd();

                debug!(socket = subscriber_fd, "subscriber connected");

                let (de, ser) = stream.into_split();

                let ser = FramedWrite::new(ser, LengthDelimitedCodec::new());
                let de = FramedRead::new(de, LengthDelimitedCodec::new());

                let ser = SymmetricallyFramed::new(ser, SymmetricalCbor::<EventGroup>::default());
                let mut de =
                    SymmetricallyFramed::new(de, SymmetricalCbor::<Vec<String>>::default());

                // Populate the scopes
                if let Some(scopes) = de.try_next().await.unwrap() {
                    subscriptions.write().unwrap().insert(
                        subscriber_fd,
                        Subscription {
                            stream: ser,
                            scopes,
                            errored: Default::default(),
                        },
                    );
                }
            }
        });

        let mut stream = ReceiverStream::new(receiver);
        while let Some(group) = stream.next().await {
            let mut subscriptions = self.subscriptions.write().unwrap();
            let mut publications = Vec::new();

            for (_, subscription) in subscriptions.iter_mut() {
                let mut group = group.clone();
                group.events_filtered(&subscription.scopes);
                if !group.events().is_empty() {
                    publications.push(async move {
                        if let Err(e) = subscription.stream.send(group).await {
                            info!(error = %e, "unable to send event");
                            subscription.errored = true;
                        }
                    });
                }
            }

            future::join_all(publications).await;

            // Remove errored subscriptions
            subscriptions.retain(|_, v| !v.errored);
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::new()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let reader = Reader::new(&config.log_file);
    let publisher = Publisher::new(&config.socket_path);

    let (tx, rx) = mpsc::channel::<EventGroup>(10);
    try_join!(reader.read(tx), publisher.publish(rx),).map(|_| ())
}
