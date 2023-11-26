// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

#[cfg(feature = "libsystemd")]
use anyhow::bail;
use anyhow::{Context as _, Result};
use crypto_auditing::types::EventGroup;
use futures::{future, stream::StreamExt, try_join, SinkExt, Stream, TryStreamExt};
use inotify::{EventMask, EventStream, Inotify, WatchDescriptor, WatchMask};
#[cfg(feature = "libsystemd")]
use libsystemd::activation::receive_descriptors;
use serde_cbor::de::Deserializer;
use std::collections::HashMap;
use std::fs;
use std::marker;
use std::os::fd::{AsRawFd, RawFd};
#[cfg(feature = "libsystemd")]
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{unix::OwnedWriteHalf, UnixListener, UnixStream};
use tokio::signal;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_serde::{formats::SymmetricalCbor, SymmetricallyFramed};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod config;

struct Reader {
    log_file: PathBuf,
    watch_descriptor: Option<WatchDescriptor>,
}

impl Reader {
    fn new(log_file: impl AsRef<Path>) -> Self {
        let log_file = log_file.as_ref().to_path_buf();
        Self {
            log_file,
            watch_descriptor: None,
        }
    }

    fn enable_monitor(&mut self, stream: &EventStream<&mut [u8; 1024]>) -> Result<()> {
        if self.watch_descriptor.is_none() {
            let watch_descriptor = stream
                .watches()
                .add(&self.log_file, WatchMask::MODIFY | WatchMask::CREATE)
                .with_context(|| {
                    format!("unable to start monitoring {}", self.log_file.display())
                })?;
            self.watch_descriptor = Some(watch_descriptor);
            info!("enabled monitoring of {}", self.log_file.display());
        }
        Ok(())
    }

    fn disable_monitor(&mut self, stream: &EventStream<&mut [u8; 1024]>) -> Result<()> {
        if self.watch_descriptor.is_some() {
            let watch_descriptor = self.watch_descriptor.take();
            stream
                .watches()
                .remove(watch_descriptor.unwrap())
                .with_context(|| {
                    format!("unable to stop monitoring {}", self.log_file.display())
                })?;
            info!("disabled monitoring of {}", self.log_file.display());
        }
        Ok(())
    }

    async fn read(
        &mut self,
        event_sender: &mpsc::Sender<EventGroup>,
        mut subscription_stream: impl Stream<Item = usize> + marker::Unpin,
        shutdown_receiver: &mut broadcast::Receiver<()>,
    ) -> Result<()> {
        let inotify =
            Inotify::init().with_context(|| "unable to initialize inotify".to_string())?;
        let mut file = fs::File::open(&self.log_file)
            .with_context(|| format!("unable to open {}", self.log_file.display()))?;

        let mut buffer = [0; 1024];
        let mut inotify_stream = inotify.into_event_stream(&mut buffer)?;

        loop {
            tokio::select! {
                Some(event_or_error) = inotify_stream.next() => {
                    let event = event_or_error?;
                    if event.mask.contains(EventMask::CREATE) {
                        file = fs::File::open(&self.log_file).with_context(|| {
                            format!("unable to read file `{}`", self.log_file.display())
                        })?;
                    }
                    for group in Deserializer::from_reader(&mut file).into_iter::<EventGroup>() {
                        event_sender.send(group?).await?
                    }
                },
                Some(n_subscriptions) = subscription_stream.next() => {
                    if n_subscriptions > 0 {
                        self.enable_monitor(&inotify_stream)?;
                    } else {
                        self.disable_monitor(&inotify_stream)?;
                    }
                }
                _ = shutdown_receiver.recv() => break,
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
    activated: Arc<RwLock<bool>>,
}

impl Publisher {
    fn new(socket_path: impl AsRef<Path>) -> Self {
        let socket_path = socket_path.as_ref().to_path_buf();
        Self {
            socket_path,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            activated: Arc::new(RwLock::new(false)),
        }
    }

    #[cfg(feature = "libsystemd")]
    async fn get_std_listener(&self) -> Result<StdUnixListener> {
        match receive_descriptors(false) {
            Ok(mut descriptors) => {
                if descriptors.len() > 1 {
                    bail!("too many file descriptors");
                } else if descriptors.is_empty() {
                    bail!("no file descriptors received");
                }
                let fd = descriptors.pop().unwrap().into_raw_fd();
                let mut activated = self.activated.write().await;
                *activated = true;
                Ok(unsafe { StdUnixListener::from_raw_fd(fd) })
            }
            Err(e) => {
                info!(error = %e, "unable to receive file descriptors");
                Ok(StdUnixListener::bind(&self.socket_path)?)
            }
        }
    }

    #[cfg(not(feature = "libsystemd"))]
    async fn get_std_listener(&self) -> Result<StdUnixListener> {
        Ok(StdUnixListener::bind(&self.socket_path)?)
    }

    async fn accept_subscriber(
        &self,
        stream: UnixStream,
        subscription_sender: &mpsc::Sender<usize>,
    ) -> Result<()> {
        let subscriber_fd = stream.as_raw_fd();

        debug!(socket = subscriber_fd, "subscriber connected");

        let (de, ser) = stream.into_split();

        let ser = FramedWrite::new(ser, LengthDelimitedCodec::new());
        let de = FramedRead::new(de, LengthDelimitedCodec::new());

        let ser = SymmetricallyFramed::new(ser, SymmetricalCbor::<EventGroup>::default());
        let mut de = SymmetricallyFramed::new(de, SymmetricalCbor::<Vec<String>>::default());

        // Populate the scopes
        if let Some(scopes) = de.try_next().await.unwrap() {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(
                subscriber_fd,
                Subscription {
                    stream: ser,
                    scopes,
                    errored: Default::default(),
                },
            );
            subscription_sender.send(subscriptions.len()).await?;
        }
        Ok(())
    }

    async fn listen(
        &self,
        subscription_sender: &mpsc::Sender<usize>,
        shutdown_receiver: &mut broadcast::Receiver<()>,
    ) -> Result<()> {
        let std_listener = self.get_std_listener().await?;
        std_listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(std_listener)?;

        loop {
            tokio::select! {
                maybe_stream = listener.accept() => {
                    let stream = match maybe_stream {
                        Ok((stream, _sock_addr)) => stream,
                        Err(e) => {
                            info!(error = %e, "unable to accept connection");
                            break;
                        }
                    };
                    if let Err(e) = self.accept_subscriber(
                        stream,
                        subscription_sender,
                    ).await {
                        info!(error = %e, "unable to accept subscriber");
                        break;
                    }
                },
                _ = shutdown_receiver.recv() => {
                    if !*self.activated.read().await {
                        drop(listener);
                        if let Err(e) = fs::remove_file(&self.socket_path) {
                            info!(error = %e, "error removing socket");
                        }
                    }
                    break;
                },
            }
        }
        Ok(())
    }

    async fn publish_event(
        &self,
        group: &EventGroup,
        subscription_sender: &mpsc::Sender<usize>,
    ) -> Result<()> {
        let mut subscriptions = self.subscriptions.write().await;
        let mut publications = Vec::new();

        let n_subscriptions = subscriptions.len();

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

        if subscriptions.len() != n_subscriptions {
            subscription_sender.send(subscriptions.len()).await?;
        }

        Ok(())
    }

    async fn publish(
        &self,
        mut event_stream: impl Stream<Item = EventGroup> + marker::Unpin,
        subscription_sender: &mpsc::Sender<usize>,
        shutdown_receiver: &mut broadcast::Receiver<()>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                Some(ref group) = event_stream.next() => {
                    self.publish_event(
                        group,
                        subscription_sender,
                    ).await?
                },
                _ = shutdown_receiver.recv() => break,
            }
        }

        Ok(())
    }
}

async fn shutdown(
    shutdown_receiver: &mut broadcast::Receiver<()>,
    shutdown_sender: &broadcast::Sender<()>,
) -> Result<()> {
    tokio::select! {
        maybe_value = signal::ctrl_c() => {
            if let Err(e) = maybe_value {
                info!(error = %e, "error receiving ctrl-c")
            }
            info!("shutting down event broker");
            if let Err(e) = shutdown_sender.send(()) {
                info!(error = %e, "unable to send shutdown");
            }
        },
        _ = shutdown_receiver.recv() => (),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::new()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    let mut reader = Reader::new(&config.log_file);
    let publisher = Publisher::new(&config.socket_path);

    let (event_tx, event_rx) = mpsc::channel::<EventGroup>(10);
    let mut event_rx = ReceiverStream::new(event_rx);

    let (subscription_tx, subscription_rx) = mpsc::channel::<usize>(10);
    let mut subscription_rx = ReceiverStream::new(subscription_rx);

    let (shutdown_tx, mut shutdown_rx1) = broadcast::channel::<()>(2);
    let mut shutdown_rx2 = shutdown_tx.subscribe();
    let mut shutdown_rx3 = shutdown_tx.subscribe();
    let mut shutdown_rx4 = shutdown_tx.subscribe();

    try_join!(
        shutdown(&mut shutdown_rx1, &shutdown_tx),
        reader.read(&event_tx, &mut subscription_rx, &mut shutdown_rx2),
        publisher.listen(&subscription_tx, &mut shutdown_rx3),
        publisher.publish(&mut event_rx, &subscription_tx, &mut shutdown_rx4),
    )
    .map(|_| ())
}
