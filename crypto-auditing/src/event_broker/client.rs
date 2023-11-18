// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::event_broker::{error::Result, SOCKET_PATH};
use crate::types::EventGroup;
use futures::{
    future::{self, AbortHandle},
    stream::Stream,
    SinkExt, TryStreamExt,
};
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_serde::{formats::SymmetricalCbor, SymmetricallyFramed};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::info;

#[derive(Clone, Debug)]
struct ClientInner {
    scopes: Vec<String>,
    sender: Sender<EventGroup>,
}

/// A client to the event broker service
///
/// # Examples
///
/// ```no_run
/// use crypto_auditing::event_broker::Client;
/// use futures::stream::StreamExt;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let client = Client::new().scopes(&vec!["tcp".to_string()]);
///
///     let (_handle, mut reader) = client.start().await?;
///
///     tokio::spawn(async move {
///         while let Some(event) = reader.next().await {
///             println!("{:?}", &event);
///         }
///     });
///
///     tokio::signal::ctrl_c().await?;
///
///     Ok(())
/// }
/// ```
pub struct Client {
    inner: ClientInner,
    address: PathBuf,
    receiver: Receiver<EventGroup>,
}

/// A handle for the client connection, which will be aborted once
/// the ownership is dropped
pub struct ClientHandle(AbortHandle);

impl Drop for ClientHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Client {
    /// Returns a new [`Client`]
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<EventGroup>(10);

        Self {
            inner: ClientInner {
                scopes: Vec::new(),
                sender: tx,
            },
            address: SOCKET_PATH.into(),
            receiver: rx,
        }
    }

    /// Sets the Unix domain address of event broker
    pub fn address(mut self, address: impl AsRef<Path>) -> Self {
        self.address = address.as_ref().to_owned();
        self
    }

    /// Sets the scopes to restrict matches of events
    pub fn scopes(mut self, scopes: &Vec<String>) -> Self {
        self.inner.scopes = scopes.to_owned();
        self
    }

    /// Starts driving the client connection.
    ///
    /// This returns a tuple consisting a [`ClientHandle`] and a [`Stream`]
    /// which generates a sequence of event groups.
    pub async fn start(self) -> Result<(ClientHandle, impl Stream<Item = EventGroup>)> {
        let stream = UnixStream::connect(&self.address).await?;
        let local_addr = stream.local_addr()?;

        let (de, ser) = stream.into_split();

        let ser = FramedWrite::new(ser, LengthDelimitedCodec::new());
        let de = FramedRead::new(de, LengthDelimitedCodec::new());

        let mut ser = SymmetricallyFramed::new(ser, SymmetricalCbor::<Vec<String>>::default());
        let mut de = SymmetricallyFramed::new(de, SymmetricalCbor::<EventGroup>::default());

        let inner = self.inner.clone();
        let (handler, abort_handle) = future::abortable(async move {
            if let Err(e) = ser.send(inner.scopes).await {
                info!(error = %e,
                          "unable to send subscription request");
            }
            loop {
                let group = match de.try_next().await {
                    Ok(group) => group,
                    Err(e) => {
                        info!(error = %e,
                                  "unable to deserialize event");
                        break;
                    }
                };

                if let Some(group) = group {
                    if let Err(e) = inner.sender.send(group).await {
                        info!(error = %e,
                                  "unable to send event");
                        break;
                    }
                }
            }
        });
        tokio::spawn(async move {
            match handler.await {
                Ok(()) | Err(future::Aborted) => info!(?local_addr, "client shutdown."),
            }
        });
        Ok((
            ClientHandle(abort_handle),
            ReceiverStream::new(self.receiver),
        ))
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}
