// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::event_broker::{error::Result, service::Subscriber as _, SOCKET_PATH};
use crate::types::EventGroup;
use futures::{
    future::{self, AbortHandle},
    stream::Stream,
};
use std::path::{Path, PathBuf};
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Cbor,
};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;
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

#[tarpc::server]
impl crate::event_broker::service::Subscriber for ClientInner {
    async fn scopes(self, _: context::Context) -> Vec<String> {
        self.scopes.clone()
    }

    async fn receive(self, _: context::Context, group: EventGroup) {
        if let Err(e) = self.sender.send(group).await {
            info!(error = %e,
                  "unable to send event");
        }
    }
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
        let server = tarpc::serde_transport::unix::connect(&self.address, Cbor::default).await?;
        let local_addr = server.local_addr()?;
        let handler = server::BaseChannel::with_defaults(server).requests();
        let (handler, abort_handle) =
            future::abortable(handler.execute(self.inner.clone().serve()));
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
