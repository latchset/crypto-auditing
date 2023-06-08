// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::service::SOCKET_PATH;
use anyhow::Result;
use crypto_auditing_types::EventGroup;
use futures::future::{self, AbortHandle};
use futures_util::Stream;
use std::path::{Path, PathBuf};
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Cbor,
};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;
use tracing::info;

use crate::service::Subscriber as _;

#[derive(Clone, Debug)]
struct ClientInner {
    scopes: Vec<String>,
    sender: Sender<EventGroup>,
}

pub struct Client {
    inner: ClientInner,
    address: PathBuf,
    receiver: Receiver<EventGroup>,
}

#[tarpc::server]
impl crate::service::Subscriber for ClientInner {
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

pub struct ClientHandle(AbortHandle);

impl Drop for ClientHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Client {
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

    pub fn address(mut self, address: impl AsRef<Path>) -> Self {
        self.address = address.as_ref().to_owned();
        self
    }

    pub fn scopes(mut self, scopes: &Vec<String>) -> Self {
        self.inner.scopes = scopes.to_owned();
        self
    }

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
