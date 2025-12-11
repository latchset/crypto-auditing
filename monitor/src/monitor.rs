// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2025 The crypto-auditing developers.

use anyhow::{Context as _, Result};
use crypto_auditing::types::{Context, ContextID, Event, EventGroup};
use futures::{Stream, stream::StreamExt, try_join};
use inotify::{EventMask, EventStream, Inotify, WatchDescriptor, WatchMask};
use serde_cbor::de::Deserializer;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::marker;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod config;

struct Reader {
    log_file: PathBuf,
    inotify_stream: EventStream<Vec<u8>>,
    watch_descriptor: WatchDescriptor,
}

impl Reader {
    fn new(log_file: impl AsRef<Path>) -> Result<Self> {
        let log_file = log_file.as_ref().to_path_buf();
        let inotify =
            Inotify::init().with_context(|| "unable to initialize inotify".to_string())?;
        let buffer = vec![0; 1024];
        let inotify_stream = inotify.into_event_stream(buffer)?;
        let watch_descriptor = inotify_stream
            .watches()
            .add(&log_file, WatchMask::MODIFY)
            .with_context(|| format!("unable to start monitoring {}", log_file.display()))?;
        Ok(Self {
            log_file,
            inotify_stream,
            watch_descriptor,
        })
    }

    async fn read(
        &mut self,
        event_sender: &mpsc::Sender<EventGroup>,
        shutdown_receiver: &mut broadcast::Receiver<()>,
    ) -> Result<()> {
        let mut file = fs::File::open(&self.log_file)
            .with_context(|| format!("unable to open {}", self.log_file.display()))?;

        loop {
            tokio::select! {
                Some(event_or_error) = self.inotify_stream.next() => {
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
                _ = shutdown_receiver.recv() => break,
            }
        }

        Ok(())
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        if let Err(e) = self
            .inotify_stream
            .watches()
            .remove(self.watch_descriptor.clone())
        {
            info!(error = %e, "unable to stop monitoring {}", self.log_file.display());
        } else {
            info!("disabled monitoring of {}", self.log_file.display());
        }
    }
}

#[derive(Debug)]
struct Writer {
    all_contexts: BTreeMap<ContextID, Rc<RefCell<Context>>>,
    root_contexts: Vec<(Instant, Rc<RefCell<Context>>)>,
    event_window: Duration,
    scopes: Vec<String>,
    timeouts: JoinSet<()>,
}

impl Writer {
    fn new(event_window: Duration, scopes: &Vec<String>) -> Self {
        let all_contexts: BTreeMap<ContextID, Rc<RefCell<Context>>> = BTreeMap::new();
        let root_contexts = Vec::new();
        Self {
            all_contexts,
            root_contexts,
            event_window,
            scopes: scopes.to_owned(),
            timeouts: JoinSet::new(),
        }
    }

    async fn handle_event_group(&mut self, group: &EventGroup) -> Result<()> {
        let mut group = group.clone();
        if !self.scopes.is_empty() {
            group.events_filtered(&self.scopes);
        }
        for event in group.events() {
            match event {
                Event::NewContext {
                    parent: parent_context,
                    origin,
                } => {
                    let context = Rc::new(RefCell::new(Context {
                        context: *group.context(),
                        origin: origin.to_owned(),
                        start: group.start(),
                        end: group.end(),
                        ..Default::default()
                    }));
                    if let Some(parent) = self.all_contexts.get(&parent_context[..]) {
                        parent
                            .borrow_mut()
                            .spans
                            .insert(*group.context(), context.clone());
                    } else {
                        self.root_contexts.push((Instant::now(), context.clone()));
                        self.timeouts.spawn(sleep(self.event_window));
                    }
                    self.all_contexts.insert(*group.context(), context);
                }
                Event::Data { key, value } => {
                    if !self.all_contexts.contains_key(group.context()) {
                        // Either this library did not do a new_context for this context, or the
                        // log we have is truncated at the beginning. Just assume that this context
                        // has no parent and create a new one so we don't loose the information in
                        // this message.
                        let context_obj = Rc::new(RefCell::new(Context {
                            context: *group.context(),
                            start: group.start(),
                            end: group.end(),
                            ..Default::default()
                        }));
                        self.root_contexts
                            .push((Instant::now(), context_obj.clone()));
                        self.all_contexts.insert(*group.context(), context_obj);
                    }
                    if let Some(parent) = self.all_contexts.get(group.context()) {
                        parent
                            .borrow_mut()
                            .events
                            .insert(key.to_string(), value.clone());
                    }
                }
            }
        }

        Ok(())
    }

    async fn write(
        &mut self,
        mut event_stream: impl Stream<Item = EventGroup> + marker::Unpin,
        shutdown_receiver: &mut broadcast::Receiver<()>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                Some(ref group) = event_stream.next() => {
                    self.handle_event_group(
                        group,
                    ).await?
                },
                Some(_) = self.timeouts.join_next() => {
                    self.root_contexts.retain(|(instant, context)| {
                        if instant.elapsed() > self.event_window {
                            println!("{}", serde_json::to_string_pretty(context).unwrap());
                            return false;
                        }
                        true
                    });
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

    let mut reader = Reader::new(&config.log_file)?;
    let mut writer = Writer::new(config.event_window, &config.scope);

    let (event_tx, event_rx) = mpsc::channel::<EventGroup>(10);
    let mut event_rx = ReceiverStream::new(event_rx);

    let (shutdown_tx, mut shutdown_rx1) = broadcast::channel::<()>(2);
    let mut shutdown_rx2 = shutdown_tx.subscribe();
    let mut shutdown_rx3 = shutdown_tx.subscribe();

    try_join!(
        shutdown(&mut shutdown_rx1, &shutdown_tx),
        reader.read(&event_tx, &mut shutdown_rx2),
        writer.write(&mut event_rx, &mut shutdown_rx3),
    )
    .map(|_| ())
}
