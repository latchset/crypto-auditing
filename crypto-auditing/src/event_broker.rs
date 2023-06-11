// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

mod error;
pub use error::{Error, Result};

mod service;

mod client;
pub use client::{Client, ClientHandle};

/// The default path of the Unix domain socket where the event broker is running
pub const SOCKET_PATH: &'static str = "/var/lib/crypto-auditing/audit.sock";
