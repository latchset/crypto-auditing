// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

mod service;
pub use service::SOCKET_PATH;

mod client;
pub use client::{Client, ClientHandle};
