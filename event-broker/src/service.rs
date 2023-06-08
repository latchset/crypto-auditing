// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crypto_auditing_types::EventGroup;

#[tarpc::service]
pub trait Subscriber {
    async fn scopes() -> Vec<String>;
    async fn receive(group: EventGroup);
}

pub const SOCKET_PATH: &'static str = "/var/lib/crypto-auditing/audit.sock";
