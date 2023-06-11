// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::types::EventGroup;

#[tarpc::service]
pub trait Subscriber {
    async fn scopes() -> Vec<String>;
    async fn receive(group: EventGroup);
}
