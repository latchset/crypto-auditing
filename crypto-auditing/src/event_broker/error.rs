// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

/// A specialized `Result` type for event broker
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for event broker operations
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
