// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{anyhow, Context as _, Result};
use clap::{arg, command, parser::ValueSource, value_parser, ArgMatches};
use crypto_auditing::event_broker::SOCKET_PATH;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toml::{Table, Value};

const CONFIG: &str = "/etc/crypto-auditing/event-broker.conf";
const LOG: &str = "/var/log/crypto-auditing/audit.cborseq";

#[derive(Debug)]
pub struct Config {
    /// Path to output log file
    pub log_file: PathBuf,

    /// Path to Unix socket
    pub socket_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_file: PathBuf::from(LOG),
            socket_path: PathBuf::from(SOCKET_PATH),
        }
    }
}

impl Config {
    pub fn new() -> Result<Self> {
        let mut config = Config::default();

        let matches = command!()
            .arg(
                arg!(
                    -c --config <FILE> "Path to configuration file"
                )
                .required(false)
                .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                arg!(
                    --"log-file" <FILE> "Path to output log file"
                )
                .required(false)
                .value_parser(value_parser!(PathBuf))
                .default_value("audit.cborseq"),
            )
            .arg(
                arg!(
                    --"socket-path" <PATH> "Path to Unix socket"
                )
                .required(false)
                .value_parser(value_parser!(PathBuf))
                .default_value(SOCKET_PATH),
            )
            .get_matches();

        if let Some(config_file) = matches.get_one::<PathBuf>("config") {
            config.merge_config_file(config_file)?;
        } else if Path::new(CONFIG).exists() {
            config.merge_config_file(CONFIG)?;
        }

        config.merge_arg_matches(&matches)?;

        Ok(config)
    }

    fn merge_config_file(&mut self, file: impl AsRef<Path>) -> Result<()> {
        let s = fs::read_to_string(file.as_ref())
            .with_context(|| format!("unable to read config file `{}`", file.as_ref().display()))?;
        let config = Table::from_str(&s).with_context(|| {
            format!("unable to parse config file `{}`", file.as_ref().display())
        })?;

        if let Some(value) = config.get("log_file") {
            self.log_file = pathbuf_from_value(value)?;
        }

        if let Some(value) = config.get("socket_path") {
            self.socket_path = pathbuf_from_value(value)?;
        }

        Ok(())
    }

    fn merge_arg_matches(&mut self, matches: &ArgMatches) -> Result<()> {
        if let Some(ValueSource::CommandLine) = matches.value_source("log-file") {
            self.log_file = matches.try_get_one::<PathBuf>("log-file")?.unwrap().clone();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("socket-path") {
            self.socket_path = matches
                .try_get_one::<PathBuf>("socket-path")?
                .unwrap()
                .clone();
        }

        Ok(())
    }
}

fn pathbuf_from_value(value: &Value) -> Result<PathBuf> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .map(PathBuf::from)
}
