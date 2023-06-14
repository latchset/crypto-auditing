// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{anyhow, Context as _, Result};
use clap::{arg, command, parser::ValueSource, value_parser, ArgAction, ArgMatches, ValueEnum};
use crypto_auditing::event_broker::SOCKET_PATH;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toml::{Table, Value};

const CONFIG: &'static str = "/etc/crypto-auditing/event-broker.conf";

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Format {
    Json,
    Cbor,
}

#[derive(Debug)]
pub struct Config {
    /// Path to Unix socket
    pub socket_path: PathBuf,

    /// Scope to match
    pub scope: Vec<String>,

    /// Output format
    pub format: Format,

    /// Path to output file
    pub output: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(SOCKET_PATH),
            scope: Vec::default(),
            format: Format::Json,
            output: None,
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
                    --"socket-path" <PATH> "Path to Unix socket"
                )
                .required(false)
                .value_parser(value_parser!(PathBuf))
                .default_value(SOCKET_PATH),
            )
            .arg(
                arg!(
                    --scope <SCOPE> "Scope to restrict matches"
                )
                .required(false)
                .value_parser(value_parser!(String))
                .action(ArgAction::Append),
            )
            .arg(
                arg!(
                    --format <FORMAT> "Output format"
                )
                .required(false)
                .value_parser(value_parser!(Format)),
            )
            .arg(
                arg!(
                    --output <PATH> "Path to output file"
                )
                .required(false)
                .value_parser(value_parser!(PathBuf)),
            )
            .get_matches();

        if let Some(config_file) = matches.get_one::<PathBuf>("config") {
            config.merge_config_file(&config_file)?;
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

        if let Some(value) = config.get("socket_path") {
            self.socket_path = pathbuf_from_value(value)?;
        }

        if let Some(value) = config.get("scope") {
            self.scope = string_array_from_value(value)?;
        }

        if let Some(value) = config.get("format") {
            self.format = format_from_value(value)?;
        }

        if let Some(value) = config.get("output") {
            self.output = Some(pathbuf_from_value(value)?);
        }

        Ok(())
    }

    fn merge_arg_matches(&mut self, matches: &ArgMatches) -> Result<()> {
        if let Some(ValueSource::CommandLine) = matches.value_source("socket-path") {
            self.socket_path = matches
                .try_get_one::<PathBuf>("socket-path")?
                .unwrap()
                .clone();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("scope") {
            self.scope = matches.try_get_many("scope")?.unwrap().cloned().collect();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("format") {
            self.format = *matches.try_get_one::<Format>("format")?.unwrap();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("output") {
            self.output = Some(matches.try_get_one::<PathBuf>("output")?.unwrap().clone());
        }

        Ok(())
    }
}

fn string_array_from_value(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("value must be array"))
        .and_then(|array| {
            array
                .iter()
                .map(|v| string_from_value(v))
                .collect::<Result<Vec<String>>>()
        })
}

fn string_from_value(value: &Value) -> Result<String> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .and_then(|v| Ok(v.to_string()))
}

fn pathbuf_from_value(value: &Value) -> Result<PathBuf> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .and_then(|v| Ok(PathBuf::from(v)))
}

fn format_from_value(value: &Value) -> Result<Format> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be format"))
        .and_then(|v| Format::from_str(v, false).map_err(|e| anyhow!("{}", e)))
}
