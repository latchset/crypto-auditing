// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2025 The crypto-auditing developers.

use anyhow::{Context as _, Result, anyhow};
use clap::{ArgAction, ArgMatches, arg, command, parser::ValueSource, value_parser};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use toml::{Table, Value};

const CONFIG: &str = "/etc/crypto-auditing/monitor.conf";
const LOG: &str = "/var/log/crypto-auditing/audit.cborseq";

#[derive(Debug)]
pub struct Config {
    /// Path to output log file
    pub log_file: PathBuf,

    /// Scope to match
    pub scope: Vec<String>,

    /// Event window
    pub event_window: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_file: PathBuf::from(LOG),
            scope: Vec::default(),
            event_window: Duration::from_secs(3),
        }
    }
}

fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseIntError> {
    let milliseconds = arg.parse()?;
    Ok(Duration::from_millis(milliseconds))
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
                    --scope <SCOPE> "Scope to restrict matches"
                )
                .required(false)
                .value_parser(value_parser!(String))
                .action(ArgAction::Append),
            )
            .arg(
                arg!(
                    --"event-window" <WINDOW> "Event window"
                )
                .required(false)
                .value_parser(parse_duration),
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

        if let Some(value) = config.get("scope") {
            self.scope = string_array_from_value(value)?;
        }

        if let Some(value) = config.get("event_window") {
            self.event_window = duration_millis_from_value(value)?;
        }

        Ok(())
    }

    fn merge_arg_matches(&mut self, matches: &ArgMatches) -> Result<()> {
        if let Some(ValueSource::CommandLine) = matches.value_source("log-file") {
            self.log_file = matches.try_get_one::<PathBuf>("log-file")?.unwrap().clone();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("event-window") {
            self.event_window = *matches.try_get_one::<Duration>("event-window")?.unwrap();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("scope") {
            self.scope = matches.try_get_many("scope")?.unwrap().cloned().collect();
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
                .map(string_from_value)
                .collect::<Result<Vec<String>>>()
        })
}

fn string_from_value(value: &Value) -> Result<String> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .map(|v| v.to_string())
}

fn pathbuf_from_value(value: &Value) -> Result<PathBuf> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .map(PathBuf::from)
}

fn duration_millis_from_value(value: &Value) -> Result<Duration> {
    value
        .as_integer()
        .ok_or_else(|| anyhow!("value must be duration in milliseconds"))
        .map(|v| Duration::from_millis(v as u64))
}
