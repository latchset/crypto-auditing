// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{anyhow, Context as _, Result};
use clap::{arg, command, parser::ValueSource, value_parser, ArgAction, ArgMatches, ValueEnum};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tokio::time::{Duration, Instant};
use toml::{Table, Value};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Format {
    Normal,
    Packed,
    Minimal,
}

const CONFIG: &'static str = "/etc/crypto-auditing/agent.conf";
const LOG: &'static str = "/var/log/crypto-auditing/audit.cborseq";

#[derive(Debug)]
pub struct Config {
    /// Path to library that defines probes
    pub library: Vec<PathBuf>,

    /// Path to output log file
    pub log_file: PathBuf,

    /// User to run the program in USER:GROUP form
    pub user: Option<(String, String)>,

    /// Output format to use
    pub format: Format,

    /// Event coalescing window
    pub coalesce_window: Option<Duration>,

    /// Maximum number of events to be written to a file
    pub max_events: Option<usize>,

    /// Path to debug trace file
    pub trace_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            library: Vec::new(),
            log_file: PathBuf::from(LOG),
            user: None,
            format: Format::Normal,
            coalesce_window: None,
            max_events: None,
            trace_file: None,
        }
    }
}

fn parse_user(arg: &str) -> Result<(String, String)> {
    let (user, group) = arg.split_at(arg.find(':').ok_or_else(|| anyhow!("no delimiter"))?);
    Ok((user.to_string(), group[1..].to_string()))
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
                    --library <FILE> "Path to library that defines probes"
                )
                .required(false)
                .value_parser(value_parser!(PathBuf))
                .action(ArgAction::Append),
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
                    --user <USER> "User to run the program in USER:GROUP form"
                )
                .required(false)
                .value_parser(parse_user),
            )
            .arg(
                arg!(
                    --format <FORMAT> "Output format to use"
                )
                .required(false)
                .value_parser(value_parser!(Format)),
            )
            .arg(
                arg!(
                    --"coalesce-window" <WINDOW> "Event coalescing window"
                )
                .required(false)
                .value_parser(parse_duration),
            )
            .arg(
                arg!(
                    --"max-events" <NUMBER> "Maximum number of events to be written to a file"
                )
                .required(false)
                .value_parser(value_parser!(usize)),
            )
            .arg(
                arg!(
                    --"trace-file" <FILE> "Path to debug trace file"
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

        if config.library.is_empty() {
            return Err(anyhow!("library must be specified"));
        }

        Ok(config)
    }

    pub fn coalesce_window_elapsed(&self, instant: &Instant) -> bool {
        self.coalesce_window
            .map(|window| instant.elapsed() > window)
            .unwrap_or(true)
    }

    pub fn should_rotate_after(&self, nevents: usize) -> bool {
        self.max_events
            .map(|max_events| nevents > max_events)
            .unwrap_or(false)
    }

    fn merge_config_file(&mut self, file: impl AsRef<Path>) -> Result<()> {
        let s = fs::read_to_string(file.as_ref())
            .with_context(|| format!("unable to read config file `{}`", file.as_ref().display()))?;
        let config = Table::from_str(&s).with_context(|| {
            format!("unable to parse config file `{}`", file.as_ref().display())
        })?;

        if let Some(value) = config.get("library") {
            self.library = pathbuf_array_from_value(value)?;
        }

        if let Some(value) = config.get("log_file") {
            self.log_file = pathbuf_from_value(value)?;
        }

        if let Some(value) = config.get("user") {
            self.user = Some(user_from_value(value)?);
        }

        if let Some(value) = config.get("format") {
            self.format = format_from_value(value)?;
        }

        if let Some(value) = config.get("coalesce_window") {
            self.coalesce_window = Some(duration_millis_from_value(value)?);
        }

        if let Some(value) = config.get("max_events") {
            self.max_events = Some(usize_from_value(value)?);
        }

        Ok(())
    }

    fn merge_arg_matches(&mut self, matches: &ArgMatches) -> Result<()> {
        if let Some(ValueSource::CommandLine) = matches.value_source("library") {
            self.library = matches.try_get_many("library")?.unwrap().cloned().collect();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("log-file") {
            self.log_file = matches.try_get_one::<PathBuf>("log-file")?.unwrap().clone();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("user") {
            self.user = matches.try_get_one::<(String, String)>("user")?.cloned();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("format") {
            self.format = *matches.try_get_one::<Format>("format")?.unwrap();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("coalesce-window") {
            self.coalesce_window = matches.try_get_one::<Duration>("coalesce-window")?.copied();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("max-events") {
            self.max_events = matches.try_get_one::<usize>("max-events")?.copied();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("trace-file") {
            self.trace_file = Some(
                matches
                    .try_get_one::<PathBuf>("trace-file")?
                    .unwrap()
                    .clone(),
            );
        }

        Ok(())
    }
}

fn pathbuf_array_from_value(value: &Value) -> Result<Vec<PathBuf>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("value must be array"))
        .and_then(|array| {
            array
                .iter()
                .map(|v| pathbuf_from_value(v))
                .collect::<Result<Vec<PathBuf>>>()
        })
}

fn pathbuf_from_value(value: &Value) -> Result<PathBuf> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .and_then(|v| Ok(PathBuf::from(v)))
}

fn user_from_value(value: &Value) -> Result<(String, String)> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .and_then(|v| parse_user(v))
        .and_then(|v| Ok(v))
}

fn format_from_value(value: &Value) -> Result<Format> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be format"))
        .and_then(|v| Format::from_str(v, false).map_err(|e| anyhow!("{}", e)))
}

fn duration_millis_from_value(value: &Value) -> Result<Duration> {
    value
        .as_integer()
        .ok_or_else(|| anyhow!("value must be duration in milliseconds"))
        .and_then(|v| Ok(Duration::from_millis(v as u64)))
}

fn usize_from_value(value: &Value) -> Result<usize> {
    value
        .as_integer()
        .ok_or_else(|| anyhow!("value must be integer"))
        .and_then(|v| Ok(v as usize))
}
