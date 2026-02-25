// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result, anyhow};
use clap::{ArgMatches, arg, command, parser::ValueSource, value_parser};
use jiff::Zoned;
use parse_datetime::parse_datetime;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toml::{Table, Value};

const CONFIG: &str = "/etc/crypto-auditing/query.conf";
const LOG: &str = "/var/log/crypto-auditing/audit.cborseq";

#[derive(Debug)]
pub struct Config {
    /// Path to output log file
    pub log_file: PathBuf,
    /// System boot time as seconds from Unix epoch
    pub boot_time: Option<u64>,
    /// The earliest timestamp to match events
    pub since: Option<Zoned>,
    /// The latest timestamp to match events
    pub until: Option<Zoned>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_file: PathBuf::from(LOG),
            boot_time: None,
            since: None,
            until: None,
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
                    --"boot-time" <SECONDS> "System boot time as seconds from Unix epoch"
                )
                .required(false)
                .value_parser(value_parser!(u64)),
            )
            .arg(
                arg!(
                    --since <TIME> "The earliest timestamp to match events"
                )
                .required(false)
                .value_parser(parse_zoned),
            )
            .arg(
                arg!(
                    --until <TIME> "The latest timestamp to match events"
                )
                .required(false)
                .value_parser(parse_zoned),
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

        if let Some(value) = config.get("since") {
            self.since = Some(zoned_from_value(value)?);
        }

        if let Some(value) = config.get("until") {
            self.until = Some(zoned_from_value(value)?);
        }

        Ok(())
    }

    fn merge_arg_matches(&mut self, matches: &ArgMatches) -> Result<()> {
        if let Some(ValueSource::CommandLine) = matches.value_source("log-file") {
            self.log_file = matches.try_get_one::<PathBuf>("log-file")?.unwrap().clone();
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("boot-time") {
            self.boot_time = Some(matches.try_get_one::<u64>("boot-time")?.unwrap().clone());
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("since") {
            self.since = Some(matches.try_get_one::<Zoned>("since")?.unwrap().clone());
        }

        if let Some(ValueSource::CommandLine) = matches.value_source("until") {
            self.until = Some(matches.try_get_one::<Zoned>("until")?.unwrap().clone());
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

fn parse_zoned(arg: &str) -> Result<Zoned> {
    Ok(parse_datetime(arg)?)
}

fn zoned_from_value(value: &Value) -> Result<Zoned> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .map(parse_zoned)?
}
