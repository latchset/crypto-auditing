// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result, anyhow};
use clap::{ArgMatches, Command, arg, command, parser::ValueSource, value_parser};
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

fn command() -> Command {
    command!()
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
}

impl Config {
    pub fn new() -> Result<Self> {
        Self::from_matches(&command().get_matches())
    }

    fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let mut config = Config::default();

        if let Some(config_file) = matches.get_one::<PathBuf>("config") {
            config.merge_config_file(config_file)?;
        } else if Path::new(CONFIG).exists() {
            config.merge_config_file(CONFIG)?;
        }

        config.merge_arg_matches(matches)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn config_file(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    fn parse_args(args: &[&str]) -> Result<Config> {
        let matches = command().try_get_matches_from(["crau-query"].iter().chain(args))?;
        Config::from_matches(&matches)
    }

    fn parse(file: &NamedTempFile, args: &[&str]) -> Result<Config> {
        let path = file.path().to_str().unwrap();
        parse_args(&[&["--config", path], args].concat())
    }

    fn timestamp(zoned: &Option<Zoned>) -> Option<Timestamp> {
        zoned.as_ref().map(Zoned::timestamp)
    }

    #[test]
    fn defaults() {
        let file = config_file("");
        let config = parse(&file, &[]).unwrap();
        assert_eq!(config.log_file, PathBuf::from(LOG));
        assert_eq!(config.boot_time, None);
        assert!(config.since.is_none());
        assert!(config.until.is_none());
    }

    #[test]
    fn from_config_file() {
        let file = config_file(
            r#"
log_file = "/tmp/audit.cborseq"
since = "2025-01-01T00:00:00Z"
until = "2025-01-02T00:00:00Z"
"#,
        );
        let config = parse(&file, &[]).unwrap();
        assert_eq!(config.log_file, PathBuf::from("/tmp/audit.cborseq"));
        assert_eq!(
            timestamp(&config.since),
            Some("2025-01-01T00:00:00Z".parse().unwrap())
        );
        assert_eq!(
            timestamp(&config.until),
            Some("2025-01-02T00:00:00Z".parse().unwrap())
        );
    }

    #[test]
    fn from_command_line() {
        let file = config_file("");
        let config = parse(
            &file,
            &[
                "--log-file",
                "/tmp/audit.cborseq",
                "--boot-time",
                "1700000000",
                "--since",
                "2025-01-01T00:00:00Z",
                "--until",
                "2025-01-02T00:00:00Z",
            ],
        )
        .unwrap();
        assert_eq!(config.log_file, PathBuf::from("/tmp/audit.cborseq"));
        assert_eq!(config.boot_time, Some(1700000000));
        assert_eq!(
            timestamp(&config.since),
            Some("2025-01-01T00:00:00Z".parse().unwrap())
        );
        assert_eq!(
            timestamp(&config.until),
            Some("2025-01-02T00:00:00Z".parse().unwrap())
        );
    }

    #[test]
    fn command_line_overrides_config_file() {
        let file = config_file(
            r#"
log_file = "/tmp/audit.cborseq"
since = "2025-01-01T00:00:00Z"
"#,
        );
        let config = parse(&file, &["--since", "2025-06-01T00:00:00Z"]).unwrap();
        // Overridden by the command-line
        assert_eq!(
            timestamp(&config.since),
            Some("2025-06-01T00:00:00Z".parse().unwrap())
        );
        // Unspecified on the command-line; kept from the config file
        assert_eq!(config.log_file, PathBuf::from("/tmp/audit.cborseq"));
        assert!(config.until.is_none());
    }

    #[test]
    fn boot_time_not_from_config_file() {
        // The boot time changes after each reboot, so it is only
        // accepted from the command-line
        let file = config_file("boot_time = 1700000000");
        let config = parse(&file, &[]).unwrap();
        assert_eq!(config.boot_time, None);
    }

    #[test]
    fn invalid_timestamp() {
        let file = config_file("");
        assert!(parse(&file, &["--since", "not a timestamp"]).is_err());

        let file = config_file(r#"until = "not a timestamp""#);
        assert!(parse(&file, &[]).is_err());
    }

    #[test]
    fn missing_config_file() {
        assert!(parse_args(&["--config", "/nonexistent/query.conf"]).is_err());
    }

    #[test]
    fn fixture_config_file() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/conf/query.conf");
        let config = parse_args(&["--config", path]).unwrap();
        assert_eq!(config.log_file, PathBuf::from(LOG));
    }
}
