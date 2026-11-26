// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::Result;
use clap::Parser;
use figment::{
    Figment,
    providers::{Format as _, Serialized, Toml},
};
use jiff::Zoned;
use parse_datetime::parse_datetime;
use serde::{Deserialize, Deserializer, Serialize, de};
use std::path::PathBuf;

const CONFIG: &str = "/etc/crypto-auditing/query.conf";
const LOG: &str = "/var/log/crypto-auditing/audit.cborseq";

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Path to output log file
    pub log_file: PathBuf,
    /// System boot time as seconds from Unix epoch
    #[serde(skip)]
    pub boot_time: Option<u64>,
    /// The earliest timestamp to match events
    #[serde(deserialize_with = "deserialize_zoned")]
    pub since: Option<Zoned>,
    /// The latest timestamp to match events
    #[serde(deserialize_with = "deserialize_zoned")]
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

// Command-line options, overriding the ones in the configuration file
// with the same name.  Unspecified options are not serialized so they
// do not override anything.
#[derive(Parser, Serialize)]
#[command(author, version, about)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    #[serde(skip)]
    config: Option<PathBuf>,

    /// Path to output log file
    #[arg(long, value_name = "FILE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    log_file: Option<PathBuf>,

    /// System boot time as seconds from Unix epoch
    #[arg(long, value_name = "SECONDS")]
    #[serde(skip)]
    boot_time: Option<u64>,

    /// The earliest timestamp to match events
    #[arg(long, value_name = "TIME")]
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<String>,

    /// The latest timestamp to match events
    #[arg(long, value_name = "TIME")]
    #[serde(skip_serializing_if = "Option::is_none")]
    until: Option<String>,
}

fn deserialize_zoned<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zoned>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|arg| {
            parse_datetime(&arg)
                .map_err(|e| de::Error::custom(format!("invalid timestamp `{arg}`: {e}")))
        })
        .transpose()
}

impl Config {
    pub fn new() -> Result<Self> {
        Self::from_cli(Cli::parse())
    }

    fn from_cli(cli: Cli) -> Result<Self> {
        let file = match &cli.config {
            Some(path) => Toml::file_exact(path),
            None => Toml::file(CONFIG),
        };
        let mut config: Self = Figment::from(file)
            .merge(Serialized::defaults(&cli))
            .extract()?;

        // The boot time changes after each reboot, so it is only
        // accepted from the command-line
        config.boot_time = cli.boot_time;

        Ok(config)
    }
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
        let cli = Cli::try_parse_from(["crau-query"].iter().chain(args))?;
        Config::from_cli(cli)
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
