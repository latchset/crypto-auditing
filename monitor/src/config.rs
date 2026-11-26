// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2025 The crypto-auditing developers.

use anyhow::Result;
use clap::Parser;
use figment::{
    Figment,
    providers::{Format as _, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use serde_with::{DurationMilliSeconds, serde_as};
use std::path::PathBuf;
use std::time::Duration;

const CONFIG: &str = "/etc/crypto-auditing/monitor.conf";
const LOG: &str = "/var/log/crypto-auditing/audit.cborseq";

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Path to output log file
    pub log_file: PathBuf,

    /// Scope to match
    pub scope: Vec<String>,

    /// Event window
    #[serde_as(as = "DurationMilliSeconds<u64>")]
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

    /// Scope to restrict matches
    #[arg(long, value_name = "SCOPE")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scope: Vec<String>,

    /// Event window in milliseconds
    #[arg(long, value_name = "WINDOW")]
    #[serde(skip_serializing_if = "Option::is_none")]
    event_window: Option<u64>,
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
        Ok(Figment::from(file)
            .merge(Serialized::defaults(&cli))
            .extract()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn config_file(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    fn parse_args(args: &[&str]) -> Result<Config> {
        let cli = Cli::try_parse_from(["crau-monitor"].iter().chain(args))?;
        Config::from_cli(cli)
    }

    fn parse(file: &NamedTempFile, args: &[&str]) -> Result<Config> {
        let path = file.path().to_str().unwrap();
        parse_args(&[&["--config", path], args].concat())
    }

    #[test]
    fn defaults() {
        let file = config_file("");
        let config = parse(&file, &[]).unwrap();
        assert_eq!(config.log_file, PathBuf::from(LOG));
        assert!(config.scope.is_empty());
        assert_eq!(config.event_window, Duration::from_secs(3));
    }

    #[test]
    fn from_config_file() {
        let file = config_file(
            r#"
log_file = "/tmp/audit.cborseq"
scope = ["tls", "ssh"]
event_window = 5000
"#,
        );
        let config = parse(&file, &[]).unwrap();
        assert_eq!(config.log_file, PathBuf::from("/tmp/audit.cborseq"));
        assert_eq!(config.scope, vec!["tls".to_string(), "ssh".to_string()]);
        assert_eq!(config.event_window, Duration::from_millis(5000));
    }

    #[test]
    fn from_command_line() {
        let file = config_file("");
        let config = parse(
            &file,
            &[
                "--log-file",
                "/tmp/audit.cborseq",
                "--scope",
                "tls",
                "--scope",
                "ssh",
                "--event-window",
                "100",
            ],
        )
        .unwrap();
        assert_eq!(config.log_file, PathBuf::from("/tmp/audit.cborseq"));
        assert_eq!(config.scope, vec!["tls".to_string(), "ssh".to_string()]);
        assert_eq!(config.event_window, Duration::from_millis(100));
    }

    #[test]
    fn command_line_overrides_config_file() {
        let file = config_file(
            r#"
log_file = "/tmp/audit.cborseq"
scope = ["tls", "ssh"]
event_window = 5000
"#,
        );
        let config = parse(&file, &["--scope", "ike", "--event-window", "100"]).unwrap();
        // Overridden by the command-line; list values are replaced, not appended
        assert_eq!(config.scope, vec!["ike".to_string()]);
        assert_eq!(config.event_window, Duration::from_millis(100));
        // Unspecified on the command-line; kept from the config file
        assert_eq!(config.log_file, PathBuf::from("/tmp/audit.cborseq"));
    }

    #[test]
    fn invalid_event_window() {
        let file = config_file("");
        assert!(parse(&file, &["--event-window", "-1"]).is_err());

        let file = config_file(r#"event_window = "soon""#);
        assert!(parse(&file, &[]).is_err());
    }

    #[test]
    fn missing_config_file() {
        assert!(parse_args(&["--config", "/nonexistent/monitor.conf"]).is_err());
    }

    #[test]
    fn dist_config_file() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../dist/conf/monitor.conf");
        let config = parse_args(&["--config", path]).unwrap();
        assert_eq!(config.log_file, PathBuf::from(LOG));
        assert_eq!(config.event_window, Duration::from_secs(3));
    }
}
