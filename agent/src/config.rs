// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Result, anyhow};
use clap::{Parser, ValueEnum};
use figment::{
    Figment,
    providers::{Format as _, Serialized, Toml},
};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_with::{DurationMilliSeconds, serde_as};
use std::path::PathBuf;
use tokio::time::Duration;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Normal,
    Packed,
    Minimal,
}

const CONFIG: &str = "/etc/crypto-auditing/agent.conf";
const LOG: &str = "/var/log/crypto-auditing/audit.cborseq";

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Path to library that defines probes
    pub library: Vec<PathBuf>,

    /// Path to output log file
    pub log_file: PathBuf,

    /// User to run the program in USER:GROUP form
    #[serde(deserialize_with = "deserialize_user")]
    pub user: Option<(String, String)>,

    /// Output format to use
    pub format: Format,

    /// Event coalescing window
    #[serde_as(as = "Option<DurationMilliSeconds<u64>>")]
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

    /// Path to library that defines probes
    #[arg(long, value_name = "FILE")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    library: Vec<PathBuf>,

    /// Path to output log file
    #[arg(long, value_name = "FILE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    log_file: Option<PathBuf>,

    /// User to run the program in USER:GROUP form
    #[arg(long, value_name = "USER")]
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,

    /// Output format to use
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<Format>,

    /// Event coalescing window in milliseconds
    #[arg(long, value_name = "WINDOW")]
    #[serde(skip_serializing_if = "Option::is_none")]
    coalesce_window: Option<u64>,

    /// Maximum number of events to be written to a file
    #[arg(long, value_name = "NUMBER")]
    #[serde(skip_serializing_if = "Option::is_none")]
    max_events: Option<usize>,

    /// Path to debug trace file
    #[arg(long, value_name = "FILE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_file: Option<PathBuf>,
}

fn deserialize_user<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<(String, String)>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|arg| {
            arg.split_once(':')
                .map(|(user, group)| (user.to_string(), group.to_string()))
                .ok_or_else(|| de::Error::custom(format!("no delimiter in `{arg}`")))
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
        let config: Self = Figment::from(file)
            .merge(Serialized::defaults(&cli))
            .extract()?;

        if config.library.is_empty() {
            return Err(anyhow!("library must be specified"));
        }

        Ok(config)
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
        let cli = Cli::try_parse_from(["crau-agent"].iter().chain(args))?;
        Config::from_cli(cli)
    }

    fn parse(file: &NamedTempFile, args: &[&str]) -> Result<Config> {
        let path = file.path().to_str().unwrap();
        parse_args(&[&["--config", path], args].concat())
    }

    #[test]
    fn defaults() {
        let file = config_file("");
        let config = parse(&file, &["--library", "/usr/lib64/libssl.so.3"]).unwrap();
        assert_eq!(
            config.library,
            vec![PathBuf::from("/usr/lib64/libssl.so.3")]
        );
        assert_eq!(config.log_file, PathBuf::from(LOG));
        assert_eq!(config.user, None);
        assert_eq!(config.format, Format::Normal);
        assert_eq!(config.coalesce_window, None);
        assert_eq!(config.max_events, None);
        assert_eq!(config.trace_file, None);
    }

    #[test]
    fn library_required() {
        let file = config_file("");
        assert!(parse(&file, &[]).is_err());
    }

    #[test]
    fn from_config_file() {
        let file = config_file(
            r#"
library = ["/usr/lib64/libgnutls.so.30", "/usr/lib64/libssl.so.3"]
log_file = "/tmp/audit.cborseq"
user = "crypto-auditing:crypto-auditing"
format = "packed"
coalesce_window = 100
max_events = 1000000
trace_file = "/tmp/trace"
"#,
        );
        let config = parse(&file, &[]).unwrap();
        assert_eq!(
            config.library,
            vec![
                PathBuf::from("/usr/lib64/libgnutls.so.30"),
                PathBuf::from("/usr/lib64/libssl.so.3"),
            ]
        );
        assert_eq!(config.log_file, PathBuf::from("/tmp/audit.cborseq"));
        assert_eq!(
            config.user,
            Some(("crypto-auditing".to_string(), "crypto-auditing".to_string()))
        );
        assert_eq!(config.format, Format::Packed);
        assert_eq!(config.coalesce_window, Some(Duration::from_millis(100)));
        assert_eq!(config.max_events, Some(1000000));
        assert_eq!(config.trace_file, Some(PathBuf::from("/tmp/trace")));
    }

    #[test]
    fn from_command_line() {
        let file = config_file("");
        let config = parse(
            &file,
            &[
                "--library",
                "/usr/lib64/libgnutls.so.30",
                "--library",
                "/usr/lib64/libssl.so.3",
                "--log-file",
                "/tmp/audit.cborseq",
                "--user",
                "user:group",
                "--format",
                "minimal",
                "--coalesce-window",
                "200",
                "--max-events",
                "10",
                "--trace-file",
                "/tmp/trace",
            ],
        )
        .unwrap();
        assert_eq!(
            config.library,
            vec![
                PathBuf::from("/usr/lib64/libgnutls.so.30"),
                PathBuf::from("/usr/lib64/libssl.so.3"),
            ]
        );
        assert_eq!(config.log_file, PathBuf::from("/tmp/audit.cborseq"));
        assert_eq!(config.user, Some(("user".to_string(), "group".to_string())));
        assert_eq!(config.format, Format::Minimal);
        assert_eq!(config.coalesce_window, Some(Duration::from_millis(200)));
        assert_eq!(config.max_events, Some(10));
        assert_eq!(config.trace_file, Some(PathBuf::from("/tmp/trace")));
    }

    #[test]
    fn command_line_overrides_config_file() {
        let file = config_file(
            r#"
library = ["/usr/lib64/libgnutls.so.30", "/usr/lib64/libssl.so.3"]
log_file = "/tmp/audit.cborseq"
user = "crypto-auditing:crypto-auditing"
format = "packed"
coalesce_window = 100
max_events = 1000000
"#,
        );
        let config = parse(
            &file,
            &[
                "--library",
                "/usr/lib64/libnss3.so",
                "--user",
                "user:group",
                "--coalesce-window",
                "200",
            ],
        )
        .unwrap();
        // Overridden by the command-line; list values are replaced, not appended
        assert_eq!(config.library, vec![PathBuf::from("/usr/lib64/libnss3.so")]);
        assert_eq!(config.user, Some(("user".to_string(), "group".to_string())));
        assert_eq!(config.coalesce_window, Some(Duration::from_millis(200)));
        // Unspecified on the command-line; kept from the config file
        assert_eq!(config.log_file, PathBuf::from("/tmp/audit.cborseq"));
        assert_eq!(config.format, Format::Packed);
        assert_eq!(config.max_events, Some(1000000));
    }

    #[test]
    fn invalid_user() {
        let file = config_file("");
        assert!(parse(&file, &["--library", "/lib", "--user", "user"]).is_err());

        let file = config_file(
            r#"
library = ["/lib"]
user = "user"
"#,
        );
        assert!(parse(&file, &[]).is_err());
    }

    #[test]
    fn invalid_format() {
        let file = config_file("");
        assert!(parse(&file, &["--library", "/lib", "--format", "bogus"]).is_err());

        let file = config_file(
            r#"
library = ["/lib"]
format = "bogus"
"#,
        );
        assert!(parse(&file, &[]).is_err());
    }

    #[test]
    fn missing_config_file() {
        assert!(parse_args(&["--config", "/nonexistent/agent.conf", "--library", "/lib"]).is_err());
    }

    #[test]
    fn fixture_config_file() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/conf/agent.conf");
        let config = parse_args(&["--config", path, "--library", "/lib"]).unwrap();
        assert_eq!(config.log_file, PathBuf::from(LOG));
    }
}
