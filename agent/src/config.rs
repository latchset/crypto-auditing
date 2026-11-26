// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use anyhow::{Context as _, Result, anyhow};
use clap::{
    ArgAction, ArgMatches, Command, ValueEnum, arg, command, parser::ValueSource, value_parser,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tokio::time::Duration;
use toml::{Table, Value};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Format {
    Normal,
    Packed,
    Minimal,
}

const CONFIG: &str = "/etc/crypto-auditing/agent.conf";
const LOG: &str = "/var/log/crypto-auditing/audit.cborseq";

#[derive(Debug, Clone)]
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

        if config.library.is_empty() {
            return Err(anyhow!("library must be specified"));
        }

        Ok(config)
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
                .map(pathbuf_from_value)
                .collect::<Result<Vec<PathBuf>>>()
        })
}

fn pathbuf_from_value(value: &Value) -> Result<PathBuf> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .map(PathBuf::from)
}

fn user_from_value(value: &Value) -> Result<(String, String)> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("value must be string"))
        .map(parse_user)?
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
        .map(|v| Duration::from_millis(v as u64))
}

fn usize_from_value(value: &Value) -> Result<usize> {
    value
        .as_integer()
        .ok_or_else(|| anyhow!("value must be integer"))
        .map(|v| v as usize)
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
        let matches = command().try_get_matches_from(["crau-agent"].iter().chain(args))?;
        Config::from_matches(&matches)
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
