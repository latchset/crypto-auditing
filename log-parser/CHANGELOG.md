0.4.0
-----
- Used the built-in event schema for reconstructing context hierarchy
- Added support for `release_context` event
- Added `--event-window` option and `event_window` configuration to
  periodically flush contexts based on the log timestamps
- Stopped reading the log once past the `--until` range
- Buffered reads from the log file
- Deferred pager setup right before output
- Enabled `tracing-subscriber` with env-filter
- Switched to `figment` for merging options from command-line and
  configuration file


0.3.2
-----
- Moved test fixtures into the crate
- Added `repository` and `homepage` to the package manifest


0.3.1
-----
- Added `--since` and `--until` options to filter events by time range
- Added `--boot-time` option for reproducible output
- Added executable filename of the application to the output
- Added JSON Schema for the output


0.3.0
-----
- Renamed the executable from `crypto-auditing-log-parser` to
  `crau-query`
- Added support for configuration file
- Printed output through pager if needed
- Included resolved `SystemTime` in the output, instead of durations
  since system boot
- Added missing feature flag for `clap`


0.2.4
-----
- Updated edition to Rust 2024


0.2.1
-----
- Added `README.md`


0.2.0
-----
- Initial release
