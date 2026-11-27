0.4.0
-----
- Flushed contexts at their own timeouts, and all remaining contexts on
  shutdown
- Added support for `release_context` event
- Switched to `figment` for merging options from command-line and
  configuration file


0.3.2
-----
- Added `repository` and `homepage` to the package manifest


0.3.1
-----
- Fixed typo


0.3.0
-----
- Initial release, combining the functionalities of the deprecated
  `crypto-auditing-event-broker` and `crypto-auditing-client` crates
  while reading the log file directly
