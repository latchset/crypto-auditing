0.4.0
-----
- Added `--ringbuf-size` option and `ringbuf_size` configuration to
  specify the size of the BPF ring buffer
- Bumped default BPF ring buffer size from 4 KB to 256 KB
- Added support for `release_context` probe
- Prohibited all-zero library context, so events with a `NULL` context
  are ignored
- Stopped obfuscating context IDs
- Switched to `bpf_copy_from_user*` from `bpf_probe_read_user*`, so
  memory in unmapped pages can be read
- Switched to `figment` for merging options from command-line and
  configuration file
- Switched to `AsyncFd::register_with_interest` to address
  RUSTSEC-2026-0386, and updated `tokio` dependency to `1.53.3`
- Updated `sysinfo` dependency to `0.39`


0.3.2
-----
- Moved test fixtures into the crate
- Added `repository` and `homepage` to the package manifest


0.3.1
-----
- Added executable filename of the application to the logs
- Added system boot time to the primary log as metadata
- Dropped Linux capabilities other than `CAP_BPF` and `CAP_PERFMON`
  after startup
- Worked around `bpf_stream_vprintk` compatibility issue with libbpf
  1.6
- Removed unused direct dependency on `nix`


0.3.0
-----
- Renamed the executable from `crypto-auditing-agent` to `crau-agent`,
  as well as the systemd unit
- Renamed `ContextID` to `ContextId`
- Suppressed compilation warning


0.2.4
-----
- Switched to using synchronous version of BPF ring buffer
- Spawned event sender in a worker thread
- Used unbounded channel for communicating with internal threads
- Updated edition to Rust 2024


0.2.3
-----
- Updated `libbpf-rs` and `libbpf-cargo` dependencies to `0.24`


0.2.2
-----
- Added support for composite events


0.2.1
-----
- Added `README.md`
- Clarified copyright and licensing


0.2.0
-----
- Initial release
