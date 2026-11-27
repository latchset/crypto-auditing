0.4.0
-----
- Removed `event_broker` module, along with the deprecated
  `crypto-auditing-client` and `crypto-auditing-event-broker` crates
- Added `schema` module for parsing event schema, with `Schema::builtin`
  and `Schema::is_parent`
- Added `ContextTracker::set_schema` to reconstruct context hierarchy
  from the event schema, when `new_context` is called with the same
  context and parent
- Added support for `release_context` event, which retires the given
  context ID from `ContextTracker` lookup table
- Split `ContextTracker::flush` into `flush` and `flush_all`
- Added `ContextTracker::latest`, `ContextTracker::set_range` and
  `ContextTracker::is_range_exhausted`
- Added `ContextTracker::root_context_count` and
  `ContextTracker::context_count`, and report usage statistics around
  flush through `tracing`
- Changed `ContextTracker` to create a context only after its `name`
  attribute is known
- Changed `ContextTracker` to use weak references to track contexts,
  preventing leaks
- Improved `ContextTracker::flush` to prune lookup tables in linear time
- Swapped the order of PID/TGID and context when formatting `ContextId`
- Added `EventGroupBuilder`, `Context::name`, `Default` impl for
  `Context`, and `EventData::{word,string,blob}` accessors
- Added `trace` module for synthesizing CBOR sequence logs for testing,
  behind the `encode` feature


0.3.2
-----
- Added `repository` and `homepage` to the package manifest


0.3.1
-----
- Moved `ContextTracker` to the top-level of the crate
- Fixed negated expiration condition in `ContextTracker`
- Allowed sibling contexts to reuse the same context ID in
  `ContextTracker`
- Added executable filename of the application to the logs
- Added system boot time to the primary log as metadata
- Fixed typo in `types` documentation


0.3.0
-----
- Added `ContextTracker`, consolidating the context tracking logic
  previously duplicated in `crau-query` and `crau-monitor`
- Moved `Context` struct into the library
- Renamed `ContextID` to `ContextId`
- Included resolved `SystemTime` in formatted logs, instead of durations
  since system boot
- Switched from `Instant` to `SystemTime` for tracking time
- Fixed typing on 32-bit architectures


0.2.4
-----
- Updated `bindgen` dependency to `0.72`
- Avoided deprecated `CargoCallbacks` constant in build script
- Updated edition to Rust 2024


0.2.3
-----
- Fixed `types` to work on 32-bit platforms


0.2.2
-----
- Silenced clippy warnings


0.2.1
-----
- Added `README.md`
- Clarified copyright and licensing


0.2.0
-----
- Initial release
