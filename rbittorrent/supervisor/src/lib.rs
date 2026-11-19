//! Building blocks of `rbittorrent-supervisor`, the PID-1 supervisor of the
//! rBittorrent Home Assistant app (see `main.rs` for the startup order).
//!
//! The crate is split into a library and a thin binary so the integration
//! tests in `tests/` can drive the real components (e.g. the Ingress proxy
//! against a mock rtbit).

pub mod apparmor;
pub mod benchmark;
pub mod bencode;
pub mod cidr;
pub mod config;
pub mod exec;
pub mod firewall;
pub mod ha_supervisor;
pub mod host;
pub mod ingress;
pub mod landlock;
pub mod migration;
pub mod natpmp;
pub mod process;
pub mod rtbit_api;
pub mod wireguard;

/// Plain, timestamped logs on stdout (the Home Assistant log tab).
pub fn init_logging(level: config::LogLevel) {
    tracing_subscriber::fmt()
        .with_max_level(level.as_tracing())
        .with_target(false)
        .with_writer(std::io::stdout)
        .init();
}

/// The same logs on stderr, for the Ingress proxy, whose stdout carries
/// requests to the supervisor (its stderr is inherited, so the lines still
/// reach the log tab).
pub fn init_logging_stderr(level: config::LogLevel) {
    tracing_subscriber::fmt()
        .with_max_level(level.as_tracing())
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
