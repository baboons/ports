//! Find the HTTP servers running on this machine, and bind them to local
//! domains.
//!
//! Split into a library so the proxy can be driven end-to-end from
//! `tests/`, which is where the behaviours that matter live: a WebSocket
//! upgrade completing, a stream arriving unbuffered. Both are things a naive
//! proxy breaks silently.

pub mod cache;
pub mod cli;
pub mod config;
pub mod proxy;
pub mod scan;
pub mod types;
