//! Utilities to determine HTTP client's IP

#![no_std]
#![warn(missing_docs)]
#![allow(clippy::style)]

pub mod forwarded;
pub mod filter;
#[cfg(feature = "http")]
pub mod http;
