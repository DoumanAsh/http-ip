//! Utilities to determine HTTP client's IP
//!
//! ## Features
//!
//! - `http` - Enables filter implementation using http's header map
//! - `axum08` - Enables `axum` extractor implementation for `0.8.x`.

#![no_std]
#![warn(missing_docs)]
#![allow(clippy::style)]

pub mod forwarded;
pub mod filter;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "axum08")]
pub mod axum08;
