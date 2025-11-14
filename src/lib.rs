//! Utilities to determine HTTP client's IP
//!
//! ## Features
//!
//! - `http` - Enables filter implementation using http's header map;
//! - `axum08` - Enables `axum` extractor implementation for `0.8.x`;
//! - `tonic014` - Enables `tonic` extension implementation for `0.14.x`.

//#![no_std]
#![warn(missing_docs)]
#![allow(clippy::style)]

#[cfg(any(feature = "tonic014", feature = "http"))]
mod shared;
pub mod forwarded;
pub mod filter;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "axum08")]
pub mod axum08;
#[cfg(feature = "tonic014")]
pub mod tonic014;
