//! Axum 0.8 extension module
//!
//! Provides [ClientIp](struct.ClientIp.html) to extract client's ip using filters

use core::{fmt, marker};
use core::net::{IpAddr, SocketAddr};

pub use axum08::*;
use axum08::extract::FromRequestParts;

use crate::filter::Filter;
use crate::http::HeaderMapClientIp;

#[repr(transparent)]
#[derive(Copy, Clone)]
///ClientIp extractor
///
///Provided `F` parameter can be used to customize filter selection. Use `nil` type to only extract rightmost IP.
///
///Defaults to `axum::extract::ConnectInfo` if corresponding header cannot provide ip
///
///## Usage
///
///```rust
///use std::net::{IpAddr, Ipv4Addr};
///
///use http_ip::axum08::{
///    routing::get,
///    handler::Handler,
///    Router,
///};
///use http_ip::axum08::ClientIp;
///
///#[derive(Clone)]
///struct MyState {
///    local_ip: IpAddr,
///}
///
/////Alternatively use derive macro
///impl http_ip::axum08::extract::FromRef<MyState> for IpAddr {
///    #[inline(always)]
///    fn from_ref(state: &MyState) -> Self {
///        state.local_ip
///    }
///}
///
///async fn create_user(client_ip: ClientIp<IpAddr>) {
///    // Do whatever you want with client_ip now
///}
///
///let state = MyState {
///    local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
///};
///let app: Router<MyState> = Router::new().route("/users", get(create_user)).with_state(state);
///```
pub struct ClientIp<F: Filter> {
    ///Underlying IP addr if available
    pub inner: Option<IpAddr>,
    _filter: marker::PhantomData<F>
}

impl<F: Filter> ClientIp<F> {
    #[inline(always)]
    fn new(inner: Option<IpAddr>) -> Self {
        Self {
            inner,
            _filter: marker::PhantomData,
        }
    }

    #[inline(always)]
    ///Access underlying value
    pub fn into_inner(self) -> Option<IpAddr> {
        self.inner
    }
}

impl<F: Filter> fmt::Debug for ClientIp<F> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, fmt)
    }
}

impl<S: Send + Sync, F: Send + Sync + Filter + Clone + extract::FromRef<S>> FromRequestParts<S> for ClientIp<F> {
    type Rejection = core::convert::Infallible;

    async fn from_request_parts(parts: &mut http::request::Parts, state: &S) -> Result<Self, Self::Rejection> {
        let filter: F = extract::FromRef::from_ref(state);
        let ip = if let Some(ip) = parts.headers.extract_filtered_forwarded_ip(&filter) {
            Some(ip)
        } else if let Ok(addr) = extract::ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await {
            Some(addr.ip())
        } else {
            None
        };
        Ok(ClientIp::new(ip))
    }
}
