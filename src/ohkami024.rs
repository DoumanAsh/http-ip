//! Ohkami 0.24 integration
use core::{fmt, marker};
use core::net::IpAddr;

use crate::find_next_ip_after_filter;
use crate::filter::Filter;
use crate::forwarded::parse_forwarded_for_rev;
use ohkami024::{FangProc, Fang};
use ohkami024::{FromRequest, Request, Response};

#[repr(transparent)]
#[derive(Copy, Clone)]
///ClientIp extractor
///
///Provided `F` parameter can be used to customize filter selection. Use `nil` type to only extract rightmost IP.
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

impl<'req, F: Send + Sync + Filter + 'static> FromRequest<'req> for ClientIp<F> {
    ///This extractor will not fail
    type Error = core::convert::Infallible;
    ///Extracts `Forwarded` header, or do nothing if not available
    ///
    ///If no IP can be determined due to filter or obfuscation, sets `ClientIp::inner` to `None`
    fn from_request(req: &'req Request) -> Option<Result<Self, Self::Error>> {
        let filter = req.context.get::<F>()?;
        //This library is a mess of undocumented functionality, but this method is basically shortcut to getting Forwarded with both possible cases
        if let Some(ip) = req.headers.forwarded().and_then(|value| find_next_ip_after_filter(parse_forwarded_for_rev(value), filter)) {
            Some(Ok(ClientIp::new(Some(ip))))
        } else {
            //do not return None as it will cause 404 by default, it is best to have your control over this behaviour
            Some(Ok(ClientIp::new(None)))
        }
    }
}

#[derive(Clone)]
///Client IP modification middleware implementing [Fang](https://docs.rs/ohkami/latest/ohkami/fang/trait.Fang.html)
pub struct ClientIpMiddleware<F> {
    filter: F,
}

impl<F: Filter + Clone + 'static> ClientIpMiddleware<F> {
    #[inline(always)]
    ///Creates new instance
    pub const fn new(filter: F) -> Self {
        Self {
            filter
        }
    }
}

impl<F: Filter + Clone + 'static, I: FangProc> Fang<I> for ClientIpMiddleware<F> {
    type Proc = ClientIpMiddlewareProc<I, F>;
    #[inline(always)]
    fn chain(&self, inner: I) -> Self::Proc {
        ClientIpMiddlewareProc {
            inner,
            filter: self.filter.clone(),
        }
    }
}

///Tracing middleware implementing [FangProc](https://docs.rs/ohkami/latest/ohkami/fang/trait.FancProc.html)
pub struct ClientIpMiddlewareProc<I, F> {
    inner: I,
    filter: F,
}

impl<I: FangProc, F: Filter + 'static> FangProc for ClientIpMiddlewareProc<I, F> {
    #[inline(always)]
    fn bite<'b>(&'b self, req: &'b mut Request) -> impl Future<Output = Response> {
        if req.ip.is_unspecified() {
            //Assume ip is set to correct one if it is not default, so we try to look up Forwarded header only if user cannot know IP yet
            if let Some(ip) = req.headers.forwarded().and_then(|value| find_next_ip_after_filter(parse_forwarded_for_rev(value), &self.filter)) {
                req.ip = ip;
            }
        }

        self.inner.bite(req)
    }
}
