//! HTTP extension module

use core::fmt;
use core::net::IpAddr;

use crate::forwarded::{self, parse_forwarded_for, parse_forwarded_for_rev};
use crate::filter::Filter;

///Re-export of [http](https://crates.io/crates/http)
pub use http as http_ext;
use http_ext::header::FORWARDED;

const FALLBACK_STR: &str = "<non-utf8>";
///FMT formatter for header values
pub struct HeaderValueFmt<'a>(http_ext::header::GetAll<'a, http_ext::header::HeaderValue>);

impl fmt::Debug for HeaderValueFmt<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = fmt.debug_list();
        for header in self.0.iter() {
            match header.to_str() {
                Ok(header) => out.entry(&header),
                Err(_) => out.entry(header),
            };
        }

        out.finish()
    }
}

impl fmt::Display for HeaderValueFmt<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut headers = self.0.iter();
        if let Some(header) = headers.next() {
            match header.to_str() {
                Ok(header) => fmt.write_str(header)?,
                Err(_) => fmt.write_str(FALLBACK_STR)?,
            }

            for header in headers {
                fmt.write_str(" ,")?;
                match header.to_str() {
                    Ok(header) => fmt.write_str(header)?,
                    Err(_) => fmt.write_str(FALLBACK_STR)?,
                }
            }
        }

        Ok(())
    }
}

///`HeaderMap` extension trait
pub trait HeaderMapClientIp {
    ///Retrieves FMT formatter for header value matching provided `key`
    fn get_header_value_fmt(&self, key: impl http_ext::header::AsHeaderName) -> HeaderValueFmt<'_>;

    ///Extracts leftmost client IP with no assumption.
    ///
    ///Note that this is generally not reliable as your client might be behind proxy
    ///Prefer to use `extract_client_ip_with` by filtering out your proxies to find correct IP
    ///
    ///Returns `None` if IP is not provided or obfuscated
    fn extract_leftmost_forwarded_ip(&self) -> Option<IpAddr>;
    ///Extracts rightmost client IP with no assumption.
    ///
    ///Returns `None` if IP is not provided or obfuscated
    fn extract_rightmost_forwarded_ip(&self) -> Option<IpAddr>;
    ///Extracts client ip taking rightmost, after filtering out any IP matching `filter`
    ///
    ///Returns `None` if IP is not provided or obfuscated
    fn extract_filtered_forwarded_ip(&self, filter: &impl Filter) -> Option<IpAddr>;
}

impl HeaderMapClientIp for http_ext::HeaderMap {
    #[inline(always)]
    fn get_header_value_fmt(&self, key: impl http_ext::header::AsHeaderName) -> HeaderValueFmt<'_> {
        HeaderValueFmt(self.get_all(key))
    }

    #[inline(always)]
    fn extract_leftmost_forwarded_ip(&self) -> Option<IpAddr> {
        self.get_all(FORWARDED)
            .into_iter()
            .next()
            .and_then(|header| header.to_str().ok())
            .and_then(|header| parse_forwarded_for(header).next())
            .and_then(|node| match node {
                forwarded::ForwardedNode::Ip(ip) => Some(ip),
                _ => None
            })
    }

    #[inline(always)]
    fn extract_rightmost_forwarded_ip(&self) -> Option<IpAddr> {
        self.get_all(FORWARDED)
            .into_iter()
            .next_back()
            .and_then(|header| header.to_str().ok())
            .and_then(|header| parse_forwarded_for_rev(header).next())
            .and_then(|node| match node {
                forwarded::ForwardedNode::Ip(ip) => Some(ip),
                _ => None
            })
    }

    fn extract_filtered_forwarded_ip(&self, filter: &impl Filter) -> Option<IpAddr> {
        let forwarded = self.get_all(FORWARDED)
                            .into_iter()
                            .rev()
                            .filter_map(|header| header.to_str().ok()).flat_map(|header| parse_forwarded_for_rev(header));

        for node in forwarded {
            match node {
                forwarded::ForwardedNode::Ip(ip) => if filter.is_match(ip) {
                    continue
                } else {
                    return Some(ip)
                },
                _ => return None,
            }
        }

        None
    }
}
