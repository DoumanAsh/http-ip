//! Tonic 0.14 extension module

use core::fmt;
use core::net::IpAddr;

pub use tonic014 as tonic;
pub use tonic::metadata::MetadataMap;

use crate::forwarded::{self, parse_forwarded_for, parse_forwarded_for_rev, parse_x_forwarded_for, parse_x_forwarded_for_rev};
use crate::filter::Filter;
use crate::shared::FALLBACK_STR;

const FORWARDED: &str = "forwarded";
const X_FORWARDED_FOR: &str = "x-forwarded-for";

///FMT formatter for header values
pub struct MetadataValueFmt<'a>(tonic::metadata::GetAll<'a, tonic::metadata::Ascii>);

impl fmt::Debug for MetadataValueFmt<'_> {
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

impl fmt::Display for MetadataValueFmt<'_> {
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

///`MetadataMap` extension trait
pub trait MetadataMapClientIp {
    ///Retrieves FMT formatter for header value matching provided `key`
    fn get_header_value_fmt(&self, key: &str) -> MetadataValueFmt<'_>;
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

impl MetadataMapClientIp for MetadataMap {
    #[inline(always)]
    fn get_header_value_fmt(&self, key: &str) -> MetadataValueFmt<'_> {
        MetadataValueFmt(self.get_all(key))
    }

    #[inline(always)]
    fn extract_leftmost_forwarded_ip(&self) -> Option<IpAddr> {
        crate::shared::impl_extract_leftmost_forwarded_ip!(self)
    }

    #[inline(always)]
    fn extract_rightmost_forwarded_ip(&self) -> Option<IpAddr> {
        crate::shared::impl_extract_rightmost_forwarded_ip!(self)
    }

    fn extract_filtered_forwarded_ip(&self, filter: &impl Filter) -> Option<IpAddr> {
        crate::shared::impl_extract_filtered_forwarded_ip!(self, filter)
    }
}
