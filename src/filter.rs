//!Filtering of IP addresses

use core::fmt;
use core::net::{IpAddr, SocketAddr};

///Interface to define function that filters out IP address
///
///When match is found, IP address is skipped from being selected as client's IP (e.g. it is load balancer IP)
pub trait Filter: Sized {
    ///Returns `true` if `ip` matches
    fn is_match(&self, ip: IpAddr) -> bool;
    #[inline(always)]
    ///Combines `self` with `right` filter in `OR` operation
    fn or<F2: Filter>(self, right: F2) -> Or<Self, F2> {
        or(self, right)
    }
}

impl Filter for IpAddr {
    #[inline(always)]
    fn is_match(&self, ip: IpAddr) -> bool {
        *self == ip
    }
}

impl Filter for SocketAddr {
    #[inline(always)]
    fn is_match(&self, ip: IpAddr) -> bool {
        self.ip() == ip
    }
}

///Combination of filters with `OR` condition
pub struct Or<F1, F2> {
    left: F1,
    right: F2,
}

impl<F1: Filter, F2: Filter> Filter for Or<F1, F2> {
    #[inline(always)]
    fn is_match(&self, ip: IpAddr) -> bool {
        self.left.is_match(ip) || self.right.is_match(ip)
    }
}

#[derive(Debug, PartialEq, Eq)]
//Possible errors parsing CIDR
enum ParseError<'a> {
    //Error parsing CIDR expression
    ParseError(ip_cidr::ParseError<'a>),
    //CIDR expression is valid, but its prefix does not fit type of IP address
    InvalidPrefix
}

#[repr(transparent)]
#[derive(PartialEq, Eq)]
///Error which is returned when parsing CIDR's textual representation
pub struct CidrParseError<'a>(ParseError<'a>);

impl fmt::Debug for CidrParseError<'_> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl fmt::Display for CidrParseError<'_> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ParseError::InvalidPrefix => fmt.write_str("Invalid CIDR prefix"),
            ParseError::ParseError(error) => fmt::Display::fmt(error, fmt),
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
///CIDR filter
pub struct Cidr(ip_cidr::Cidr);

impl Cidr {
    #[inline]
    ///Creates new instance from textual representation
    pub const fn from_text(text: &str) -> Result<Self, CidrParseError<'_>> {
        match ip_cidr::parse_cidr(text) {
            Ok(Some(inner)) => Ok(Self(inner)),
            Ok(None) => Err(CidrParseError(ParseError::InvalidPrefix)),
            Err(error) => Err(CidrParseError(ParseError::ParseError(error))),
        }
    }

    #[inline]
    ///Creates new instance from IP and prefix, returning error if `prefix` is invalid
    pub const fn new(ip: IpAddr, prefix: u8) -> Result<Self, CidrParseError<'static>> {
        match ip_cidr::Cidr::new(ip, prefix) {
            Some(cidr) => Ok(Self(cidr)),
            None => Err(CidrParseError(ParseError::InvalidPrefix)),
        }
    }
}

impl Filter for Cidr {
    #[inline(always)]
    fn is_match(&self, ip: IpAddr) -> bool {
        self.0.contains(ip)
    }
}

impl fmt::Debug for Cidr {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl fmt::Display for Cidr {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

#[inline]
///Creates new `OR` filter out of two filters
pub const fn or<F1, F2>(left: F1, right: F2) -> Or<F1, F2> {
    Or {
        left,
        right
    }
}

