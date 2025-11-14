//! `Forwarded` header module

use core::{marker, fmt};
use core::net::IpAddr;

//Forwarded syntax
//Syntax is: <entry 1>, <entry N>
//Entry is: <key1>=<value1>;<keyN>=<valueN>
const FORWARDED_SEP: char = ',';
const ENTRY_SEP: char = ';';
const PAIR_SEP: char = '=';

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
///Parsed node of the Forwarded header
///
///See details <https://datatracker.ietf.org/doc/html/rfc7239#section-4>
pub enum ForwardedNode<'a> {
    ///Proxy specified real IP address
    Ip(IpAddr),
    ///Proxy decided to obscure
    Name(&'a str),
    ///Proxy indicates it cannot know IP
    Unknown,
}

impl<'a> ForwardedNode<'a> {
    #[inline(always)]
    fn parse_name(name: &'a str) -> Self {
        if let Ok(name) = name.parse() {
            return Self::Ip(name);
        } else {
            return Self::Name(name)
        }
    }

    #[inline(always)]
    ///Returns `ip` value if node is valid IP address
    pub const fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            _ => None
        }
    }

    #[inline]
    ///Parses X-Forwarded-For's `Node` identifier
    pub fn parse_x_node(mut node: &'a str) -> Self {
        node = node.trim();
        match node.parse() {
            Ok(ip) => ForwardedNode::Ip(ip),
            Err(_) => ForwardedNode::Name(node)
        }
    }

    ///Parses `Node` identifier
    pub fn parse_node(mut node: &'a str) -> Self {
        node = node.trim_matches('"');
        if node.eq_ignore_ascii_case("unknown") {
            return Self::Unknown;
        }

        if let Some(mut ipv6) = node.strip_prefix('[') {
            if let Some(end_addr_idx) = ipv6.find(']') {
                ipv6 = &ipv6[..end_addr_idx];
                return Self::parse_name(ipv6);
            } else {
                return Self::Name(ipv6);
            }
        }

        let mut node = node.rsplit(':');
        let port_or_ip = node.next().unwrap();
        let ip = if let Some(ip) = node.next() {
            ip
        } else {
            port_or_ip
        };

        ForwardedNode::parse_name(ip)
    }
}

impl fmt::Display for ForwardedNode<'_> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => fmt::Display::fmt(&ip, fmt),
            Self::Name(ip) => fmt.write_str(&ip),
            Self::Unknown => fmt.write_str("-"),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
///`Forwarded` entry value
pub enum ForwardedValue<'a> {
    ///Identifies node that passed request to the proxy
    ///
    ///This potentially can be the same as `For`
    By(ForwardedNode<'a>),
    ///Contains client's IP information
    ///
    ///This is normally what you're looking for when you need to identify client's original IP
    For(ForwardedNode<'a>),
    ///Original value of `Host` header
    Host(&'a str),
    ///String with protocol name
    ///
    ///<https://datatracker.ietf.org/doc/html/rfc7239#section-5.4>
    Protocol(&'a str)
}

///Iterator of `Forwarded` entry's components
pub struct ForwardedEntryIter<'a> {
    components: core::str::Split<'a, char>,
}

impl<'a> ForwardedEntryIter<'a> {
    ///Parses single entry within `Forwarded` header
    ///
    ///It performs no error checking, ignoring invalid values, as it assumes you parse valid `Forwarded` header
    ///
    ///Values within entry is separated by `;`
    ///
    ///This iterator returns [ForwardedValue](enum.ForwardedValue.html)
    pub fn parse_entry(value: &'a str) -> Self {
        Self {
            components: value.split(ENTRY_SEP)
        }
    }
}

impl<'a> Iterator for ForwardedEntryIter<'a> {
    type Item = ForwardedValue<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(value) = self.components.next() {
            let mut pairs = value.splitn(2, PAIR_SEP);
            let key = pairs.next().unwrap();
            if key.eq_ignore_ascii_case("for") {
                if let Some(node) = pairs.next() {
                    return Some(ForwardedValue::For(ForwardedNode::parse_node(node)))
                }
            } else if key.eq_ignore_ascii_case("by") {
                if let Some(node) = pairs.next() {
                    return Some(ForwardedValue::By(ForwardedNode::parse_node(node)))
                }
            } else if key.eq_ignore_ascii_case("proto") {
                if let Some(proto) = pairs.next() {
                    return Some(ForwardedValue::Protocol(proto))
                }
            } else if key.eq_ignore_ascii_case("host") {
                if let Some(host) = pairs.next() {
                    return Some(ForwardedValue::Host(host))
                }
            }
        }

        None
    }
}

///Iterator over entries components within `Forwarded` header
pub struct ForwardedIter<'a, I> {
    components: I,
    _lifetime: marker::PhantomData<&'a I>,
}

impl<'a, I: Iterator<Item = &'a str> + 'a> Iterator for ForwardedIter<'a, I> {
    type Item = ForwardedEntryIter<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.components.next().map(ForwardedEntryIter::parse_entry)
    }
}

///Iterator over `For` components within `Forwarded` header
///
///This is most likely what you need most of the time in order to determine client's actual IP, but
///you can use [ForwardedIter](struct.ForwardedIter.html) when you need to iterate over all
///components
pub struct ForwardedForIter<'a, I> {
    components: I,
    _lifetime: marker::PhantomData<&'a I>,
}

impl<'a, I: Iterator<Item = &'a str> + 'a> Iterator for ForwardedForIter<'a, I> {
    type Item = ForwardedNode<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(value) = self.components.next() {
            let mut pairs = value.splitn(2, PAIR_SEP);
            let key = pairs.next().unwrap();
            if key.eq_ignore_ascii_case("for") {
                if let Some(node) = pairs.next() {
                    return Some(ForwardedNode::parse_node(node))
                }
            }
        }

        None
    }
}

///Iterator over `X-Forwarded-For` header
///
///This header is not standard and iterator assumes it is simple list of IP addresses.
pub struct XForwardedForIter<'a, I> {
    components: I,
    _lifetime: marker::PhantomData<&'a I>,
}

impl<'a, I: Iterator<Item = &'a str> + 'a> Iterator for XForwardedForIter<'a, I> {
    type Item = ForwardedNode<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.components.next().map(ForwardedNode::parse_x_node)
    }
}

#[inline(always)]
///Parses provided string as `Forwarded` header
///
///It performs no error checking, ignoring invalid values, as it assumes you parse valid `Forwarded` header
///
///Every proxy's entry is separated by `,`
///
///This iterator returns iterator over individual proxy's entries within `value`
pub fn parse_forwarded<'a>(value: &'a str) -> ForwardedIter<'a, impl Iterator<Item = &'a str>> {
    ForwardedIter {
        components: value.split(FORWARDED_SEP),
        _lifetime: marker::PhantomData,
    }
}

#[inline(always)]
///Variant of [parse_forwarded](fn.parse_forwarded.html) that reverses order of output
pub fn parse_forwarded_rev<'a>(value: &'a str) -> ForwardedIter<'a, impl Iterator<Item = &'a str>> {
    ForwardedIter {
        components: value.rsplit(FORWARDED_SEP),
        _lifetime: marker::PhantomData,
    }
}

#[inline(always)]
///Parses provided string as `Forwarded` header returning all `For` nodes in order
pub fn parse_forwarded_for<'a>(value: &'a str) -> ForwardedForIter<'a, impl Iterator<Item = &'a str>> {
    ForwardedForIter {
        components: value.split([FORWARDED_SEP, ENTRY_SEP]),
        _lifetime: marker::PhantomData,
    }
}

#[inline(always)]
///Parses provided string as `Forwarded` header returning all `For` nodes in reverse order
pub fn parse_forwarded_for_rev<'a>(value: &'a str) -> ForwardedForIter<'a, impl Iterator<Item = &'a str>> {
    ForwardedForIter {
        components: value.rsplit([FORWARDED_SEP, ENTRY_SEP]),
        _lifetime: marker::PhantomData,
    }
}

#[inline(always)]
///Parses provided string as `X-Forwarded-For` header returning all nodes in order
pub fn parse_x_forwarded_for<'a>(value: &'a str) -> XForwardedForIter<'a, impl Iterator<Item = &'a str>> {
    XForwardedForIter {
        components: value.split(FORWARDED_SEP),
        _lifetime: marker::PhantomData,
    }
}

#[inline(always)]
///Parses provided string as `X-Forwarded-For` header returning all nodes in reverse order
pub fn parse_x_forwarded_for_rev<'a>(value: &'a str) -> XForwardedForIter<'a, impl Iterator<Item = &'a str>> {
    XForwardedForIter {
        components: value.rsplit(FORWARDED_SEP),
        _lifetime: marker::PhantomData,
    }
}
