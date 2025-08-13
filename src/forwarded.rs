//! `Forwarded` header module

use core::{marker, fmt};
use core::net::IpAddr;

#[derive(PartialEq, Eq, Debug)]
///Parsed node of the Forwarded header
///
///See details https://datatracker.ietf.org/doc/html/rfc7239#section-4
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

#[inline(always)]
///Extracts client IPs from forwarded header
pub fn parse_forwarded_for(value: &str) -> ForwardedNodeIter<impl Iterator<Item = &'_ str>> {
    ForwardedNodeIter {
        //Syntax is: <entry 1>, <entry N>
        //Entry is: <key1>=<value1>;<keyN>=<valueN>
        components: value.split([';', ',']),
        _lifetime: marker::PhantomData,
    }
}

///Iterator over `node` components within `ForwardedNode` header
pub struct ForwardedNodeIter<'a, I> {
    components: I,
    _lifetime: marker::PhantomData<&'a I>,
}

impl<'a, I: Iterator<Item = &'a str> + 'a> Iterator for ForwardedNodeIter<'a, I> {
    type Item = ForwardedNode<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(value) = self.components.next() {
            let mut pairs = value.split('=');
            let key = pairs.next().unwrap();
            if key.eq_ignore_ascii_case("for") {
                if let Some(value) = pairs.next() {
                    let value = value.trim_matches('"');
                    if value.eq_ignore_ascii_case("unknown") {
                        return Some(ForwardedNode::Unknown);
                    }

                    if let Some(mut ipv6) = value.strip_prefix('[') {
                        if let Some(end_addr_idx) = ipv6.find(']') {
                            ipv6 = &ipv6[..end_addr_idx];
                            return Some(ForwardedNode::parse_name(ipv6));
                        } else {
                            return Some(ForwardedNode::Name(ipv6));
                        }
                    }

                    let mut value = value.rsplit(':');
                    let port_or_ip = value.next().unwrap();
                    let ip = if let Some(ip) = value.next() {
                        ip
                    } else {
                        port_or_ip
                    };

                    return Some(ForwardedNode::parse_name(ip));
                }
            }
        }

        None
    }
}
