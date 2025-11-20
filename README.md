# http-ip

[![Rust](https://github.com/DoumanAsh/http-ip/actions/workflows/rust.yml/badge.svg)](https://github.com/DoumanAsh/http-ip/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/http-ip.svg)](https://crates.io/crates/http-ip)
[![Documentation](https://docs.rs/http-ip/badge.svg)](https://docs.rs/crate/http-ip/)

Utilities to determine HTTP client's IP

## Features

- `http` - Enables filter implementation using http's header map;
- `axum08` - Enables `axum` extractor implementation for `0.8.x`;
- `tonic014` - Enables `tonic` extension implementation for `0.14.x`.

## Example

A very simple example to extract IP from given header value using CIDR filtering to determine client's IP

This is different from a very common approach selecting leftmost IP as client's IP
Instead you can search starting through the right, filtering out your cloud's CIDRs to guarantee you get client's real external IP.
In complicated network environments individual clients are rarely having static IPs and
most likely hidden by corporate proxy that shields company's network, which often inserts extra IP in between you and client.

This in-between IP is more often than not, what you'd want to get and use, rather than leftmost
(which may be client IP, but it is not client IP from perspective of public network)

```rust

const IPS: &str = "203.0.113.195,2001:db8:85a3:8d3:1319:8a2e:370:7348,198.51.100.178";
const CIDR: http_ip::filter::Cidr = match http_ip::filter::Cidr::from_text("198.51.100.0/24") {
    Ok(cidr) => cidr,
    Err(_) => panic!("I cannot fail"),
};

//Get ips in reverse (from right) order to filter out proxy IPs manually until we reach client's IP
let ips = http_ip::forwarded::parse_x_forwarded_for_rev(IPS);
let client_ip = http_ip::find_next_ip_after_filter(ips, &CIDR).expect("to find ip");
assert_eq!(client_ip, core::net::IpAddr::V6(core::net::Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x8d3, 0x1319, 0x8a2e, 0x370, 0x7348)));
```
