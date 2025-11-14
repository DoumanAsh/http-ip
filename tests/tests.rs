use core::net::IpAddr;

use http_ip::forwarded::{parse_x_forwarded_for, parse_x_forwarded_for_rev};
use http_ip::forwarded::{parse_forwarded_for, parse_forwarded_for_rev};
use http_ip::forwarded::{parse_forwarded, parse_forwarded_rev};
use http_ip::forwarded::{ForwardedNode, ForwardedValue};

#[test]
fn should_parse_single_forwarded_entry() {
    let mut ips = parse_forwarded("For=\"[2001:db8:cafe::17]:4711\"");
    let mut entry = ips.next().expect("have single entry");
    let ip = entry.next().unwrap();
    let expected_ip: IpAddr = "2001:db8:cafe::17".parse().unwrap();
    assert_eq!(ForwardedValue::For(ForwardedNode::Ip(expected_ip)), ip);
    assert!(entry.next().is_none());
    assert!(ips.next().is_none());
}

#[test]
fn should_parse_two_forwarded_entries() {
    let mut ips = parse_forwarded("By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1");
    let mut entry = ips.next().expect("have single entry");

    let ip = entry.next().unwrap();
    let expected_ip: IpAddr = "2001:db8:cafe::17".parse().unwrap();
    assert_eq!(ForwardedValue::By(ForwardedNode::Ip(expected_ip)), ip);

    let mut entry = ips.next().expect("have single entry");
    let ip = entry.next().unwrap();
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(ForwardedValue::For(ForwardedNode::Ip(expected_ip)), ip);

    assert!(entry.next().is_none());
    assert!(ips.next().is_none());
}

#[test]
fn should_parse_multiple_forwarded_entries() {
    let mut ips = parse_forwarded(
        "By=\"[2001:db8:cafe::17]:4711\";For=127.0.0.1,For=unknown,For=_hidden",
    );
    let mut entry = ips.next().expect("have single entry");
    let ip = entry.next().unwrap();
    let expected_ip: IpAddr = "2001:db8:cafe::17".parse().unwrap();
    assert_eq!(ForwardedValue::By(ForwardedNode::Ip(expected_ip)), ip);
    let ip = entry.next().unwrap();
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(ForwardedValue::For(ForwardedNode::Ip(expected_ip)), ip);

    let mut entry = ips.next().expect("have single entry");
    let ip = entry.next().unwrap();
    assert_eq!(ForwardedValue::For(ForwardedNode::Unknown), ip);

    let mut entry = ips.next().expect("have single entry");
    let ip = entry.next().unwrap();
    assert_eq!(ForwardedValue::For(ForwardedNode::Name("_hidden")), ip);

    assert!(entry.next().is_none());
    assert!(ips.next().is_none());
}

#[test]
fn should_parse_multiple_forwarded_entries_rev() {
    let mut ips = parse_forwarded_rev(
        "By=\"[2001:db8:cafe::17]:4711\";For=127.0.0.1,For=unknown,For=_hidden",
    );

    let mut entry = ips.next().expect("have single entry");
    let ip = entry.next().unwrap();
    assert_eq!(ForwardedValue::For(ForwardedNode::Name("_hidden")), ip);

    let mut entry = ips.next().expect("have single entry");
    let ip = entry.next().unwrap();
    assert_eq!(ForwardedValue::For(ForwardedNode::Unknown), ip);

    let mut entry = ips.next().expect("have single entry");
    let ip = entry.next().unwrap();
    let expected_ip: IpAddr = "2001:db8:cafe::17".parse().unwrap();
    assert_eq!(ForwardedValue::By(ForwardedNode::Ip(expected_ip)), ip);
    let ip = entry.next().unwrap();
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(ForwardedValue::For(ForwardedNode::Ip(expected_ip)), ip);

    assert!(entry.next().is_none());
    assert!(ips.next().is_none());
}

#[test]
fn should_parse_single_entry_with_forwarded_for_simple() {
    let mut ips = parse_forwarded_for("For=\"[2001:db8:cafe::17]:4711\"");
    let ip = ips.next().unwrap();
    let expected_ip: IpAddr = "2001:db8:cafe::17".parse().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip), ip);
    assert!(ips.next().is_none());
}

#[test]
fn should_parse_single_entry_with_forwarded_for_multi() {
    let mut ips = parse_forwarded_for("By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1");
    let ip = ips.next().unwrap();
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip), ip);
    assert!(ips.next().is_none());
}

#[test]
fn should_parse_multiple_entries_with_forwarded_for() {
    let mut ips = parse_forwarded_for(
        "By=\"[2001:db8:cafe::17]:4711\";For=127.0.0.1,For=unknown,For=_hidden",
    );
    let ip = ips.next().unwrap();
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip), ip);

    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Unknown, ip);

    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Name("_hidden"), ip);
}

#[test]
fn should_parse_single_entry_with_forwarded_for_simple_rev() {
    let mut ips = parse_forwarded_for_rev("For=\"[2001:db8:cafe::17]:4711\"");
    let ip = ips.next().unwrap();
    let expected_ip: IpAddr = "2001:db8:cafe::17".parse().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip), ip);
    assert!(ips.next().is_none());
}

#[test]
fn should_parse_single_entry_with_forwarded_for_multi_rev() {
    let mut ips = parse_forwarded_for_rev("By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1");
    let ip = ips.next().unwrap();
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip), ip);
    assert!(ips.next().is_none());
}

#[test]
fn should_parse_multiple_entries_with_forwarded_for_rev() {
    let mut ips = parse_forwarded_for_rev(
        "By=\"[2001:db8:cafe::17]:4711\";For=127.0.0.1,For=unknown,For=_hidden",
    );

    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Name("_hidden"), ip);

    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Unknown, ip);

    let ip = ips.next().unwrap();
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip), ip);
}

#[test]
fn should_parse_x_forwarded_for() {
    const IPS: &str = "203.0.113.195,2001:db8:85a3:8d3:1319:8a2e:370:7348,198.51.100.178";

    let expected_ip1: IpAddr = "203.0.113.195".parse().unwrap();
    let expected_ip2: IpAddr = "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap();
    let expected_ip3: IpAddr = "198.51.100.178".parse().unwrap();

    let mut ips = parse_x_forwarded_for_rev(IPS);
    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip3), ip);
    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip2), ip);
    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip1), ip);
    assert!(ips.next().is_none());

    let mut ips = parse_x_forwarded_for(IPS);
    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip1), ip);
    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip2), ip);
    let ip = ips.next().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip3), ip);
    assert!(ips.next().is_none());
}
