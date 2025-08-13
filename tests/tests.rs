use core::net::IpAddr;

use http_ip::forwarded::{parse_forwarded_for, ForwardedNode};

#[test]
fn should_parse_forwarded_header() {
    let mut ips = parse_forwarded_for("For=\"[2001:db8:cafe::17]:4711\"");
    let ip = ips.next().unwrap();
    let expected_ip: IpAddr = "2001:db8:cafe::17".parse().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip), ip);
    assert!(ips.next().is_none());

    let mut ips = parse_forwarded_for("By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1");
    let ip = ips.next().unwrap();
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(ForwardedNode::Ip(expected_ip), ip);
    assert!(ips.next().is_none());

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
