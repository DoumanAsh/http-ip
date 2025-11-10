use http::HeaderMap;
use http::header::FORWARDED;

use http_ip::http::HeaderMapClientIp;
use http_ip::filter::{self, Cidr};

use core::net::IpAddr;

#[test]
fn should_format_header_map() {
    let mut headers = HeaderMap::new();

    headers.append(FORWARDED, "By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1".parse().unwrap());
    headers.append(FORWARDED, "For=unknown,For=_hidden".parse().unwrap());

    let display = headers.get_header_value_fmt(FORWARDED).to_string();
    assert_eq!(display, "By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1 ,For=unknown,For=_hidden");
}

#[test]
fn should_extract_left_most_ip_from_header_map() {
    let mut headers = HeaderMap::new();

    headers.append(FORWARDED, "By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1".parse().unwrap());
    headers.append(FORWARDED, "For=unknown,For=_hidden".parse().unwrap());

    let ip = headers.extract_leftmost_forwarded_ip().expect("to have IP");
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(expected_ip, ip);
}

#[test]
fn should_not_extract_left_most_ip_from_header_map() {
    let mut headers = HeaderMap::new();

    headers.append(FORWARDED, "By=\"[2001:db8:cafe::17]:4711\",For=_hidden".parse().unwrap());
    headers.append(FORWARDED, "For=unknown,For=127.0.0.1".parse().unwrap());

    let result = headers.extract_leftmost_forwarded_ip();
    assert!(result.is_none(), "Unexpected IP={:?}", result);
}


#[test]
fn should_extract_right_most_ip_from_header_map() {
    let mut headers = HeaderMap::new();

    headers.append(FORWARDED, "By=\"[2001:db8:cafe::17]:4711\",For=_hidden".parse().unwrap());
    headers.append(FORWARDED, "For=unknown,For=127.0.0.1".parse().unwrap());

    let ip = headers.extract_rightmost_forwarded_ip().expect("to have IP");
    let expected_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(expected_ip, ip);
}

#[test]
fn should_not_extract_right_most_ip_from_header_map() {
    let mut headers = HeaderMap::new();

    headers.append(FORWARDED, "By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1".parse().unwrap());
    headers.append(FORWARDED, "For=unknown,For=_hidden".parse().unwrap());

    let result = headers.extract_rightmost_forwarded_ip();
    assert!(result.is_none(), "Unexpected IP={:?}", result);
}

#[test]
fn should_extract_filtered_by_ip_from_header_map() {
    let mut headers = HeaderMap::new();

    headers.append(FORWARDED, "By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1".parse().unwrap());
    headers.append(FORWARDED, "For=192.168.0.1,For=10.0.0.1".parse().unwrap());

    let filtered_ip: IpAddr = "10.0.0.1".parse().unwrap();
    let expected_ip: IpAddr = "192.168.0.1".parse().unwrap();
    let result = headers.extract_filtered_forwarded_ip(&filtered_ip).expect("to get ip");
    assert_eq!(result, expected_ip);
}

#[test]
fn should_extract_filtered_by_cidr_from_header_map() {
    let mut headers = HeaderMap::new();

    headers.append(FORWARDED, "By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1".parse().unwrap());
    headers.append(FORWARDED, "For=192.168.0.1,For=10.0.0.1".parse().unwrap());

    let filtered_ip = Cidr::from_text("10.0.0.0/31").expect("to parse");
    let expected_ip: IpAddr = "192.168.0.1".parse().unwrap();
    let result = headers.extract_filtered_forwarded_ip(&filtered_ip).expect("to get ip");
    assert_eq!(result, expected_ip);

    let filtered_ip = Cidr::from_text("10.0.0.0/1").expect("to parse");
    let expected_ip: IpAddr = "192.168.0.1".parse().unwrap();
    let result = headers.extract_filtered_forwarded_ip(&filtered_ip).expect("to get ip");
    assert_eq!(result, expected_ip);
}

#[test]
fn should_not_extract_filtered_by_cidr_from_header_map() {
    let mut headers = HeaderMap::new();

    headers.append(FORWARDED, "By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1".parse().unwrap());
    headers.append(FORWARDED, "For=192.168.0.1,For=10.0.0.1".parse().unwrap());

    let filtered_ip = Cidr::from_text("10.0.0.0/32").expect("to parse");
    let expected_ip: IpAddr = "10.0.0.1".parse().unwrap();
    let result = headers.extract_filtered_forwarded_ip(&filtered_ip).expect("to get ip");
    assert_eq!(result, expected_ip);
}

#[test]
fn should_extract_filtered_by_cidr_from_header_map_with_or() {
    let mut headers = HeaderMap::new();

    headers.append(FORWARDED, "By=\"[2001:db8:cafe::17]:4711\",For=127.0.0.1".parse().unwrap());
    headers.append(FORWARDED, "For=192.168.0.1,For=10.0.0.1".parse().unwrap());

    let filtered_ip = Cidr::from_text("10.0.0.0/32").expect("to parse");
    let filtered_ip2: IpAddr = "10.0.0.1".parse().expect("to parse");
    let filter = filter::or(filtered_ip, filtered_ip2);
    let expected_ip: IpAddr = "192.168.0.1".parse().unwrap();
    let result = headers.extract_filtered_forwarded_ip(&filter).expect("to get ip");
    assert_eq!(result, expected_ip);
}
