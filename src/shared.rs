pub const FALLBACK_STR: &str = "<non-utf8>";

//Implementation of header map extensions cannot be easily shared due to tonic's Metadata not providing reference access to HeaderMap
//Make it plain functions later if it becomes available one day
macro_rules! impl_extract_leftmost_forwarded_ip {
    ($this:expr) => {
        if let Some(forwarded) = $this.get_all(FORWARDED).into_iter().next() {
            forwarded.to_str().ok().and_then(|header| parse_forwarded_for(header).next()).and_then(|node| node.ip())
        } else if let Some(x_forwarded) = $this.get_all(X_FORWARDED_FOR).into_iter().next() {
            x_forwarded.to_str().ok().and_then(|header| parse_x_forwarded_for(header).next()).and_then(|node| node.ip())
        } else {
            None
        }
    }
}

macro_rules! impl_extract_rightmost_forwarded_ip {
    ($this:expr) => {
        if let Some(forwarded) = $this.get_all(FORWARDED).into_iter().next_back() {
            forwarded.to_str().ok().and_then(|header| parse_forwarded_for_rev(header).next()).and_then(|node| node.ip())
        } else if let Some(x_forwarded) = $this.get_all(X_FORWARDED_FOR).into_iter().next_back() {
            x_forwarded.to_str().ok().and_then(|header| parse_x_forwarded_for_rev(header).next()).and_then(|node| node.ip())
        } else {
            None
        }
    }
}

macro_rules! impl_extract_filtered_forwarded_ip {
    ($this:expr, $filter:expr) => {{
        let forwarded = $this.get_all(FORWARDED)
                             .into_iter()
                             .rev()
                             .filter_map(|header| header.to_str().ok()).flat_map(|header| parse_forwarded_for_rev(header));

        let mut forwarded_found = false;
        for node in forwarded {
            forwarded_found = true;
            match node {
                forwarded::ForwardedNode::Ip(ip) => if $filter.is_match(ip) {
                    continue
                } else {
                    return Some(ip)
                },
                _ => return None,
            }
        }

        if !forwarded_found {
            let forwarded = $this.get_all(X_FORWARDED_FOR)
                                 .into_iter()
                                 .rev()
                                 .filter_map(|header| header.to_str().ok()).flat_map(|header| parse_x_forwarded_for_rev(header));

            return $crate::find_next_ip_after_filter(forwarded, $filter);
        }

        None
    }}
}

pub(crate) use impl_extract_leftmost_forwarded_ip;
pub(crate) use impl_extract_rightmost_forwarded_ip;
pub(crate) use impl_extract_filtered_forwarded_ip;
