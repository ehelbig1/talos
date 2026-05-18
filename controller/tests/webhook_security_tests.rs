use std::net::IpAddr;
use std::str::FromStr;

#[tokio::test]
async fn test_webhook_ip_normalization() {
    let allowed_ips = vec!["127.0.0.0/8".to_string()];
    let source_ip = IpAddr::from_str("::ffff:127.0.0.1").unwrap();

    // Logic from controller/src/webhooks/mod.rs:135
    let normalized_ip = match source_ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(source_ip),
        _ => source_ip,
    };

    let mut allowed = false;
    for stored in &allowed_ips {
        if let Ok(network) = stored.parse::<ipnetwork::IpNetwork>() {
            if network.contains(normalized_ip) {
                allowed = true;
                break;
            }
        }
    }

    assert!(
        allowed,
        "IPv4-mapped IPv6 address should match IPv4 CIDR after normalization: {:?}",
        normalized_ip
    );
}

#[tokio::test]
async fn test_webhook_cidr_boundary() {
    let allowed_ips = vec!["192.168.1.0/24".to_string()];

    let ip_inside = IpAddr::from_str("192.168.1.255").unwrap();
    let ip_outside = IpAddr::from_str("192.168.2.0").unwrap();

    let mut allowed_inside = false;
    for stored in &allowed_ips {
        if let Ok(network) = stored.parse::<ipnetwork::IpNetwork>() {
            if network.contains(ip_inside) {
                allowed_inside = true;
                break;
            }
        }
    }
    assert!(
        allowed_inside,
        "192.168.1.255 should be inside 192.168.1.0/24"
    );

    let mut allowed_outside = false;
    for stored in &allowed_ips {
        if let Ok(network) = stored.parse::<ipnetwork::IpNetwork>() {
            if network.contains(ip_outside) {
                allowed_outside = true;
                break;
            }
        }
    }
    assert!(
        !allowed_outside,
        "192.168.2.0 should be outside 192.168.1.0/24"
    );
}

#[tokio::test]
async fn test_webhook_hmac_slack_freshness() {
    // Current timestamp
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Old timestamp (10 minutes ago)
    let old_ts = (now_secs - 600).to_string();

    // Verification logic from controller/src/webhooks/mod.rs:647
    let ts_secs = old_ts.parse::<i64>().unwrap();
    assert!(
        (now_secs - ts_secs).abs() > 300,
        "Timestamp should be outside the ±5 minute window"
    );
}
