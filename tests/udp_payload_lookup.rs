use RustScanX::generated::get_parsed_data;
use RustScanX::scanner::build_udp_payload_lookup;

#[test]
fn udp_payload_lookup_contains_common_udp_ports() {
    let udp_map = get_parsed_data();
    let lookup = build_udp_payload_lookup(udp_map);

    // 这些是常见的 UDP 服务；有效载荷数据库应当包含它们。
    assert!(
        lookup.contains_key(&53),
        "expected UDP payload for DNS (53)"
    );
    assert!(
        lookup.contains_key(&123),
        "expected UDP payload for NTP (123)"
    );
}

#[test]
fn udp_payload_lookup_payloads_are_non_empty_for_known_ports() {
    let udp_map = get_parsed_data();
    let lookup = build_udp_payload_lookup(udp_map);

    // 不断言确切的字节（生成的有效载荷集合可能演变），
    // 但对于这些知名协议，它不应为空。
    let dns = lookup.get(&53).expect("missing DNS payload");
    assert!(!dns.is_empty(), "DNS payload should not be empty");

    let ntp = lookup.get(&123).expect("missing NTP payload");
    assert!(!ntp.is_empty(), "NTP payload should not be empty");
}
