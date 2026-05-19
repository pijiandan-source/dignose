from dignose.dns_compare import (
    DEFAULT_CHINA_UDP_DNS_PROVIDERS,
    DEFAULT_DOMAINS,
    GLOBAL_DOH_PROVIDERS,
    GLOBAL_UDP_DNS_PROVIDERS,
    classify_ip,
    normalize_hostname,
)


def test_normalize_hostname_accepts_url_port_and_path():
    assert normalize_hostname("https://example.com:443/check") == "example.com"
    assert normalize_hostname("https://uu.163.com/api") == "uu.163.com"
    assert normalize_hostname("uu.163.com/client") == "uu.163.com"
    assert normalize_hostname("example.com.") == "example.com"


def test_classify_ip():
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("10.0.0.1") == "private"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("169.254.1.1") == "link_local"
    assert classify_ip("ff02::1") == "multicast"
    assert classify_ip("fd00::1") == "unique_local"


def test_default_profile_is_china_first():
    default_servers = {item["server"] for item in DEFAULT_CHINA_UDP_DNS_PROVIDERS}
    assert {"223.5.5.5", "119.29.29.29", "114.114.114.114", "180.76.76.76"} <= default_servers
    assert "1.1.1.1" not in default_servers
    assert any(domain == "uu.163.com" for domain, _category in DEFAULT_DOMAINS)
    assert any(domain == "adl.netease.com" for domain, _category in DEFAULT_DOMAINS)


def test_global_providers_are_separate_reference_groups():
    assert any(item["server"] == "1.1.1.1" for item in GLOBAL_UDP_DNS_PROVIDERS)
    assert any(item["endpoint"] == "https://dns.google/resolve" for item in GLOBAL_DOH_PROVIDERS)
