from dignose.utils import is_loopback_ip, is_private_ip, safe_json_dumps, section


def test_section_shape():
    assert section(True, {"x": 1}, None) == {"ok": True, "data": {"x": 1}, "error": None}


def test_ip_helpers():
    assert is_loopback_ip("127.0.0.1")
    assert is_private_ip("192.168.1.1")
    assert not is_private_ip("8.8.8.8")


def test_json_keeps_chinese():
    assert "只读" in safe_json_dumps({"message": "只读"})

