"""Tests for IOC Normalization Engine and Canonical Hashes."""
import pytest

from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import IOCType
from app.services.normalizer import (
    compute_canonical_hash,
    detect_and_normalize,
    normalize_asn,
    normalize_cve,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ipv4,
    normalize_ipv6,
    normalize_url,
    remove_defanging,
)


def test_remove_defanging():
    assert remove_defanging("hxxps://malicious[.]com/bad") == "https://malicious.com/bad"
    assert remove_defanging("192[.]168[.]1[.]1") == "192.168.1.1"
    assert remove_defanging("analyst[@]corp[.]com") == "analyst@corp.com"
    assert remove_defanging("hxxp[:]//bad(.)site") == "http://bad.site"


def test_normalize_ipv4_valid():
    assert normalize_ipv4("192.168.1.1") == "192.168.1.1"
    assert normalize_ipv4("192.168.001.001") == "192.168.1.1"
    assert normalize_ipv4("10[.]0[.]0[.]1") == "10.0.0.1"


def test_normalize_ipv4_invalid():
    with pytest.raises(PoseidonException) as exc:
        normalize_ipv4("999.999.999.999")
    assert exc.value.code == ErrorCode.IOC_INVALID_FORMAT


def test_normalize_ipv6_valid():
    assert normalize_ipv6("2001:0db8:0000:0000:0000:ff00:0042:8329") == "2001:db8::ff00:42:8329"
    assert normalize_ipv6("fe80[::]1") == "fe80::1"


def test_normalize_domain_valid():
    assert normalize_domain("EXAMPLE.COM") == "example.com"
    assert normalize_domain("evil[.]com.") == "evil.com"
    assert normalize_domain("http://phishing.site/login") == "phishing.site"
    assert normalize_domain("bücher.de") == "xn--bcher-kva.de"  # Punycode check


def test_normalize_domain_rejects_ip():
    with pytest.raises(PoseidonException) as exc:
        normalize_domain("1.1.1.1")
    assert exc.value.code == ErrorCode.IOC_INVALID_FORMAT


def test_normalize_url_valid():
    assert normalize_url("hxxp://EXAMPLE.com:80/path?b=2&a=1#frag") == "http://example.com/path?a=1&b=2"
    assert normalize_url("https://secure.site:443/test") == "https://secure.site/test"
    assert normalize_url("bad.com/malware.exe") == "http://bad.com/malware.exe"


def test_normalize_hashes():
    # MD5 (32 hex)
    md5_raw = "5D41402ABC4B2A76B9719D911017C592"
    h_type, norm = normalize_hash(md5_raw)
    assert h_type == IOCType.HASH_MD5
    assert norm == md5_raw.lower()

    # SHA256 (64 hex)
    sha256_raw = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    h_type, norm = normalize_hash(sha256_raw)
    assert h_type == IOCType.HASH_SHA256
    assert norm == sha256_raw.lower()


def test_normalize_hash_invalid():
    with pytest.raises(PoseidonException) as exc:
        normalize_hash("not_a_hex_string_too_short")
    assert exc.value.code == ErrorCode.IOC_INVALID_FORMAT


def test_normalize_cve():
    assert normalize_cve("cve-2024-3094") == "CVE-2024-3094"
    assert normalize_cve("CVE-2021-44228") == "CVE-2021-44228"

    with pytest.raises(PoseidonException) as exc:
        normalize_cve("INVALID-CVE-STRING")
    assert exc.value.code == ErrorCode.IOC_INVALID_FORMAT


def test_normalize_asn():
    assert normalize_asn("15169") == "AS15169"
    assert normalize_asn("as15169") == "AS15169"
    assert normalize_asn("AS13335") == "AS13335"


def test_normalize_email():
    assert normalize_email("Attacker[@]Evil[.]Com") == "attacker@evil.com"


def test_detect_and_normalize_heuristics():
    # IPv4
    t, v = detect_and_normalize("185[.]220[.]101[.]5")
    assert t == IOCType.IPV4
    assert v == "185.220.101.5"

    # CVE
    t, v = detect_and_normalize("cve-2023-38606")
    assert t == IOCType.CVE
    assert v == "CVE-2023-38606"

    # URL
    t, v = detect_and_normalize("hxxps://malware-drop[.]cc/payload.bin?k=v")
    assert t == IOCType.URL
    assert v == "https://malware-drop.cc/payload.bin?k=v"

    # Domain
    t, v = detect_and_normalize("APT29-C2[.]NET")
    assert t == IOCType.DOMAIN
    assert v == "apt29-c2.net"


def test_compute_canonical_hash():
    h1 = compute_canonical_hash(IOCType.IPV4, "1.1.1.1")
    h2 = compute_canonical_hash(IOCType.IPV4, "1.1.1.1")
    h3 = compute_canonical_hash(IOCType.DOMAIN, "1.1.1.1")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64
