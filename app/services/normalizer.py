"""Poseidon IOC Normalization Engine.

Enforces deterministic, canonical representations for all Cyber Threat Intelligence observable types.
Includes defanging removal, RFC compliance, and canonical hash computation.
"""
import hashlib
import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.core.errors import ErrorCode, PoseidonException
from app.models.enums import IOCType

# Regular Expressions
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
ASN_REGEX = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)
HEX_REGEX = re.compile(r"^[a-fA-F0-9]+$")
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def remove_defanging(value: str) -> str:
    """Removes common CTI defanging artifacts (e.g. hxxp, [.], [::], (@), etc.)."""
    cleaned = value.strip()

    # Defanged brackets around punctuation (e.g. [.], [::], [:], (@), etc.)
    cleaned = re.sub(r"[\[\(\{]([.:@]+)[\]\)\}]", r"\1", cleaned)

    # Defanged schemes
    cleaned = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^fxps?://", "ftp://", cleaned, flags=re.IGNORECASE)

    return cleaned.strip()


def normalize_ipv4(value: str) -> str:
    """Validates and deterministically normalizes an IPv4 address, stripping leading zeros."""
    cleaned = remove_defanging(value)

    # Strip leading zeros from octets before IPv4Address validation
    parts = cleaned.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        cleaned = ".".join(str(int(p)) for p in parts)

    try:
        ip = ipaddress.IPv4Address(cleaned)
        return str(ip)
    except Exception as exc:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Invalid IPv4 address '{value}': {exc}",
            details={"raw_value": value, "ioc_type": IOCType.IPV4.value},
        ) from exc


def normalize_ipv6(value: str) -> str:
    """Validates and deterministically normalizes an IPv6 address to RFC 5952 format."""
    cleaned = remove_defanging(value)
    try:
        ip = ipaddress.IPv6Address(cleaned)
        return str(ip)
    except Exception as exc:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Invalid IPv6 address '{value}': {exc}",
            details={"raw_value": value, "ioc_type": IOCType.IPV6.value},
        ) from exc


def normalize_domain(value: str) -> str:
    """Normalizes a domain or FQDN (lowercase, IDNA/Punycode, strip trailing dots and ports)."""
    cleaned = remove_defanging(value).lower()

    # Remove protocol prefix if accidentally included
    cleaned = re.sub(r"^https?://", "", cleaned)
    # Remove path or query if attached
    cleaned = cleaned.split("/")[0].split("?")[0]
    # Remove port if present
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]
    # Remove trailing dot (root zone)
    cleaned = cleaned.rstrip(".")

    if not cleaned:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message="Domain name cannot be empty.",
            details={"raw_value": value},
        )

    # Check for IP address masquerading as domain
    try:
        ipaddress.ip_address(cleaned)
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Value '{value}' is an IP address, not a domain.",
            details={"raw_value": value, "detected_ip": cleaned},
        )
    except ValueError:
        pass

    try:
        # Convert IDN/Unicode domain to Punycode/ASCII
        encoded = cleaned.encode("idna").decode("ascii")
    except Exception as exc:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Invalid domain encoding for '{value}': {exc}",
            details={"raw_value": value},
        ) from exc

    if not DOMAIN_REGEX.match(encoded):
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Invalid domain name format for '{value}'.",
            details={"raw_value": value, "encoded": encoded},
        )

    return encoded


def normalize_url(value: str) -> str:
    """Deterministically normalizes a URL (lowercase host, sorted query params, stripped fragment)."""
    cleaned = remove_defanging(value)

    # Ensure URL has a scheme
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = f"http://{cleaned}"

    parsed = urlsplit(cleaned)
    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https", "ftp"}:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Unsupported URL scheme '{scheme}'.",
            details={"raw_value": value, "scheme": scheme},
        )

    netloc = parsed.netloc.lower()
    if not netloc:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Invalid URL without host '{value}'.",
            details={"raw_value": value},
        )

    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    # Deterministically sort query params
    query = ""
    if parsed.query:
        params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
        query = urlencode(params)

    # Ensure root path if empty and query exists
    path = parsed.path
    if not path:
        path = "/"

    normalized = urlunsplit((scheme, netloc, path, query, ""))
    return normalized


def normalize_hash(value: str, expected_type: IOCType | None = None) -> tuple[IOCType, str]:
    """Validates and normalizes cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512)."""
    cleaned = value.strip().lower()

    if not HEX_REGEX.match(cleaned):
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Hash '{value}' contains invalid non-hexadecimal characters.",
            details={"raw_value": value},
        )

    length = len(cleaned)
    length_type_map = {
        32: IOCType.HASH_MD5,
        40: IOCType.HASH_SHA1,
        64: IOCType.HASH_SHA256,
        128: IOCType.HASH_SHA512,
    }

    detected_type = length_type_map.get(length)
    if not detected_type:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Hash length {length} does not match MD5 (32), SHA-1 (40), SHA-256 (64), or SHA-512 (128).",
            details={"raw_value": value, "length": length},
        )

    if expected_type and expected_type != detected_type:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Expected hash type {expected_type.value}, but detected {detected_type.value}.",
            details={"raw_value": value, "expected": expected_type.value, "detected": detected_type.value},
        )

    return detected_type, cleaned


def normalize_cve(value: str) -> str:
    """Normalizes CVE identifiers to standard uppercase CVE-YYYY-NNNN format."""
    cleaned = value.strip().upper()
    if not CVE_REGEX.match(cleaned):
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Invalid CVE format '{value}'. Expected format CVE-YYYY-NNNN...",
            details={"raw_value": value},
        )
    return cleaned


def normalize_asn(value: str) -> str:
    """Normalizes Autonomous System Number to AS<number> format."""
    cleaned = value.strip().upper()
    match = ASN_REGEX.match(cleaned)
    if not match:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Invalid ASN format '{value}'. Expected AS12345 or 12345.",
            details={"raw_value": value},
        )
    return f"AS{match.group(1)}"


def normalize_email(value: str) -> str:
    """Normalizes email address with defanging removal and domain IDNA encoding."""
    cleaned = remove_defanging(value).strip().lower()
    if "@" not in cleaned:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Invalid email address '{value}'.",
            details={"raw_value": value},
        )

    parts = cleaned.rsplit("@", 1)
    user_part = parts[0]
    domain_part = parts[1]

    if not user_part or not domain_part:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message=f"Invalid email address '{value}'.",
            details={"raw_value": value},
        )

    normalized_domain = normalize_domain(domain_part)
    return f"{user_part}@{normalized_domain}"


def detect_and_normalize(raw_value: str, explicit_type: IOCType | None = None) -> tuple[IOCType, str]:
    """Detects IOC type (if not explicitly specified) and returns (IOCType, normalized_value)."""
    val = raw_value.strip()
    if not val:
        raise PoseidonException(
            code=ErrorCode.IOC_INVALID_FORMAT,
            message="Observable value cannot be empty.",
        )

    if explicit_type:
        match explicit_type:
            case IOCType.IPV4:
                return IOCType.IPV4, normalize_ipv4(val)
            case IOCType.IPV6:
                return IOCType.IPV6, normalize_ipv6(val)
            case IOCType.DOMAIN | IOCType.FQDN:
                return explicit_type, normalize_domain(val)
            case IOCType.URL:
                return IOCType.URL, normalize_url(val)
            case IOCType.HASH_MD5 | IOCType.HASH_SHA1 | IOCType.HASH_SHA256 | IOCType.HASH_SHA512:
                _, norm_hash = normalize_hash(val, expected_type=explicit_type)
                return explicit_type, norm_hash
            case IOCType.CVE:
                return IOCType.CVE, normalize_cve(val)
            case IOCType.AUTONOMOUS_SYSTEM:
                return IOCType.AUTONOMOUS_SYSTEM, normalize_asn(val)
            case IOCType.EMAIL_ADDRESS:
                return IOCType.EMAIL_ADDRESS, normalize_email(val)
            case _:
                # Generic fallback for other observable types (e.g. mutex, user-agent)
                return explicit_type, remove_defanging(val)

    # Heuristic Automatic Detection
    defanged = remove_defanging(val)

    # 1. Check CVE
    if CVE_REGEX.match(defanged.upper()):
        return IOCType.CVE, normalize_cve(defanged)

    # 2. Check Hashes
    if HEX_REGEX.match(defanged):
        length = len(defanged)
        if length in {32, 40, 64, 128}:
            hash_type, norm_hash = normalize_hash(defanged)
            return hash_type, norm_hash

    # 3. Check IPv4 / IPv6
    try:
        norm_ipv4 = normalize_ipv4(defanged)
        return IOCType.IPV4, norm_ipv4
    except PoseidonException:
        pass

    try:
        norm_ipv6 = normalize_ipv6(defanged)
        return IOCType.IPV6, norm_ipv6
    except PoseidonException:
        pass

    # 4. Check URL
    if defanged.lower().startswith(("http://", "https://", "ftp://")) or "/" in defanged:
        try:
            norm_url = normalize_url(defanged)
            return IOCType.URL, norm_url
        except PoseidonException:
            pass

    # 5. Check Email
    if "@" in defanged and " " not in defanged:
        try:
            return IOCType.EMAIL_ADDRESS, normalize_email(defanged)
        except PoseidonException:
            pass

    # 6. Check ASN
    if ASN_REGEX.match(defanged.upper()) and (defanged.upper().startswith("AS") or len(defanged) <= 6):
        try:
            return IOCType.AUTONOMOUS_SYSTEM, normalize_asn(defanged)
        except PoseidonException:
            pass

    # 7. Check Domain
    try:
        norm_domain = normalize_domain(defanged)
        return IOCType.DOMAIN, norm_domain
    except PoseidonException:
        pass

    raise PoseidonException(
        code=ErrorCode.IOC_UNKNOWN_TYPE,
        message=f"Unable to heuristically detect valid IOC type for '{raw_value}'. Specify type explicitly.",
        details={"raw_value": raw_value},
    )


def compute_canonical_hash(ioc_type: IOCType, normalized_value: str) -> str:
    """Computes SHA-256 canonical hash of '{ioc_type}:{normalized_value}'."""
    payload = f"{ioc_type.value}:{normalized_value}".encode()
    return hashlib.sha256(payload).hexdigest()


def compute_payload_sha256(payload: str | bytes) -> str:
    """Computes SHA-256 hash of raw upstream payload for cryptographic tamper evidence."""
    if isinstance(payload, str):
        data = payload.encode("utf-8")
    else:
        data = payload
    return hashlib.sha256(data).hexdigest()
