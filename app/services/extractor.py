"""Poseidon Unstructured Text and Log IOC Extractor Engine.

Extracts, defangs, canonicalizes, and correlates cyber observables from unstructured text,
incident reports, log streams, and security alerts.
"""
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import PoseidonException
from app.models.enums import IOCType
from app.models.ioc import CanonicalIOC
from app.services.normalizer import (
    compute_canonical_hash,
    detect_and_normalize,
    remove_defanging,
)

# Regex Matchers designed to capture both fanged and defanged patterns
URL_PATTERN = re.compile(
    r"(?:(?:hxxps?|https?|fxp|ftp)://|(?:hxxps?|https?|fxp|ftp)\[:\]//)[^\s<>'\"{}|\\^`]+",
    re.IGNORECASE,
)

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b"
)

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9_.+-]+(?:\[@\]|@)[a-zA-Z0-9-.]+(?:\[\.\]|\.)[a-zA-Z]{2,}\b",
    re.IGNORECASE,
)

ASN_PATTERN = re.compile(
    r"\b(?:AS|as)\d{1,7}\b"
)

# Hashes
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Domains (both fanged and defanged, e.g. evil[.]com, sub.threat-domain[.]xyz)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.))+[a-zA-Z]{2,}\b",
    re.IGNORECASE,
)


@dataclass
class ExtractedCandidate:
    """Represents an extracted observable candidate from unstructured text."""
    raw_value: str
    normalized_value: str
    ioc_type: IOCType
    is_valid: bool = True
    validation_error: str | None = None
    occurrences: int = 1
    already_exists: bool = False
    existing_ioc_id: str | None = None
    existing_risk_score: float | None = None
    existing_confidence_score: float | None = None
    existing_status: str | None = None


class IOCExtractor:
    """Extracts, defangs, deduplicates, and validates observables from unstructured text."""

    @classmethod
    def extract_from_text(
        cls,
        text: str,
        auto_defang: bool = True,
        target_types: list[IOCType] | None = None,
    ) -> list[ExtractedCandidate]:
        """Extracts all potential IOCs from text using ordered pattern matching."""
        if not text:
            return []

        cleaned_text = text
        found_tokens: dict[str, ExtractedCandidate] = {}

        # Tracking spans of matched URLs to avoid sub-extracting their domains or IPs
        matched_spans: list[tuple[int, int]] = []

        def is_in_matched_span(start: int, end: int) -> bool:
            return any(ms_start <= start and end <= ms_end for ms_start, ms_end in matched_spans)

        # 1. Extract URLs first (broadest composite token)
        for match in URL_PATTERN.finditer(cleaned_text):
            raw_val = match.group(0).rstrip(".,;:)>]\"'")
            matched_spans.append((match.start(), match.end()))
            cls._process_token(raw_val, found_tokens, auto_defang, target_types)

        # 2. Extract CVEs
        for match in CVE_PATTERN.finditer(cleaned_text):
            if is_in_matched_span(match.start(), match.end()):
                continue
            raw_val = match.group(0)
            cls._process_token(raw_val, found_tokens, auto_defang, target_types)

        # 3. Extract Emails
        for match in EMAIL_PATTERN.finditer(cleaned_text):
            if is_in_matched_span(match.start(), match.end()):
                continue
            raw_val = match.group(0).rstrip(".,;:)>]\"'")
            cls._process_token(raw_val, found_tokens, auto_defang, target_types)

        # 4. Extract IPv4 Addresses
        for match in IPV4_PATTERN.finditer(cleaned_text):
            if is_in_matched_span(match.start(), match.end()):
                continue
            raw_val = match.group(0)
            cls._process_token(raw_val, found_tokens, auto_defang, target_types)

        # 5. Extract Hashes (SHA256 first, then SHA1, then MD5 to prevent sub-string matching)
        for match in SHA256_PATTERN.finditer(cleaned_text):
            if is_in_matched_span(match.start(), match.end()):
                continue
            raw_val = match.group(0)
            matched_spans.append((match.start(), match.end()))
            cls._process_token(raw_val, found_tokens, auto_defang, target_types)

        for match in SHA1_PATTERN.finditer(cleaned_text):
            if is_in_matched_span(match.start(), match.end()):
                continue
            raw_val = match.group(0)
            matched_spans.append((match.start(), match.end()))
            cls._process_token(raw_val, found_tokens, auto_defang, target_types)

        for match in MD5_PATTERN.finditer(cleaned_text):
            if is_in_matched_span(match.start(), match.end()):
                continue
            raw_val = match.group(0)
            cls._process_token(raw_val, found_tokens, auto_defang, target_types)

        # 6. Extract ASNs
        for match in ASN_PATTERN.finditer(cleaned_text):
            if is_in_matched_span(match.start(), match.end()):
                continue
            raw_val = match.group(0)
            cls._process_token(raw_val, found_tokens, auto_defang, target_types)

        # 7. Extract Domains
        for match in DOMAIN_PATTERN.finditer(cleaned_text):
            if is_in_matched_span(match.start(), match.end()):
                continue
            raw_val = match.group(0).rstrip(".,;:)>]\"'")
            cls._process_token(raw_val, found_tokens, auto_defang, target_types)

        return list(found_tokens.values())

    @classmethod
    def _process_token(
        cls,
        raw_val: str,
        found_tokens: dict[str, ExtractedCandidate],
        auto_defang: bool,
        target_types: list[IOCType] | None,
    ) -> None:
        raw_val = raw_val.strip()
        if not raw_val:
            return

        defanged = remove_defanging(raw_val) if auto_defang else raw_val

        try:
            ioc_type, norm_val = detect_and_normalize(defanged)
            is_valid = True
            error = None
        except PoseidonException as exc:
            ioc_type = IOCType.GENERIC_INDICATOR
            norm_val = defanged
            is_valid = False
            error = exc.message

        if target_types and ioc_type not in target_types:
            return

        dedup_key = f"{ioc_type.value}:{norm_val}"
        if dedup_key in found_tokens:
            found_tokens[dedup_key].occurrences += 1
        else:
            found_tokens[dedup_key] = ExtractedCandidate(
                raw_value=raw_val,
                normalized_value=norm_val,
                ioc_type=ioc_type,
                is_valid=is_valid,
                validation_error=error,
                occurrences=1,
            )

    @classmethod
    async def correlate_with_database(
        cls,
        db: AsyncSession,
        candidates: list[ExtractedCandidate],
    ) -> list[ExtractedCandidate]:
        """Cross-references candidates with existing CanonicalIOC records in the database."""
        if not candidates:
            return []

        # Build list of canonical hashes for valid candidates
        hash_map: dict[str, ExtractedCandidate] = {}
        for c in candidates:
            if c.is_valid:
                canonical_hash = compute_canonical_hash(c.ioc_type, c.normalized_value)
                hash_map[canonical_hash] = c

        if not hash_map:
            return candidates

        stmt = select(CanonicalIOC).where(CanonicalIOC.canonical_hash.in_(list(hash_map.keys())))
        result = await db.execute(stmt)
        existing_iocs = result.scalars().all()

        for ioc in existing_iocs:
            if ioc.canonical_hash in hash_map:
                target = hash_map[ioc.canonical_hash]
                target.already_exists = True
                target.existing_ioc_id = ioc.id
                target.existing_risk_score = ioc.risk_score
                target.existing_confidence_score = ioc.confidence_score
                target.existing_status = ioc.status.value

        return candidates
