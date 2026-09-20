"""MISP Event Export Engine for Poseidon CTI Cases."""
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import AttackTechnique, MalwareFamily, ThreatActor, Vulnerability
from app.models.enums import TLP, CasePriority, CaseStatus
from app.models.investigation import InvestigationCase
from app.models.ioc import CanonicalIOC


class MispExportService:
    """Serializes POSEIDON Investigation Cases into standard MISP Event format."""

    THREAT_LEVEL_MAP = {
        CasePriority.CRITICAL: "1",  # High / Critical
        CasePriority.HIGH: "1",
        CasePriority.MEDIUM: "2",    # Medium
        CasePriority.LOW: "3",       # Low
    }

    ANALYSIS_MAP = {
        CaseStatus.DRAFT: "0",       # Initial
        CaseStatus.OPEN: "1",        # Ongoing
        CaseStatus.IN_REVIEW: "1",   # Ongoing
        CaseStatus.CLOSED: "2",      # Completed
        CaseStatus.ARCHIVED: "2",    # Completed
    }

    DISTRIBUTION_MAP = {
        TLP.RED: "0",                # Your organisation only
        TLP.AMBER_STRICT: "0",
        TLP.AMBER: "1",              # This community only
        TLP.GREEN: "2",              # Connected communities
        TLP.CLEAR: "3",              # All communities
    }

    IOC_TYPE_TO_MISP = {
        "ipv4": ("ip-dst", "Network activity"),
        "ipv6": ("ip-dst", "Network activity"),
        "domain": ("domain", "Network activity"),
        "fqdn": ("hostname", "Network activity"),
        "url": ("url", "Network activity"),
        "hash_md5": ("md5", "Payload delivery"),
        "hash_sha1": ("sha1", "Payload delivery"),
        "hash_sha256": ("sha256", "Payload delivery"),
        "hash_sha512": ("sha512", "Payload delivery"),
        "cve": ("vulnerability", "External analysis"),
        "email": ("email-dst", "Network activity"),
        "ja3": ("ja3-fingerprint-md5", "Network activity"),
        "ja4": ("ja4", "Network activity"),
    }

    @classmethod
    async def export_case_as_misp_event(
        cls,
        session: AsyncSession,
        case: InvestigationCase,
    ) -> dict[str, Any]:
        """Convert a POSEIDON case and linked observables into a standard MISP Event document."""
        attributes: list[dict[str, Any]] = []
        tags: list[dict[str, str]] = [
            {"name": f"tlp:{case.tlp.value.lower()}"},
            {"name": f"poseidon:case_number={case.case_number}"},
            {"name": f"poseidon:priority={case.priority.value}"},
        ]

        for t in case.tags:
            tags.append({"name": t})

        # Extract IDs
        ioc_ids: list[str] = []
        actor_ids: list[str] = []
        malware_ids: list[str] = []
        vuln_ids: list[str] = []
        tech_ids: list[str] = []

        for ref in case.entity_references:
            etype = ref.get("entity_type", "").lower()
            eid = ref.get("entity_id", "")
            if not eid:
                continue
            if etype in ["ioc", "canonical_ioc"]:
                ioc_ids.append(eid)
            elif etype in ["actor", "threat_actor"]:
                actor_ids.append(eid)
            elif etype in ["malware", "malware_family"]:
                malware_ids.append(eid)
            elif etype in ["vulnerability", "cve"]:
                vuln_ids.append(eid)
            elif etype in ["technique", "attack_technique"]:
                tech_ids.append(eid)

        # 1. Observables / IOCs
        if ioc_ids:
            ioc_stmt = select(CanonicalIOC).where(CanonicalIOC.id.in_(ioc_ids))
            iocs = (await session.execute(ioc_stmt)).scalars().all()
            for ioc in iocs:
                itype = ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)
                misp_type, misp_cat = cls.IOC_TYPE_TO_MISP.get(itype, ("text", "Other"))

                attributes.append({
                    "uuid": ioc.id,
                    "type": misp_type,
                    "category": misp_cat,
                    "value": ioc.value,
                    "to_ids": bool(ioc.risk_score >= 60),
                    "comment": f"POSEIDON IOC ({itype}) Risk: {ioc.risk_score} Epistemic: {ioc.epistemic_classification.value}",
                    "timestamp": str(int(ioc.last_seen.timestamp())),
                })

        # 2. Threat Actors
        if actor_ids:
            actor_stmt = select(ThreatActor).where(ThreatActor.id.in_(actor_ids))
            actors = (await session.execute(actor_stmt)).scalars().all()
            for actor in actors:
                attributes.append({
                    "uuid": actor.id,
                    "type": "threat-actor",
                    "category": "Attribution",
                    "value": actor.name,
                    "to_ids": False,
                    "comment": f"Sophistication: {actor.sophistication}, Motivation: {actor.primary_motivation}",
                })
                tags.append({"name": f"misp-galaxy:threat-actor=\"{actor.name}\""})

        # 3. Malware Families
        if malware_ids:
            mal_stmt = select(MalwareFamily).where(MalwareFamily.id.in_(malware_ids))
            malwares = (await session.execute(mal_stmt)).scalars().all()
            for mal in malwares:
                attributes.append({
                    "uuid": mal.id,
                    "type": "comment",
                    "category": "Antivirus detection",
                    "value": f"Malware Family: {mal.name} ({', '.join(mal.malware_types or [])})",
                    "to_ids": False,
                })
                tags.append({"name": f"misp-galaxy:mitre-malware=\"{mal.name}\""})

        # 4. Vulnerabilities
        if vuln_ids:
            vuln_stmt = select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))
            vulns = (await session.execute(vuln_stmt)).scalars().all()
            for v in vulns:
                attributes.append({
                    "uuid": v.id,
                    "type": "vulnerability",
                    "category": "External analysis",
                    "value": v.cve_id,
                    "to_ids": False,
                    "comment": f"CVSS: {v.cvss_score}, CISA KEV: {v.is_cisa_kev}",
                })

        # 5. MITRE ATT&CK Techniques
        if tech_ids:
            tech_stmt = select(AttackTechnique).where(AttackTechnique.id.in_(tech_ids))
            techniques = (await session.execute(tech_stmt)).scalars().all()
            for tech in techniques:
                tags.append({"name": f"misp-galaxy:mitre-attack-pattern=\"{tech.name} - {tech.id}\""})

        # Construct Final MISP Event Payload
        return {
            "Event": {
                "uuid": case.id,
                "info": f"[{case.case_number}] {case.title}",
                "date": case.created_at.strftime("%Y-%m-%d"),
                "threat_level_id": cls.THREAT_LEVEL_MAP.get(case.priority, "2"),
                "analysis": cls.ANALYSIS_MAP.get(case.status, "1"),
                "distribution": cls.DISTRIBUTION_MAP.get(case.tlp, "1"),
                "published": bool(case.status == CaseStatus.CLOSED),
                "Attribute": attributes,
                "Tag": tags,
                "Org": {"name": "POSEIDON Threat Intelligence Platform"},
                "analysis_report": case.findings_markdown or case.description or "",
            }
        }
