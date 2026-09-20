"""STIX 2.1 Serialization and Export Engine for Poseidon CTI Cases and Intelligence Graph."""
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import AttackTechnique, MalwareFamily, ThreatActor, Vulnerability
from app.models.investigation import InvestigationCase
from app.models.ioc import CanonicalIOC
from app.models.relationship import CanonicalRelationship


class StixExportService:
    """Serializes POSEIDON Investigation Cases, IOCs, and Graph Entities into standard STIX 2.1 JSON Bundles."""

    @classmethod
    def _deterministic_uuid(cls, prefix: str, key: str) -> str:
        """Generate a deterministic UUID v5 for consistent STIX IDs."""
        namespace = uuid.UUID("36d8d9b1-5e5d-4f1a-8c7e-9f3a1b2c3d4e")
        generated = uuid.uuid5(namespace, f"{prefix}:{key}")
        return f"{prefix}--{generated}"

    @classmethod
    def serialize_canonical_ioc(cls, ioc: CanonicalIOC) -> list[dict[str, Any]]:
        """Serialize a single CanonicalIOC into STIX 2.1 SCO and Indicator SDO."""
        stix_objects: list[dict[str, Any]] = []
        itype = ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)
        pattern = ""
        sco_obj: dict[str, Any] | None = None

        if itype == "ipv4":
            sco_id = cls._deterministic_uuid("ipv4-addr", ioc.value)
            sco_obj = {"type": "ipv4-addr", "id": sco_id, "spec_version": "2.1", "value": ioc.value}
            pattern = f"[ipv4-addr:value = '{ioc.value}']"
        elif itype == "ipv6":
            sco_id = cls._deterministic_uuid("ipv6-addr", ioc.value)
            sco_obj = {"type": "ipv6-addr", "id": sco_id, "spec_version": "2.1", "value": ioc.value}
            pattern = f"[ipv6-addr:value = '{ioc.value}']"
        elif itype in ["domain", "fqdn"]:
            sco_id = cls._deterministic_uuid("domain-name", ioc.value)
            sco_obj = {"type": "domain-name", "id": sco_id, "spec_version": "2.1", "value": ioc.value}
            pattern = f"[domain-name:value = '{ioc.value}']"
        elif itype == "url":
            sco_id = cls._deterministic_uuid("url", ioc.value)
            sco_obj = {"type": "url", "id": sco_id, "spec_version": "2.1", "value": ioc.value}
            pattern = f"[url:value = '{ioc.value}']"
        elif "hash" in itype:
            algo = "SHA-256" if "sha256" in itype else ("MD5" if "md5" in itype else "SHA-1")
            sco_id = cls._deterministic_uuid("file", ioc.value)
            sco_obj = {"type": "file", "id": sco_id, "spec_version": "2.1", "hashes": {algo: ioc.value}}
            pattern = f"[file:hashes.'{algo}' = '{ioc.value}']"

        if sco_obj:
            stix_objects.append(sco_obj)

        indicator_id = f"indicator--{ioc.id}"
        indicator_sdo = {
            "type": "indicator",
            "id": indicator_id,
            "spec_version": "2.1",
            "created": ioc.first_seen.isoformat(),
            "modified": ioc.last_seen.isoformat(),
            "name": f"Observable: {ioc.value}",
            "description": f"POSEIDON IOC ({itype}) with risk score {ioc.risk_score}/100",
            "pattern": pattern or f"[{itype}:value = '{ioc.value}']",
            "pattern_type": "stix",
            "valid_from": ioc.first_seen.isoformat(),
            "confidence": int(ioc.confidence_score),
            "indicator_types": ["malicious-activity"],
            "labels": ioc.tags or [],
            "x_poseidon_risk_score": ioc.risk_score,
            "x_poseidon_epistemic_classification": (
                ioc.epistemic_classification.value
                if hasattr(ioc.epistemic_classification, "value")
                else str(ioc.epistemic_classification)
            ),
            "x_poseidon_status": (
                ioc.status.value if hasattr(ioc.status, "value") else str(ioc.status)
            ),
        }
        stix_objects.append(indicator_sdo)
        return stix_objects

    @classmethod
    def serialize_threat_actor(cls, actor: ThreatActor) -> dict[str, Any]:
        """Serialize a ThreatActor into a STIX 2.1 threat-actor SDO."""
        return {
            "type": "threat-actor",
            "id": f"threat-actor--{actor.id}",
            "spec_version": "2.1",
            "created": actor.created_at.isoformat(),
            "modified": actor.updated_at.isoformat(),
            "name": actor.name,
            "aliases": actor.aliases or [],
            "description": actor.description or "",
            "threat_actor_types": actor.threat_actor_types or ["cybercrime"],
            "primary_motivation": actor.primary_motivation or "financial-gain",
            "sophistication": actor.sophistication or "intermediate",
            "resource_level": actor.resource_level or "organization",
            "confidence": int(actor.confidence),
            "country": actor.origin_country,
        }

    @classmethod
    def serialize_malware_family(cls, mal: MalwareFamily) -> dict[str, Any]:
        """Serialize a MalwareFamily into a STIX 2.1 malware SDO."""
        return {
            "type": "malware",
            "id": f"malware--{mal.id}",
            "spec_version": "2.1",
            "created": mal.created_at.isoformat(),
            "modified": mal.updated_at.isoformat(),
            "name": mal.name,
            "is_family": mal.is_family,
            "aliases": mal.aliases or [],
            "description": mal.description or "",
            "malware_types": mal.malware_types or ["trojan"],
            "architecture_execution_envs": mal.target_platforms or [],
        }

    @classmethod
    async def export_case_as_stix_bundle(
        cls,
        session: AsyncSession,
        case: InvestigationCase,
    ) -> dict[str, Any]:
        """Convert an entire investigation case dossier into a valid STIX 2.1 JSON Bundle."""
        stix_objects: list[dict[str, Any]] = []
        object_refs: list[str] = []
        entity_id_to_stix_id: dict[str, str] = {}

        # 1. Gather all entity IDs referenced in case
        ioc_ids: list[str] = []
        actor_ids: list[str] = []
        malware_ids: list[str] = []
        vuln_ids: list[str] = []
        technique_ids: list[str] = []

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
                technique_ids.append(eid)

        # 2. Serialize IOCs & Observables
        if ioc_ids:
            ioc_stmt = select(CanonicalIOC).where(CanonicalIOC.id.in_(ioc_ids))
            iocs = (await session.execute(ioc_stmt)).scalars().all()
            for ioc in iocs:
                pattern = ""
                sco_obj: dict[str, Any] | None = None
                itype = ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)

                if itype == "ipv4":
                    sco_id = cls._deterministic_uuid("ipv4-addr", ioc.value)
                    sco_obj = {"type": "ipv4-addr", "id": sco_id, "spec_version": "2.1", "value": ioc.value}
                    pattern = f"[ipv4-addr:value = '{ioc.value}']"
                elif itype == "ipv6":
                    sco_id = cls._deterministic_uuid("ipv6-addr", ioc.value)
                    sco_obj = {"type": "ipv6-addr", "id": sco_id, "spec_version": "2.1", "value": ioc.value}
                    pattern = f"[ipv6-addr:value = '{ioc.value}']"
                elif itype in ["domain", "fqdn"]:
                    sco_id = cls._deterministic_uuid("domain-name", ioc.value)
                    sco_obj = {"type": "domain-name", "id": sco_id, "spec_version": "2.1", "value": ioc.value}
                    pattern = f"[domain-name:value = '{ioc.value}']"
                elif itype == "url":
                    sco_id = cls._deterministic_uuid("url", ioc.value)
                    sco_obj = {"type": "url", "id": sco_id, "spec_version": "2.1", "value": ioc.value}
                    pattern = f"[url:value = '{ioc.value}']"
                elif "hash" in itype:
                    algo = "SHA-256" if "sha256" in itype else ("MD5" if "md5" in itype else "SHA-1")
                    sco_id = cls._deterministic_uuid("file", ioc.value)
                    sco_obj = {"type": "file", "id": sco_id, "spec_version": "2.1", "hashes": {algo: ioc.value}}
                    pattern = f"[file:hashes.'{algo}' = '{ioc.value}']"

                if sco_obj:
                    stix_objects.append(sco_obj)
                    object_refs.append(sco_obj["id"])

                indicator_id = f"indicator--{ioc.id}"
                entity_id_to_stix_id[ioc.id] = indicator_id
                entity_id_to_stix_id[ioc.value] = indicator_id

                indicator_sdo = {
                    "type": "indicator",
                    "id": indicator_id,
                    "spec_version": "2.1",
                    "created": ioc.first_seen.isoformat(),
                    "modified": ioc.last_seen.isoformat(),
                    "name": f"Observable: {ioc.value}",
                    "description": f"POSEIDON IOC ({itype}) with risk score {ioc.risk_score}/100",
                    "pattern": pattern or f"[{itype}:value = '{ioc.value}']",
                    "pattern_type": "stix",
                    "valid_from": ioc.first_seen.isoformat(),
                    "confidence": int(ioc.confidence_score),
                    "indicator_types": ["malicious-activity"],
                    "labels": ioc.tags or [],
                    "x_poseidon_risk_score": ioc.risk_score,
                    "x_poseidon_epistemic_classification": ioc.epistemic_classification.value,
                    "x_poseidon_status": ioc.status.value,
                }
                stix_objects.append(indicator_sdo)
                object_refs.append(indicator_id)

        # 3. Serialize Threat Actors
        if actor_ids:
            actor_stmt = select(ThreatActor).where(ThreatActor.id.in_(actor_ids))
            actors = (await session.execute(actor_stmt)).scalars().all()
            for actor in actors:
                stix_id = f"threat-actor--{actor.id}"
                entity_id_to_stix_id[actor.id] = stix_id
                entity_id_to_stix_id[actor.name] = stix_id

                actor_sdo = {
                    "type": "threat-actor",
                    "id": stix_id,
                    "spec_version": "2.1",
                    "created": actor.created_at.isoformat(),
                    "modified": actor.updated_at.isoformat(),
                    "name": actor.name,
                    "aliases": actor.aliases or [],
                    "description": actor.description or "",
                    "threat_actor_types": actor.threat_actor_types or ["cybercrime"],
                    "primary_motivation": actor.primary_motivation or "financial-gain",
                    "sophistication": actor.sophistication or "intermediate",
                    "resource_level": actor.resource_level or "organization",
                    "confidence": int(actor.confidence),
                    "country": actor.origin_country,
                }
                stix_objects.append(actor_sdo)
                object_refs.append(stix_id)

        # 4. Serialize Malware Families
        if malware_ids:
            mal_stmt = select(MalwareFamily).where(MalwareFamily.id.in_(malware_ids))
            malwares = (await session.execute(mal_stmt)).scalars().all()
            for mal in malwares:
                stix_id = f"malware--{mal.id}"
                entity_id_to_stix_id[mal.id] = stix_id
                entity_id_to_stix_id[mal.name] = stix_id

                mal_sdo = {
                    "type": "malware",
                    "id": stix_id,
                    "spec_version": "2.1",
                    "created": mal.created_at.isoformat(),
                    "modified": mal.updated_at.isoformat(),
                    "name": mal.name,
                    "is_family": mal.is_family,
                    "aliases": mal.aliases or [],
                    "description": mal.description or "",
                    "malware_types": mal.malware_types or ["trojan"],
                    "architecture_execution_envs": mal.target_platforms or [],
                    "capabilities": mal.capabilities or [],
                    "confidence": int(mal.confidence),
                }
                stix_objects.append(mal_sdo)
                object_refs.append(stix_id)

        # 5. Serialize ATT&CK Techniques
        if technique_ids:
            tech_stmt = select(AttackTechnique).where(AttackTechnique.id.in_(technique_ids))
            techniques = (await session.execute(tech_stmt)).scalars().all()
            for tech in techniques:
                stix_id = cls._deterministic_uuid("attack-pattern", tech.id)
                entity_id_to_stix_id[tech.id] = stix_id

                tech_sdo = {
                    "type": "attack-pattern",
                    "id": stix_id,
                    "spec_version": "2.1",
                    "name": tech.name,
                    "description": tech.description or "",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tech.id,
                            "url": tech.mitre_url or f"https://attack.mitre.org/techniques/{tech.id}/",
                        }
                    ],
                }
                stix_objects.append(tech_sdo)
                object_refs.append(stix_id)

        # 6. Serialize Vulnerabilities
        if vuln_ids:
            vuln_stmt = select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))
            vulns = (await session.execute(vuln_stmt)).scalars().all()
            for v in vulns:
                stix_id = cls._deterministic_uuid("vulnerability", v.cve_id)
                entity_id_to_stix_id[v.id] = stix_id
                entity_id_to_stix_id[v.cve_id] = stix_id

                vuln_sdo = {
                    "type": "vulnerability",
                    "id": stix_id,
                    "spec_version": "2.1",
                    "name": v.cve_id,
                    "description": v.description or v.name or "",
                    "external_references": [
                        {
                            "source_name": "cve",
                            "external_id": v.cve_id,
                            "url": f"https://nvd.nist.gov/vuln/detail/{v.cve_id}",
                        }
                    ],
                    "x_poseidon_cvss": v.cvss_score,
                    "x_poseidon_cisa_kev": v.is_cisa_kev,
                }
                stix_objects.append(vuln_sdo)
                object_refs.append(stix_id)

        # 7. Serialize Relationships between included entities
        all_collected_ids = list(entity_id_to_stix_id.keys())
        if len(all_collected_ids) >= 2:
            rel_stmt = select(CanonicalRelationship).where(
                CanonicalRelationship.source_id.in_(all_collected_ids),
                CanonicalRelationship.target_id.in_(all_collected_ids),
            )
            relationships = (await session.execute(rel_stmt)).scalars().all()
            for rel in relationships:
                s_ref = entity_id_to_stix_id.get(rel.source_id)
                t_ref = entity_id_to_stix_id.get(rel.target_id)
                if s_ref and t_ref:
                    rel_sro = {
                        "type": "relationship",
                        "id": f"relationship--{rel.id}",
                        "spec_version": "2.1",
                        "created": rel.created_at.isoformat(),
                        "modified": rel.updated_at.isoformat(),
                        "relationship_type": rel.relationship_type.value if hasattr(rel.relationship_type, "value") else str(rel.relationship_type),
                        "source_ref": s_ref,
                        "target_ref": t_ref,
                        "confidence": int(rel.confidence),
                        "description": rel.rationale or "",
                        "x_poseidon_epistemic_classification": rel.epistemic_classification.value,
                    }
                    stix_objects.append(rel_sro)
                    object_refs.append(rel_sro["id"])

        # 8. Create Root STIX Report SDO
        report_sdo = {
            "type": "report",
            "id": f"report--{case.id}",
            "spec_version": "2.1",
            "created": case.created_at.isoformat(),
            "modified": case.updated_at.isoformat(),
            "name": f"[{case.case_number}] {case.title}",
            "description": case.findings_markdown or case.description or "Poseidon CTI Investigation Dossier",
            "published": (case.closed_at or case.updated_at).isoformat(),
            "report_types": ["threat-report", "investigation"],
            "object_refs": object_refs,
            "labels": case.tags or ["cti", "investigation"],
            "x_poseidon_case_number": case.case_number,
            "x_poseidon_priority": case.priority.value,
            "x_poseidon_status": case.status.value,
            "x_poseidon_tlp": case.tlp.value,
        }
        stix_objects.insert(0, report_sdo)

        # 9. Return Final STIX 2.1 Bundle
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": stix_objects,
        }
