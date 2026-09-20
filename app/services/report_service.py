"""Strategic Intelligence Bulletins & Reports Service Engine."""
import csv
import io
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.entities import AttackTechnique, Campaign, MalwareFamily, ThreatActor, Vulnerability
from app.models.enums import PAP, TLP, EpistemicClassification, ReportStatus, ReportType
from app.models.investigation import CaseNote, InvestigationCase
from app.models.ioc import CanonicalIOC
from app.models.report import Report, ReportObject
from app.schemas.report import GenerateReportFromCaseRequest, ReportCreate, ReportObjectCreate, ReportUpdate


class ReportService:
    """Orchestrates intelligence report generation, case compilation, publishing, and multi-format dissemination."""

    @classmethod
    async def generate_report_number(cls, session: AsyncSession) -> str:
        """Generate an incremental, audit-friendly report identifier: POS-REP-{year}-{seq:04d}."""
        year = datetime.now(UTC).year
        prefix = f"POS-REP-{year}-"
        count_stmt = select(func.count(Report.id)).where(Report.report_number.like(f"{prefix}%"))
        count = (await session.execute(count_stmt)).scalar() or 0
        seq = count + 1
        return f"{prefix}{seq:04d}"

    @classmethod
    async def create_report(
        cls,
        session: AsyncSession,
        report_in: ReportCreate,
        author_id: str | None = None,
    ) -> Report:
        """Create a new CTI report with linked objects."""
        report_number = await cls.generate_report_number(session)
        now = datetime.now(UTC)

        report = Report(
            report_number=report_number,
            title=report_in.title,
            report_type=report_in.report_type,
            status=report_in.status,
            tlp=report_in.tlp,
            pap=report_in.pap,
            confidence=report_in.confidence,
            summary=report_in.summary,
            content_markdown=report_in.content_markdown,
            published_at=now if report_in.status == ReportStatus.PUBLISHED else None,
            author_id=author_id,
            author_name=report_in.author_name or "Poseidon CTI Lab",
            investigation_id=report_in.investigation_id,
            tags=report_in.tags,
            mitre_attack=report_in.mitre_attack,
            targeted_sectors=report_in.targeted_sectors,
            targeted_countries=report_in.targeted_countries,
            recommendations=report_in.recommendations,
        )
        session.add(report)
        await session.flush()

        # Add linked objects
        for obj_in in report_in.objects:
            obj = ReportObject(
                report_id=report.id,
                entity_type=obj_in.entity_type,
                entity_id=obj_in.entity_id,
                epistemic_classification=obj_in.epistemic_classification,
                role_in_report=obj_in.role_in_report,
                label=obj_in.label,
            )
            session.add(obj)

        await session.commit()
        await session.refresh(report)
        return report

    @classmethod
    async def get_report(cls, session: AsyncSession, report_id: str) -> Report | None:
        """Fetch report by ID with eager loading of attached objects."""
        stmt = (
            select(Report)
            .where(Report.id == report_id)
            .options(selectinload(Report.objects))
        )
        res = await session.execute(stmt)
        return res.scalars().first()

    @classmethod
    async def list_reports(
        cls,
        session: AsyncSession,
        report_type: ReportType | None = None,
        status: ReportStatus | None = None,
        tlp: TLP | None = None,
        sector: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Report], int]:
        """List reports with multi-criteria filtering and pagination."""
        query = select(Report).options(selectinload(Report.objects))

        if report_type:
            query = query.where(Report.report_type == report_type)
        if status:
            query = query.where(Report.status == status)
        if tlp:
            query = query.where(Report.tlp == tlp)
        if search:
            search_pattern = f"%{search}%"
            query = query.where(
                or_(
                    Report.title.ilike(search_pattern),
                    Report.report_number.ilike(search_pattern),
                    Report.summary.ilike(search_pattern),
                )
            )

        # Count total
        count_stmt = select(func.count()).select_from(query.subquery())
        total = (await session.execute(count_stmt)).scalar() or 0

        # Order and paginate
        query = query.order_by(Report.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await session.execute(query)
        items = list(result.scalars().all())

        # Sector post-filter if specified
        if sector:
            items = [r for r in items if sector.lower() in [s.lower() for s in (r.targeted_sectors or [])]]
            total = len(items)

        return items, total

    @classmethod
    async def update_report(
        cls,
        session: AsyncSession,
        report_id: str,
        update_in: ReportUpdate,
    ) -> Report | None:
        """Update report fields and optionally sync linked objects."""
        report = await cls.get_report(session, report_id)
        if not report:
            return None

        update_data = update_in.model_dump(exclude_unset=True)
        objects_data = update_data.pop("objects", None)

        for field, value in update_data.items():
            setattr(report, field, value)

        if report.status == ReportStatus.PUBLISHED and not report.published_at:
            report.published_at = datetime.now(UTC)

        if objects_data is not None:
            # Replace existing objects
            await session.execute(delete(ReportObject).where(ReportObject.report_id == report_id))
            for obj_in in objects_data:
                obj = ReportObject(
                    report_id=report.id,
                    entity_type=obj_in["entity_type"],
                    entity_id=obj_in["entity_id"],
                    epistemic_classification=obj_in.get("epistemic_classification", EpistemicClassification.FACT),
                    role_in_report=obj_in.get("role_in_report", "Observable"),
                    label=obj_in.get("label", ""),
                )
                session.add(obj)

        await session.commit()
        await session.refresh(report)
        return report

    @classmethod
    async def publish_report(cls, session: AsyncSession, report_id: str) -> Report | None:
        """Mark a report as officially PUBLISHED and stamp timestamp."""
        report = await cls.get_report(session, report_id)
        if not report:
            return None

        report.status = ReportStatus.PUBLISHED
        report.published_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(report)
        return report

    @classmethod
    async def delete_report(cls, session: AsyncSession, report_id: str) -> bool:
        """Permanently delete a report and associated objects."""
        report = await cls.get_report(session, report_id)
        if not report:
            return False

        await session.delete(report)
        await session.commit()
        return True

    @classmethod
    async def generate_from_investigation(
        cls,
        session: AsyncSession,
        request: GenerateReportFromCaseRequest,
        author_id: str | None = None,
    ) -> Report:
        """Auto-generate an intelligence bulletin draft from an Investigation Case with epistemic separation."""
        case_stmt = (
            select(InvestigationCase)
            .where(InvestigationCase.id == request.case_id)
            .options(selectinload(InvestigationCase.notes))
        )
        case_res = await session.execute(case_stmt)
        case = case_res.scalars().first()
        if not case:
            raise ValueError(f"Investigation Case {request.case_id} not found.")

        # 1. Categorize Notes and Epistemic Evidence
        facts: list[str] = []
        observations: list[str] = []
        correlations: list[str] = []
        assessments: list[str] = []
        hypotheses: list[str] = []

        for note in case.notes:
            content = f"[{note.created_at.strftime('%Y-%m-%d')}] {note.content}"
            if note.epistemic_classification == EpistemicClassification.FACT:
                facts.append(content)
            elif note.epistemic_classification == EpistemicClassification.OBSERVATION:
                observations.append(content)
            elif note.epistemic_classification == EpistemicClassification.CORRELATION:
                correlations.append(content)
            elif note.epistemic_classification == EpistemicClassification.ASSESSMENT:
                assessments.append(content)
            elif note.epistemic_classification == EpistemicClassification.HYPOTHESIS:
                hypotheses.append(content)

        # 2. Extract referenced observables and entities
        report_objects_create: list[ReportObjectCreate] = []
        ioc_summary_table: list[dict[str, Any]] = []

        ioc_ids = [ref.get("entity_id") for ref in (case.entity_references or []) if ref.get("entity_type") in ["ioc", "canonical_ioc"]]
        if ioc_ids:
            ioc_stmt = select(CanonicalIOC).where(CanonicalIOC.id.in_(ioc_ids))
            iocs = (await session.execute(ioc_stmt)).scalars().all()
            for ioc in iocs:
                report_objects_create.append(
                    ReportObjectCreate(
                        entity_type="ioc",
                        entity_id=ioc.id,
                        epistemic_classification=EpistemicClassification.FACT,
                        role_in_report="Network Observable / Indicator",
                        label=f"{ioc.ioc_type.value}: {ioc.normalized_value}",
                    )
                )
                ioc_summary_table.append({
                    "type": ioc.ioc_type.value,
                    "value": ioc.normalized_value,
                    "risk": ioc.risk_score,
                    "confidence": f"{ioc.confidence_score}%",
                    "status": ioc.status.value,
                })

        # Add other entities if present
        for ref in (case.entity_references or []):
            etype = ref.get("entity_type")
            eid = ref.get("entity_id")
            if etype not in ["ioc", "canonical_ioc"] and eid:
                report_objects_create.append(
                    ReportObjectCreate(
                        entity_type=etype,
                        entity_id=eid,
                        epistemic_classification=EpistemicClassification.CORRELATION,
                        role_in_report=ref.get("role", "Correlated Threat Entity"),
                        label=ref.get("label", f"{etype}:{eid[:8]}"),
                    )
                )

        # 3. Assemble Structured Markdown Content
        title = request.title_override or f"CTI Intelligence Bulletin: {case.title}"
        tlp = request.tlp or case.tlp
        pap = request.pap or PAP.AMBER

        markdown_lines = [
            f"# {title}",
            "",
            f"**Report Classification**: TLP:{tlp.value} | PAP:{pap.value} | **Case Reference**: {case.case_number}",
            f"**Published by**: Poseidon Threat Intelligence Unit | **Priority**: {case.priority.value}",
            "",
            "## 1. Executive Summary",
            case.description or "This intelligence bulletin provides structured threat intelligence compiled from operational investigation telemetry.",
            "",
            "## 2. Epistemic Evidence Matrix (Prompt 03 Standard)",
            "POSEIDON enforces strict epistemic demarcation between factual telemetry and analytical working hypotheses.",
            "",
            "### 2.1 Facts (Verifiable Telemetry & Cryptographic Artifacts)",
        ]

        if facts:
            for f in facts:
                markdown_lines.append(f"- {f}")
        else:
            markdown_lines.append("- *No discrete fact notes recorded.*")

        markdown_lines.extend([
            "",
            "### 2.2 Observations (Third-Party Feed Reports & External Claims)",
        ])
        if observations:
            for o in observations:
                markdown_lines.append(f"- {o}")
        else:
            markdown_lines.append("- *No third-party feed observations recorded.*")

        markdown_lines.extend([
            "",
            "### 2.3 Correlations (Deterministic Entity & Infrastructure Overlaps)",
        ])
        if correlations:
            for c in correlations:
                markdown_lines.append(f"- {c}")
        else:
            markdown_lines.append("- *No automated graph correlations flagged.*")

        markdown_lines.extend([
            "",
            "### 2.4 Assessments (Analytical Interpretations)",
        ])
        if assessments:
            for a in assessments:
                markdown_lines.append(f"- {a}")
        else:
            markdown_lines.append("- *No formal analyst assessments recorded.*")

        markdown_lines.extend([
            "",
            "### 2.5 Hypotheses & Working Theories (Evidence FOR vs AGAINST)",
        ])
        if hypotheses:
            for h in hypotheses:
                markdown_lines.append(f"- {h}")
        else:
            markdown_lines.append("- *No working hypotheses registered.*")

        markdown_lines.extend([
            "",
            "## 3. Threat Indicators & Observables",
            "| Type | Observable Value | Risk Score | Confidence | Status |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        if ioc_summary_table:
            for row in ioc_summary_table:
                markdown_lines.append(f"| `{row['type']}` | `{row['value']}` | {row['risk']}/100 | {row['confidence']} | {row['status']} |")
        else:
            markdown_lines.append("| *N/A* | *No indicators directly linked* | - | - | - |")

        markdown_lines.extend([
            "",
            "## 4. Mitigation & Recommended Defensive Actions",
            "1. Block or sinkhole flagged indicators at border edge gateways and EDR agents.",
            "2. Audit network telemetry for callback beacons matching observed temporal patterns.",
            "3. Disseminate bulletin to internal incident response and threat hunting teams under specified TLP constraints.",
        ])

        content_markdown = "\n".join(markdown_lines)
        summary = (
            case.description[:250] + "..." if len(case.description) > 250 else case.description
        ) or f"Strategic intelligence analysis synthesized from case {case.case_number}."

        report_in = ReportCreate(
            title=title,
            report_type=request.report_type,
            status=ReportStatus.DRAFT,
            tlp=tlp,
            pap=pap,
            confidence=80,
            summary=summary,
            content_markdown=content_markdown,
            author_name="Poseidon CTI Lab",
            investigation_id=case.id,
            tags=list(set((case.tags or []) + ["bulletin", "investigation-export"])),
            mitre_attack=[],
            targeted_sectors=["Financial Services", "Technology", "Critical Infrastructure"],
            targeted_countries=["US", "BR", "EU"],
            recommendations=[
                "Deploy network firewall blocking for corroborated high-risk indicators.",
                "Inspect historical DNS logs for resolution to identified C2 infrastructure.",
                "Review relevant MITRE ATT&CK detection coverage.",
            ],
            objects=report_objects_create,
        )

        return await cls.create_report(session, report_in, author_id=author_id)

    @classmethod
    async def export_stix_bundle(cls, session: AsyncSession, report_id: str) -> dict[str, Any]:
        """Serializes Report into a compliant STIX 2.1 JSON Bundle with Report SDO and linked indicators."""
        report = await cls.get_report(session, report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found.")

        marking_id = f"marking-definition--{uuid.uuid5(uuid.NAMESPACE_DNS, f'tlp:{report.tlp.value.lower()}')}"
        marking_def = {
            "type": "marking-definition",
            "id": marking_id,
            "spec_version": "2.1",
            "created": "2026-01-01T00:00:00.000Z",
            "definition_type": "tlp",
            "name": f"TLP:{report.tlp.value}",
            "definition": {"tlp": report.tlp.value.lower()},
        }

        identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'poseidon.threat.intelligence')}"
        identity_sdo = {
            "type": "identity",
            "id": identity_id,
            "spec_version": "2.1",
            "name": report.author_name or "Poseidon CTI Lab",
            "identity_class": "organization",
            "sectors": report.targeted_sectors or ["security"],
        }

        stix_objects: list[dict[str, Any]] = [marking_def, identity_sdo]
        object_refs: list[str] = [identity_id]

        # Convert linked report objects to STIX SDOs
        ioc_ids = [o.entity_id for o in report.objects if o.entity_type == "ioc"]
        if ioc_ids:
            ioc_stmt = select(CanonicalIOC).where(CanonicalIOC.id.in_(ioc_ids))
            iocs = (await session.execute(ioc_stmt)).scalars().all()
            for ioc in iocs:
                stix_indicator_id = f"indicator--{ioc.id}"
                stix_indicator = {
                    "type": "indicator",
                    "id": stix_indicator_id,
                    "spec_version": "2.1",
                    "created": ioc.created_at.isoformat(),
                    "modified": ioc.updated_at.isoformat(),
                    "name": f"{ioc.ioc_type.value}: {ioc.normalized_value}",
                    "description": f"Poseidon CTI Indicator with Risk {ioc.risk_score}/100",
                    "pattern": f"[{ioc.ioc_type.value.lower()}:value = '{ioc.normalized_value}']",
                    "pattern_type": "stix",
                    "valid_from": ioc.first_seen.isoformat(),
                    "confidence": int(ioc.confidence_score),
                    "labels": ioc.tags or ["malicious-activity"],
                    "object_marking_refs": [marking_id],
                }
                stix_objects.append(stix_indicator)
                object_refs.append(stix_indicator_id)

        # STIX Report SDO
        report_sdo = {
            "type": "report",
            "id": f"report--{report.id}",
            "spec_version": "2.1",
            "created": report.created_at.isoformat(),
            "modified": report.updated_at.isoformat(),
            "name": report.title,
            "description": report.summary or report.title,
            "published": (report.published_at or report.created_at).isoformat(),
            "report_types": [report.report_type.value.lower()],
            "object_refs": object_refs,
            "confidence": report.confidence,
            "labels": report.tags or ["threat-bulletin"],
            "object_marking_refs": [marking_id],
            "created_by_ref": identity_id,
            "x_poseidon_report_number": report.report_number,
            "x_poseidon_pap": report.pap.value,
            "x_poseidon_sectors": report.targeted_sectors,
            "x_poseidon_countries": report.targeted_countries,
        }
        stix_objects.append(report_sdo)

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": stix_objects,
        }

    @classmethod
    async def export_html_briefing(cls, session: AsyncSession, report_id: str) -> str:
        """Generate a clean, print-ready HTML Cyber Threat Intelligence Briefing."""
        report = await cls.get_report(session, report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found.")

        tlp_colors = {
            TLP.CLEAR: "#94a3b8",
            TLP.GREEN: "#22c55e",
            TLP.AMBER: "#f59e0b",
            TLP.AMBER_STRICT: "#f97316",
            TLP.RED: "#ef4444",
        }
        tlp_color = tlp_colors.get(report.tlp, "#f59e0b")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>[{report.report_number}] {report.title}</title>
  <style>
    @page {{ size: A4; margin: 15mm; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
      line-height: 1.6;
      color: #0f172a;
      background: #ffffff;
      margin: 0;
      padding: 24px;
    }}
    .banner {{
      background: {tlp_color};
      color: #ffffff;
      text-align: center;
      font-weight: 700;
      font-size: 13px;
      letter-spacing: 0.1em;
      padding: 6px;
      text-transform: uppercase;
      margin-bottom: 20px;
    }}
    .header {{
      border-bottom: 2px solid #0f172a;
      padding-bottom: 16px;
      margin-bottom: 24px;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-top: 12px;
      font-size: 12px;
    }}
    .meta-item strong {{ display: block; color: #64748b; font-size: 10px; text-transform: uppercase; }}
    h1 {{ font-size: 24px; margin: 0 0 8px 0; color: #080c14; }}
    h2 {{ font-size: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 24px; color: #1e293b; }}
    .summary-box {{
      background: #f8fafc;
      border-left: 4px solid #38bdf8;
      padding: 16px;
      margin: 16px 0;
      font-size: 14px;
    }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }}
    th, td {{ padding: 8px 10px; border: 1px solid #cbd5e1; text-align: left; }}
    th {{ background: #f1f5f9; font-weight: 600; }}
    .tag {{ display: inline-block; background: #e0f2fe; color: #0369a1; padding: 2px 6px; border-radius: 4px; font-size: 11px; margin: 2px; }}
    .footer {{ margin-top: 40px; padding-top: 12px; border-top: 1px solid #cbd5e1; font-size: 10px; color: #64748b; text-align: center; }}
    @media print {{
      body {{ padding: 0; }}
      .no-print {{ display: none; }}
    }}
  </style>
</head>
<body>
  <div class="banner">CLASSIFICATION: TLP:{report.tlp.value} // PAP:{report.pap.value}</div>
  <div class="header">
    <h1>{report.title}</h1>
    <div class="meta-grid">
      <div class="meta-item"><strong>Report ID</strong>{report.report_number}</div>
      <div class="meta-item"><strong>Type</strong>{report.report_type.value}</div>
      <div class="meta-item"><strong>Published</strong>{report.published_at.strftime('%Y-%m-%d %H:%M UTC') if report.published_at else 'DRAFT'}</div>
      <div class="meta-item"><strong>Author</strong>{report.author_name}</div>
    </div>
  </div>

  <h2>1. Executive Summary</h2>
  <div class="summary-box">
    {report.summary or 'No executive summary provided.'}
  </div>

  <h2>2. Technical Threat Narrative</h2>
  <div>
    <pre style="white-space: pre-wrap; font-family: inherit; font-size: 13px;">{report.content_markdown}</pre>
  </div>

  <h2>3. Associated Observables & Indicators ({len(report.objects)})</h2>
  <table>
    <thead>
      <tr>
        <th>Entity Type</th>
        <th>Label / Identifier</th>
        <th>Epistemic Certainty</th>
        <th>Role in Report</th>
      </tr>
    </thead>
    <tbody>
      {"".join(f"<tr><td><code>{obj.entity_type}</code></td><td><strong>{obj.label}</strong></td><td>{obj.epistemic_classification.value}</td><td>{obj.role_in_report}</td></tr>" for obj in report.objects) if report.objects else "<tr><td colspan='4'>No entities directly linked.</td></tr>"}
    </tbody>
  </table>

  <h2>4. Dissemination & Mitigation Recommendations</h2>
  <ul>
    {"".join(f"<li>{rec}</li>" for rec in (report.recommendations or [])) if report.recommendations else "<li>Enforce standard edge firewall and endpoint EDR blocking.</li>"}
  </ul>

  <div class="footer">
    PRODUCED BY POSEIDON CYBER THREAT INTELLIGENCE PLATFORM — STRICT ADHERENCE TO TLP:{report.tlp.value} DISSEMINATION PROTOCOL
  </div>
</body>
</html>"""
        return html

    @classmethod
    async def export_markdown(cls, session: AsyncSession, report_id: str) -> str:
        """Produce clean, frontmatter-enhanced Markdown report."""
        report = await cls.get_report(session, report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found.")

        pub_str = report.published_at.isoformat() if report.published_at else "DRAFT"
        frontmatter = f"""---
title: "{report.title}"
report_number: "{report.report_number}"
type: "{report.report_type.value}"
status: "{report.status.value}"
tlp: "{report.tlp.value}"
pap: "{report.pap.value}"
confidence: {report.confidence}
author: "{report.author_name}"
published_at: "{pub_str}"
tags: {report.tags}
sectors: {report.targeted_sectors}
countries: {report.targeted_countries}
---

"""
        return frontmatter + report.content_markdown

    @classmethod
    async def export_csv(cls, session: AsyncSession, report_id: str) -> str:
        """Generate a CSV indicator table of all linked observables."""
        report = await cls.get_report(session, report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found.")

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["report_number", "report_title", "entity_type", "entity_id", "label", "epistemic_classification", "role_in_report"])

        for obj in report.objects:
            writer.writerow([
                report.report_number,
                report.title,
                obj.entity_type,
                obj.entity_id,
                obj.label,
                obj.epistemic_classification.value,
                obj.role_in_report,
            ])

        return output.getvalue()
