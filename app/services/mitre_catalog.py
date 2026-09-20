"""MITRE ATT&CK Enterprise Matrix Seed Catalog and Threat Entity Seeder."""
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import (
    AttackTactic,
    AttackTechnique,
    MalwareFamily,
    ThreatActor,
    Vulnerability,
)
from app.models.enums import TLP, EpistemicClassification, RelationshipType
from app.models.relationship import CanonicalRelationship, compute_relationship_hash

logger = structlog.get_logger(__name__)

# 14 MITRE ATT&CK Enterprise Tactics
TACTICS_DATA = [
    {"id": "TA0043", "name": "Reconnaissance", "order_index": 1, "description": "The adversary is trying to gather information they can use to plan future operations."},
    {"id": "TA0042", "name": "Resource Development", "order_index": 2, "description": "The adversary is trying to establish resources they can use to support operations."},
    {"id": "TA0001", "name": "Initial Access", "order_index": 3, "description": "The adversary is trying to get into your network."},
    {"id": "TA0002", "name": "Execution", "order_index": 4, "description": "The adversary is trying to run malicious code."},
    {"id": "TA0003", "name": "Persistence", "order_index": 5, "description": "The adversary is trying to maintain their foothold."},
    {"id": "TA0004", "name": "Privilege Escalation", "order_index": 6, "description": "The adversary is trying to gain higher-level permissions."},
    {"id": "TA0005", "name": "Defense Evasion", "order_index": 7, "description": "The adversary is trying to avoid being detected."},
    {"id": "TA0006", "name": "Credential Access", "order_index": 8, "description": "The adversary is trying to steal account names and passwords."},
    {"id": "TA0007", "name": "Discovery", "order_index": 9, "description": "The adversary is trying to observe your environment."},
    {"id": "TA0008", "name": "Lateral Movement", "order_index": 10, "description": "The adversary is trying to move through your environment."},
    {"id": "TA0009", "name": "Collection", "order_index": 11, "description": "The adversary is trying to gather data of interest to their goal."},
    {"id": "TA0011", "name": "Command and Control", "order_index": 12, "description": "The adversary is trying to communicate with compromised systems."},
    {"id": "TA0010", "name": "Exfiltration", "order_index": 13, "description": "The adversary is trying to steal data."},
    {"id": "TA0040", "name": "Impact", "order_index": 14, "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data."},
]

# Core Enterprise Techniques
TECHNIQUES_DATA = [
    # Reconnaissance
    {"id": "T1595", "tactic_id": "TA0043", "name": "Active Scanning", "description": "Scanning infrastructure to gather victim reconnaissance telemetry.", "platforms": ["PRE"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1595.001", "tactic_id": "TA0043", "name": "Scanning IP Blocks", "description": "Scanning IPv4 / IPv6 network blocks for open ports and services.", "platforms": ["PRE"], "is_subtechnique": True, "parent_technique_id": "T1595"},
    {"id": "T1592", "tactic_id": "TA0043", "name": "Gather Victim Host Information", "description": "Adversaries may gather information about the victim's hosts.", "platforms": ["PRE"], "is_subtechnique": False, "parent_technique_id": None},

    # Resource Development
    {"id": "T1583", "tactic_id": "TA0042", "name": "Acquire Infrastructure", "description": "Acquiring domains, VPS servers, and IP addresses to stage attacks.", "platforms": ["PRE"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1583.001", "tactic_id": "TA0042", "name": "Domains", "description": "Registering typo-squatted, bulletproof, or aging domains for C2.", "platforms": ["PRE"], "is_subtechnique": True, "parent_technique_id": "T1583"},
    {"id": "T1587", "tactic_id": "TA0042", "name": "Develop Capabilities", "description": "Developing custom malware, exploit payloads, and code signing certs.", "platforms": ["PRE"], "is_subtechnique": False, "parent_technique_id": None},

    # Initial Access
    {"id": "T1566", "tactic_id": "TA0001", "name": "Phishing", "description": "Sending spearphishing messages with malicious attachments or links.", "platforms": ["Linux", "macOS", "Windows"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1566.001", "tactic_id": "TA0001", "name": "Spearphishing Attachment", "description": "Malicious payload attached to spearphishing email.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": True, "parent_technique_id": "T1566"},
    {"id": "T1566.002", "tactic_id": "TA0001", "name": "Spearphishing Link", "description": "Lure link directing victim to credential harvesting or exploit portal.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": True, "parent_technique_id": "T1566"},
    {"id": "T1190", "tactic_id": "TA0001", "name": "Exploit Public-Facing Application", "description": "Exploiting vulnerable internet-facing servers and edge services (CVEs).", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Execution
    {"id": "T1059", "tactic_id": "TA0002", "name": "Command and Scripting Interpreter", "description": "Abusing command line shells and scripting environments.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1059.001", "tactic_id": "TA0002", "name": "PowerShell", "description": "Executing malicious PowerShell cmdlets and scripts in-memory.", "platforms": ["Windows"], "is_subtechnique": True, "parent_technique_id": "T1059"},
    {"id": "T1204", "tactic_id": "TA0002", "name": "User Execution", "description": "Relying on target user interaction to trigger payload execution.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Persistence
    {"id": "T1547", "tactic_id": "TA0003", "name": "Boot or Logon Autostart Execution", "description": "Configuring registry keys and startup folders to maintain persistence.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1078", "tactic_id": "TA0003", "name": "Valid Accounts", "description": "Obtaining and misusing credentials of existing legitimate accounts.", "platforms": ["Windows", "Linux", "macOS", "Cloud"], "is_subtechnique": False, "parent_technique_id": None},

    # Privilege Escalation
    {"id": "T1068", "tactic_id": "TA0004", "name": "Exploitation for Privilege Escalation", "description": "Exploiting software vulnerabilities to elevate process privileges.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1055", "tactic_id": "TA0004", "name": "Process Injection", "description": "Injecting malicious code into running benign processes (e.g. svchost).", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Defense Evasion
    {"id": "T1027", "tactic_id": "TA0005", "name": "Obfuscated Files or Information", "description": "Encrypting or packing payloads to evade static anti-virus signatures.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1070", "tactic_id": "TA0005", "name": "Indicator Removal", "description": "Clearing event logs, timestomping, and deleting staging scripts.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Credential Access
    {"id": "T1003", "tactic_id": "TA0006", "name": "OS Credential Dumping", "description": "Dumping LSASS memory, SAM database, or shadow copies to extract hashes.", "platforms": ["Windows", "Linux"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1555", "tactic_id": "TA0006", "name": "Credentials from Password Stores", "description": "Harvesting credentials stored in web browsers, crypto wallets, and VPNs.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Discovery
    {"id": "T1082", "tactic_id": "TA0007", "name": "System Information Discovery", "description": "Gathering OS version, architecture, patches, and hardware attributes.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1016", "tactic_id": "TA0007", "name": "System Network Configuration Discovery", "description": "Querying local IP addresses, routing tables, and default gateways.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Lateral Movement
    {"id": "T1021", "tactic_id": "TA0008", "name": "Remote Services", "description": "Connecting to remote internal systems using SMB, RDP, SSH, or WinRM.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1021.001", "tactic_id": "TA0008", "name": "Remote Desktop Protocol", "description": "Logging into victim internal servers via exposed RDP services.", "platforms": ["Windows"], "is_subtechnique": True, "parent_technique_id": "T1021"},
    {"id": "T1570", "tactic_id": "TA0008", "name": "Lateral Tool Transfer", "description": "Pivoting and copying attack tools from one internal host to another.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Collection
    {"id": "T1005", "tactic_id": "TA0009", "name": "Data from Local System", "description": "Collecting sensitive files and databases from victim workstations.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1560", "tactic_id": "TA0009", "name": "Archive Collected Data", "description": "Compressing and encrypting staging files prior to exfiltration (ZIP/RAR).", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Command and Control
    {"id": "T1071", "tactic_id": "TA0011", "name": "Application Layer Protocol", "description": "Communicating with C2 servers using standard web or mail protocols.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1071.001", "tactic_id": "TA0011", "name": "Web Protocols", "description": "Using HTTP / HTTPS / WebSockets traffic to blend C2 with standard traffic.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": True, "parent_technique_id": "T1071"},
    {"id": "T1105", "tactic_id": "TA0011", "name": "Ingress Tool Transfer", "description": "Downloading secondary payloads and staging tools from external C2 server.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Exfiltration
    {"id": "T1041", "tactic_id": "TA0010", "name": "Exfiltration Over C2 Channel", "description": "Stealing sensitive data through established Command and Control sessions.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1567", "tactic_id": "TA0010", "name": "Exfiltration Over Web Service", "description": "Exfiltrating sensitive data to cloud storage (Mega, Dropbox, Telegram API).", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},

    # Impact
    {"id": "T1486", "tactic_id": "TA0040", "name": "Data Encrypted for Impact", "description": "Encrypting enterprise storage, VM disks, and backups to extort ransom.", "platforms": ["Windows", "Linux", "macOS"], "is_subtechnique": False, "parent_technique_id": None},
    {"id": "T1490", "tactic_id": "TA0040", "name": "Inhibit System Recovery", "description": "Deleting Volume Shadow Copies (vssadmin delete shadows) and backup catalogs.", "platforms": ["Windows", "Linux"], "is_subtechnique": False, "parent_technique_id": None},
]

# Top Adversary Profiles
ADVERSARIES_DATA = [
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard", "The Dukes"],
        "threat_actor_types": ["nation-state"],
        "primary_motivation": "espionage",
        "sophistication": "advanced",
        "resource_level": "government",
        "origin_country": "RU",
        "description": "Russian state-sponsored cyber espionage syndicate attributed to Russia's Foreign Intelligence Service (SVR). Highly sophisticated, responsible for SolarWinds supply chain compromise and global diplomatic targeting.",
        "confidence": 95.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1566.002", "T1071.001", "T1059.001", "T1078"],
    },
    {
        "name": "Lazarus Group",
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Zinc", "Labyrinth Chollima"],
        "threat_actor_types": ["nation-state", "cybercrime"],
        "primary_motivation": "financial-gain",
        "secondary_motivations": ["espionage", "sabotage"],
        "sophistication": "advanced",
        "resource_level": "government",
        "origin_country": "KP",
        "description": "North Korean state-sponsored cyber operations unit specializing in high-value cryptocurrency heists, SWIFT banking operations, and critical defense industry espionage.",
        "confidence": 90.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1566.001", "T1105", "T1071.001", "T1027"],
    },
    {
        "name": "UNC4393",
        "aliases": ["BlackCat Group", "ALPHV Affiliate Syndicate"],
        "threat_actor_types": ["cybercrime"],
        "primary_motivation": "financial-gain",
        "sophistication": "expert",
        "resource_level": "organization",
        "origin_country": "RU",
        "description": "Highly aggressive Ransomware-as-a-Service (RaaS) affiliate syndicate deploying BlackCat/ALPHV ransomware. Notorious for double extortion, healthcare system disruptions, and credential exploitation.",
        "confidence": 88.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1486", "T1490", "T1021.001", "T1003", "T1190"],
    },
    {
        "name": "Volt Typhoon",
        "aliases": ["Bronze Silhouette", "Vanguard Panda", "Insidious Taurus"],
        "threat_actor_types": ["nation-state"],
        "primary_motivation": "espionage",
        "secondary_motivations": ["sabotage"],
        "sophistication": "advanced",
        "resource_level": "government",
        "origin_country": "CN",
        "description": "State-sponsored cyber espionage group targeting critical infrastructure (energy, communications, maritime ports). Emphasizes living-off-the-land techniques (LotL) and stealth operational relay networks.",
        "confidence": 92.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1078", "T1059", "T1021", "T1190"],
    },
    {
        "name": "FIN7",
        "aliases": ["Carbanak", "Sangria Tempest", "Elbrus"],
        "threat_actor_types": ["cybercrime"],
        "primary_motivation": "financial-gain",
        "sophistication": "expert",
        "resource_level": "organization",
        "origin_country": "RU",
        "description": "Financially motivated cybercrime syndicate responsible for massive point-of-sale intrusions, spearphishing targeting hospitality/retail, and ransomware deployment collaborations.",
        "confidence": 85.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1566.001", "T1059.001", "T1055", "T1105"],
    },
]

# Top Malware Families
MALWARE_DATA = [
    {
        "name": "LummaStealer",
        "aliases": ["LummaC2", "Lumma Infostealer"],
        "malware_types": ["infostealer"],
        "target_platforms": ["windows"],
        "capabilities": ["credential-theft", "crypto-wallet-theft", "anti-analysis", "c2-communication"],
        "description": "Prolific C-based infostealer distributed via cracked software, malicious YouTube links, and fake captcha pages. Exfiltrates browser credentials, session tokens, Discord tokens, and crypto extensions.",
        "confidence": 92.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1555", "T1071.001", "T1027"],
    },
    {
        "name": "Qakbot",
        "aliases": ["QBot", "Pinkslipbot", "QuackBot"],
        "malware_types": ["trojan", "loader", "banking-trojan"],
        "target_platforms": ["windows"],
        "capabilities": ["modular-payload-delivery", "email-thread-hijacking", "credential-theft", "worm-propagation"],
        "description": "Modular banking trojan and initial access loader. Historically leveraged to deliver secondary ransomware strains including BlackCat, MegaCortex, and ProLock.",
        "confidence": 90.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1566.001", "T1059", "T1105"],
    },
    {
        "name": "BlackCat",
        "aliases": ["ALPHV", "Noberus"],
        "malware_types": ["ransomware"],
        "target_platforms": ["windows", "linux", "vmware-esxi"],
        "capabilities": ["encryption", "shadow-copy-deletion", "anti-forensics", "double-extortion"],
        "description": "Sophisticated ransomware written in Rust with support for multiple operating systems including Windows, Linux, and VMware ESXi. Features multi-threaded encryption and recovery suppression.",
        "confidence": 95.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1486", "T1490", "T1021.001"],
    },
    {
        "name": "Cobalt Strike",
        "aliases": ["Beacon"],
        "malware_types": ["c2-framework"],
        "is_family": False,
        "target_platforms": ["windows", "linux"],
        "capabilities": ["process-injection", "c2-communication", "privilege-escalation", "in-memory-execution"],
        "description": "Commercial adversary simulation and penetration testing platform heavily cracked and abused by APTs and cybercriminals for post-exploitation lateral movement and C2.",
        "confidence": 95.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1071.001", "T1055", "T1105"],
    },
    {
        "name": "RedLine Stealer",
        "aliases": ["RedLine"],
        "malware_types": ["infostealer"],
        "target_platforms": ["windows"],
        "capabilities": ["credential-theft", "hardware-inventory", "browser-data-scraping"],
        "description": "Commodity .NET malware sold on underground forums. Scrapes system hardware information, saved logins, auto-complete forms, and credit cards.",
        "confidence": 88.0,
        "tlp": TLP.AMBER,
        "techniques": ["T1555", "T1082", "T1071.001"],
    },
]

# Top Exploited Vulnerabilities
VULNERABILITIES_DATA = [
    {
        "cve_id": "CVE-2024-1709",
        "name": "ConnectWise ScreenConnect Authentication Bypass",
        "description": "Authentication bypass vulnerability allowing unauthenticated remote attackers to create administrative user accounts and execute arbitrary commands.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.975,
        "is_cisa_kev": True,
        "has_public_poc": True,
        "affected_products": ["ConnectWise ScreenConnect < 23.9.8"],
        "techniques": ["T1190", "T1078"],
    },
    {
        "cve_id": "CVE-2024-38077",
        "name": "Windows Remote Desktop Licensing Service RCE (MadLicense)",
        "description": "Remote code execution flaw in Windows Remote Desktop Licensing service through malformed network packets, allowing unauthenticated pre-auth code execution.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.890,
        "is_cisa_kev": False,
        "has_public_poc": True,
        "affected_products": ["Windows Server 2008 through Windows Server 2025"],
        "techniques": ["T1190", "T1068"],
    },
    {
        "cve_id": "CVE-2023-34362",
        "name": "MOVEit Transfer SQL Injection Lead to RCE",
        "description": "SQL injection vulnerability in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain unauthorized access and deploy web shells.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.965,
        "is_cisa_kev": True,
        "has_public_poc": True,
        "affected_products": ["Progress Software MOVEit Transfer"],
        "techniques": ["T1190", "T1505.003"],
    },
]


async def seed_mitre_and_entities(session: AsyncSession) -> dict[str, int]:
    """Idempotently seed the MITRE ATT&CK Matrix and foundational threat entity profiles."""
    stats = {
        "tactics": 0,
        "techniques": 0,
        "actors": 0,
        "malware": 0,
        "vulnerabilities": 0,
        "relationships": 0,
    }

    # 1. Seed Tactics
    for t_data in TACTICS_DATA:
        stmt = select(AttackTactic).where(AttackTactic.id == t_data["id"])
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()
        if not existing:
            tactic = AttackTactic(
                id=t_data["id"],
                name=t_data["name"],
                description=t_data["description"],
                order_index=t_data["order_index"],
            )
            session.add(tactic)
            stats["tactics"] += 1

    await session.flush()

    # 2. Seed Techniques
    for tech_data in TECHNIQUES_DATA:
        stmt = select(AttackTechnique).where(AttackTechnique.id == tech_data["id"])
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()
        if not existing:
            tech = AttackTechnique(
                id=tech_data["id"],
                tactic_id=tech_data["tactic_id"],
                name=tech_data["name"],
                description=tech_data["description"],
                is_subtechnique=tech_data["is_subtechnique"],
                parent_technique_id=tech_data["parent_technique_id"],
                platforms=tech_data["platforms"],
                detection_guidance=f"Monitor telemetry for {tech_data['name']} execution and anomalous child processes.",
                mitre_url=f"https://attack.mitre.org/techniques/{tech_data['id']}/",
            )
            session.add(tech)
            stats["techniques"] += 1

    await session.flush()

    # 3. Seed Threat Actors
    actor_map: dict[str, str] = {}
    for a_data in ADVERSARIES_DATA:
        stmt = select(ThreatActor).where(ThreatActor.name == a_data["name"])
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()
        if not existing:
            actor = ThreatActor(
                name=a_data["name"],
                aliases=a_data["aliases"],
                threat_actor_types=a_data["threat_actor_types"],
                primary_motivation=a_data["primary_motivation"],
                secondary_motivations=a_data.get("secondary_motivations", []),
                sophistication=a_data["sophistication"],
                resource_level=a_data["resource_level"],
                origin_country=a_data["origin_country"],
                description=a_data["description"],
                confidence=a_data["confidence"],
                tlp=a_data["tlp"],
                is_active=True,
                attributes={"targeted_sectors": ["defense", "finance", "energy", "healthcare"]},
            )
            session.add(actor)
            await session.flush()
            actor_map[a_data["name"]] = actor.id
            stats["actors"] += 1
        else:
            actor_map[a_data["name"]] = existing.id

    # 4. Seed Malware Families
    malware_map: dict[str, str] = {}
    for m_data in MALWARE_DATA:
        stmt = select(MalwareFamily).where(MalwareFamily.name == m_data["name"])
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()
        if not existing:
            malware = MalwareFamily(
                name=m_data["name"],
                aliases=m_data["aliases"],
                malware_types=m_data["malware_types"],
                is_family=m_data.get("is_family", True),
                target_platforms=m_data["target_platforms"],
                capabilities=m_data["capabilities"],
                description=m_data["description"],
                confidence=m_data["confidence"],
                tlp=m_data["tlp"],
                is_active=True,
                attributes={"architecture": ["x86", "x64"]},
            )
            session.add(malware)
            await session.flush()
            malware_map[m_data["name"]] = malware.id
            stats["malware"] += 1
        else:
            malware_map[m_data["name"]] = existing.id

    # 5. Seed Vulnerabilities
    vuln_map: dict[str, str] = {}
    for v_data in VULNERABILITIES_DATA:
        stmt = select(Vulnerability).where(Vulnerability.cve_id == v_data["cve_id"])
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()
        if not existing:
            vuln = Vulnerability(
                cve_id=v_data["cve_id"],
                name=v_data["name"],
                description=v_data["description"],
                cvss_score=v_data["cvss_score"],
                cvss_vector=v_data.get("cvss_vector"),
                epss_score=v_data.get("epss_score"),
                is_cisa_kev=v_data["is_cisa_kev"],
                has_public_poc=v_data["has_public_poc"],
                affected_products=v_data["affected_products"],
                published_date=datetime.now(UTC),
                attributes={"cisa_action_due": "2024-03-01"},
            )
            session.add(vuln)
            await session.flush()
            vuln_map[v_data["cve_id"]] = vuln.id
            stats["vulnerabilities"] += 1
        else:
            vuln_map[v_data["cve_id"]] = existing.id

    # 6. Seed Semantic Knowledge Graph Links
    now = datetime.now(UTC)

    # Actor -> Technique links
    for a_data in ADVERSARIES_DATA:
        actor_id = actor_map.get(a_data["name"])
        if not actor_id:
            continue
        for tech_id in a_data.get("techniques", []):
            rel_hash = compute_relationship_hash(actor_id, RelationshipType.USES_TECHNIQUE, tech_id)
            stmt = select(CanonicalRelationship).where(CanonicalRelationship.relationship_hash == rel_hash)
            existing_rel = (await session.execute(stmt)).scalar_one_or_none()
            if not existing_rel:
                rel = CanonicalRelationship(
                    source_id=actor_id,
                    source_type="threat_actor",
                    target_id=tech_id,
                    target_type="attack_technique",
                    relationship_type=RelationshipType.USES_TECHNIQUE,
                    epistemic_classification=EpistemicClassification.ASSESSMENT,
                    confidence=85.0,
                    first_seen=now,
                    last_seen=now,
                    source_name="MITRE ATT&CK CTI Mapping",
                    rationale=f"Adversary '{a_data['name']}' observed utilizing technique '{tech_id}' in reported campaigns.",
                    relationship_hash=rel_hash,
                )
                session.add(rel)
                stats["relationships"] += 1

    # Malware -> Technique links
    for m_data in MALWARE_DATA:
        malware_id = malware_map.get(m_data["name"])
        if not malware_id:
            continue
        for tech_id in m_data.get("techniques", []):
            rel_hash = compute_relationship_hash(malware_id, RelationshipType.USES_TECHNIQUE, tech_id)
            stmt = select(CanonicalRelationship).where(CanonicalRelationship.relationship_hash == rel_hash)
            existing_rel = (await session.execute(stmt)).scalar_one_or_none()
            if not existing_rel:
                rel = CanonicalRelationship(
                    source_id=malware_id,
                    source_type="malware",
                    target_id=tech_id,
                    target_type="attack_technique",
                    relationship_type=RelationshipType.USES_TECHNIQUE,
                    epistemic_classification=EpistemicClassification.OBSERVATION,
                    confidence=90.0,
                    first_seen=now,
                    last_seen=now,
                    source_name="Malware Analysis Sandbox",
                    rationale=f"Malware sample '{m_data['name']}' triggers behavioral pattern mapped to MITRE '{tech_id}'.",
                    relationship_hash=rel_hash,
                )
                session.add(rel)
                stats["relationships"] += 1

    # Threat Actor -> Malware (uses)
    actor_malware_links = [
        ("UNC4393", "BlackCat", "RaaS operator deploying BlackCat encryptor"),
        ("FIN7", "Cobalt Strike", "FIN7 affiliates leveraging Cobalt Strike beacons"),
        ("Lazarus Group", "LummaStealer", "State-sponsored actor adopting commodity infostealers"),
    ]
    for a_name, m_name, reason in actor_malware_links:
        a_id = actor_map.get(a_name)
        m_id = malware_map.get(m_name)
        if a_id and m_id:
            rel_hash = compute_relationship_hash(a_id, RelationshipType.USES, m_id)
            stmt = select(CanonicalRelationship).where(CanonicalRelationship.relationship_hash == rel_hash)
            existing_rel = (await session.execute(stmt)).scalar_one_or_none()
            if not existing_rel:
                rel = CanonicalRelationship(
                    source_id=a_id,
                    source_type="threat_actor",
                    target_id=m_id,
                    target_type="malware",
                    relationship_type=RelationshipType.USES,
                    epistemic_classification=EpistemicClassification.ASSESSMENT,
                    confidence=85.0,
                    first_seen=now,
                    last_seen=now,
                    source_name="Threat Intelligence Bulletin",
                    rationale=reason,
                    relationship_hash=rel_hash,
                )
                session.add(rel)
                stats["relationships"] += 1

    # Threat Actor / Malware -> Vulnerability (exploits)
    if "UNC4393" in actor_map and "CVE-2024-1709" in vuln_map:
        a_id = actor_map["UNC4393"]
        v_id = vuln_map["CVE-2024-1709"]
        rel_hash = compute_relationship_hash(a_id, RelationshipType.EXPLOITS, v_id)
        stmt = select(CanonicalRelationship).where(CanonicalRelationship.relationship_hash == rel_hash)
        if not (await session.execute(stmt)).scalar_one_or_none():
            session.add(CanonicalRelationship(
                source_id=a_id,
                source_type="threat_actor",
                target_id=v_id,
                target_type="vulnerability",
                relationship_type=RelationshipType.EXPLOITS,
                epistemic_classification=EpistemicClassification.OBSERVATION,
                confidence=95.0,
                first_seen=now,
                last_seen=now,
                source_name="CISA KEV Advisory",
                rationale="UNC4393 weaponized ConnectWise ScreenConnect bypass for initial foothold.",
                relationship_hash=rel_hash,
            ))
            stats["relationships"] += 1

    await session.commit()
    logger.info("mitre_catalog_seeded", **stats)
    return stats
