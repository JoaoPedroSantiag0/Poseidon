"""Role-Based Access Control (RBAC) Permissions Matrix."""

from app.models.enums import UserRole

# Canonical Permissions
PERM_IOC_READ = "ioc:read"
PERM_IOC_WRITE = "ioc:write"
PERM_ENRICH_EXECUTE = "enrich:execute"
PERM_INVESTIGATION_READ = "investigation:read"
PERM_INVESTIGATION_WRITE = "investigation:write"
PERM_RISK_OVERRIDE = "risk:override"
PERM_SOURCE_CONFIG = "source:config"
PERM_AUDIT_READ = "audit:read"
PERM_STIX_EXPORT = "stix:export"
PERM_REPORT_READ = "report:read"
PERM_REPORT_WRITE = "report:write"

# Role to Permissions Mapping
ROLE_PERMISSIONS: dict[UserRole, set[str]] = {
    UserRole.ADMIN: {
        PERM_IOC_READ,
        PERM_IOC_WRITE,
        PERM_ENRICH_EXECUTE,
        PERM_INVESTIGATION_READ,
        PERM_INVESTIGATION_WRITE,
        PERM_RISK_OVERRIDE,
        PERM_SOURCE_CONFIG,
        PERM_AUDIT_READ,
        PERM_STIX_EXPORT,
        PERM_REPORT_READ,
        PERM_REPORT_WRITE,
    },
    UserRole.CTI_ANALYST: {
        PERM_IOC_READ,
        PERM_IOC_WRITE,
        PERM_ENRICH_EXECUTE,
        PERM_INVESTIGATION_READ,
        PERM_INVESTIGATION_WRITE,
        PERM_RISK_OVERRIDE,
        PERM_STIX_EXPORT,
        PERM_REPORT_READ,
        PERM_REPORT_WRITE,
    },
    UserRole.THREAT_HUNTER: {
        PERM_IOC_READ,
        PERM_IOC_WRITE,
        PERM_ENRICH_EXECUTE,
        PERM_INVESTIGATION_READ,
        PERM_INVESTIGATION_WRITE,
        PERM_STIX_EXPORT,
        PERM_REPORT_READ,
        PERM_REPORT_WRITE,
    },
    UserRole.SOC_ANALYST: {
        PERM_IOC_READ,
        PERM_ENRICH_EXECUTE,
        PERM_INVESTIGATION_READ,
        PERM_STIX_EXPORT,
        PERM_REPORT_READ,
    },
    UserRole.VIEWER: {
        PERM_IOC_READ,
        PERM_INVESTIGATION_READ,
        PERM_REPORT_READ,
    },
    UserRole.API_CLIENT: {
        PERM_IOC_READ,
        PERM_ENRICH_EXECUTE,
        PERM_STIX_EXPORT,
        PERM_REPORT_READ,
    },
}


def has_permission(role: UserRole, permission: str) -> bool:
    """Checks whether a given UserRole possesses a specific permission."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms
