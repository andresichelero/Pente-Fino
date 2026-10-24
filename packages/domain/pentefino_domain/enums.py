from enum import StrEnum


class ProgramPlatform(StrEnum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    PRIVATE = "private"
    LAB = "lab"


class ProgramState(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class AssetType(StrEnum):
    DOMAIN = "domain"
    WILDCARD_DOMAIN = "wildcard_domain"
    HOSTNAME = "hostname"
    URL = "url"
    CIDR = "cidr"
    IP = "ip"


class ScopeAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    DISCOVER_ONLY = "discover_only"


class ScopeState(StrEnum):
    IN_SCOPE_EXPLICIT = "in_scope_explicit"
    IN_SCOPE_DERIVED = "in_scope_derived"
    CANDIDATE = "candidate"
    OUT_OF_SCOPE = "out_of_scope"


class ImpactClass(StrEnum):
    PASSIVE = "passive"
    SAFE_READ_ONLY = "safe_read_only"
    ACTIVE_REVIEWED = "active_reviewed"
    STATEFUL = "stateful"
    INTRUSIVE = "intrusive"
    LAB_ONLY = "lab_only"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    REPORTED = "reported"
    ACCEPTED = "accepted"
    REMEDIATED = "remediated"
    RESOLVED = "resolved"
    REOPENED = "reopened"


class EvidenceLevel(StrEnum):
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"


class FindingConfidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceType(StrEnum):
    DNS = "dns"
    HTTP_INTERACTION = "http_interaction"
    TLS = "tls"
    FINGERPRINT = "fingerprint"
