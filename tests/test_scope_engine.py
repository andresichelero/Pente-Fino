from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# Ensure packages/scope is accessible in sys.path
_scope_pkg_path = Path(__file__).resolve().parent.parent / "packages" / "scope"
if str(_scope_pkg_path) not in sys.path:
    sys.path.insert(0, str(_scope_pkg_path))

from pentefino_scope import (  # noqa: E402
    AssetType,
    AuthorizationSnapshot,
    PrecedenceTier,
    ScopeAction,
    ScopeDecision,
    ScopeEngine,
    ScopeRule,
    ScopeTarget,
    check_dns_rebinding,
    evaluate_target,
    is_prohibited_ip,
)


@pytest.fixture
def base_program_id():
    return uuid4()


@pytest.fixture
def active_snapshot(base_program_id):
    now = datetime.now(timezone.utc)
    return AuthorizationSnapshot(
        program_id=base_program_id,
        policy_hash="a" * 64,
        rules_json={},
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
    )


# ==============================================================================
# 1. Strict 7-Tier Precedence Evaluation Tests
# ==============================================================================

class TestPrecedenceTiers:

    def test_tier_1_explicit_deny_beats_explicit_allow(self, base_program_id, active_snapshot):
        target = "https://admin.example.com"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="admin.example.com",
                action=ScopeAction.DENY,
            ),
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="admin.example.com",
                action=ScopeAction.ALLOW,
            ),
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_DENY
        assert decision.reason == "EXPLICIT_DENY_RULE_MATCHED"

    def test_tier_1_explicit_deny_beats_wildcard_allow(self, base_program_id, active_snapshot):
        target = "https://corp.example.com"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            ),
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="corp.example.com",
                action=ScopeAction.DENY,
            ),
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_DENY

    def test_tier_2_missing_snapshot_fails_closed(self, base_program_id):
        target = "https://app.example.com"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=None, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPIRED_AUTH
        assert "MISSING_AUTHORIZATION_SNAPSHOT" in decision.reason

    def test_tier_2_future_snapshot_denied(self, base_program_id):
        target = "https://app.example.com"
        now = datetime.now(timezone.utc)
        future_snapshot = AuthorizationSnapshot(
            program_id=base_program_id,
            policy_hash="b" * 64,
            rules_json={},
            valid_from=now + timedelta(days=1),
            valid_until=now + timedelta(days=30),
        )
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=future_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPIRED_AUTH
        assert decision.reason == "AUTHORIZATION_NOT_YET_ACTIVE"

    def test_tier_2_expired_snapshot_denied(self, base_program_id):
        target = "https://app.example.com"
        now = datetime.now(timezone.utc)
        expired_snapshot = AuthorizationSnapshot(
            program_id=base_program_id,
            policy_hash="c" * 64,
            rules_json={},
            valid_from=now - timedelta(days=30),
            valid_until=now - timedelta(days=1),
        )
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=expired_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPIRED_AUTH
        assert decision.reason == "AUTHORIZATION_EXPIRED"

    def test_tier_3_port_restriction_denies_unauthorized_port(self, base_program_id, active_snapshot):
        target = "https://app.example.com:8443/login"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
                allowed_ports=[80, 443],
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.PATH_PORT_DENY
        assert "PORT_NOT_ALLOWED" in decision.reason

    def test_tier_3_port_restriction_allows_authorized_port(self, base_program_id, active_snapshot):
        target = "https://app.example.com:443/login"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
                allowed_ports=[80, 443],
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW

    def test_tier_3_denied_path_overrides_host_allow(self, base_program_id, active_snapshot):
        target = "https://app.example.com/admin/settings"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
                denied_paths=["/admin", "/logout"],
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.PATH_PORT_DENY
        assert "PATH_DENIED" in decision.reason

    def test_tier_3_denied_path_glob_matching(self, base_program_id, active_snapshot):
        target = "https://app.example.com/api/v2/private-secret"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
                denied_paths=["/api/v2/private*"],
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.PATH_PORT_DENY

    def test_tier_3_path_normalization_prevents_traversal_bypass(self, base_program_id, active_snapshot):
        # Attacker tries to bypass denied path /admin using dot-segments and percent-encoding
        target_traversal = "https://app.example.com/public/../admin/users"
        target_encoded = "https://app.example.com/%2e%2e/admin/users"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
                denied_paths=["/admin"],
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)

        d1 = engine.evaluate_target(target_traversal)
        assert d1.allowed is False
        assert d1.matched_tier == PrecedenceTier.PATH_PORT_DENY

        d2 = engine.evaluate_target(target_encoded)
        assert d2.allowed is False
        assert d2.matched_tier == PrecedenceTier.PATH_PORT_DENY

    def test_tier_4_exact_fqdn_allows(self, base_program_id, active_snapshot):
        target = "https://portal.example.com/dashboard"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="portal.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW

    def test_tier_4_exact_ip_allows(self, base_program_id, active_snapshot):
        target = "http://93.184.216.34:80/"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.IP,
                pattern="93.184.216.34",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW

    def test_tier_5_wildcard_domain_allows_subdomain(self, base_program_id, active_snapshot):
        target = "https://api.example.com/v1"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.WILDCARD_ALLOW

    def test_tier_5_wildcard_domain_allows_multilevel_subdomain(self, base_program_id, active_snapshot):
        target = "https://us-east.stage.api.example.com/v1"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.WILDCARD_ALLOW

    def test_tier_5_cidr_allows_contained_ip(self, base_program_id, active_snapshot):
        # 198.51.100.0/24 documentation subnet, test with lab mode
        target = "http://198.51.100.42:8080/"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.CIDR,
                pattern="198.51.100.0/24",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules, environment_class="lab")
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.WILDCARD_ALLOW

    def test_tier_6_derived_candidate_denied(self, base_program_id, active_snapshot):
        # Recon-discovered CNAME or host not promoted
        target = ScopeTarget.from_url("https://cname.thirdparty-cdn.com", is_derived=True)
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.DERIVED_CANDIDATE
        assert decision.reason == "DERIVED_CANDIDATE_REQUIRES_PROMOTION"

    def test_tier_6_derived_candidate_matching_wildcard_promoted_and_allowed(
        self, base_program_id, active_snapshot
    ):
        # Recon discovers sub.example.com -> matches *.example.com at Tier 5
        target = ScopeTarget.from_url("https://discovered-sub.example.com", is_derived=True)
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.WILDCARD_ALLOW

    def test_tier_7_unknown_target_default_deny(self, base_program_id, active_snapshot):
        target = "https://unauthorized.com/index.html"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.UNKNOWN_DENY
        assert decision.reason == "UNKNOWN_TARGET_DEFAULT_DENY"


# ==============================================================================
# 2. Scope Invariants Tests
# ==============================================================================

class TestScopeInvariants:

    def test_wildcard_domain_never_authorizes_ip_scan(self, base_program_id, active_snapshot):
        """
        CRITICAL INVARIANT: *.example.com resolving to 93.184.216.34 does NOT authorize
        direct scanning against http://93.184.216.34/.
        """
        target = "http://93.184.216.34/"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.UNKNOWN_DENY

    def test_wildcard_domain_does_not_match_apex_without_explicit_rule(
        self, base_program_id, active_snapshot
    ):
        """
        *.example.com does not match apex example.com.
        """
        target = "https://example.com"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.UNKNOWN_DENY

    def test_wildcard_domain_rejects_prefix_collision(self, base_program_id, active_snapshot):
        """Prevents missing dot vulnerability: fakeexample.com does not match *.example.com."""
        target = "https://fakeexample.com"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False

    def test_wildcard_domain_rejects_suffix_collision(self, base_program_id, active_snapshot):
        """example.com.attacker.com does not match *.example.com."""
        target = "https://example.com.attacker.com"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False

    def test_idn_punycode_matching(self, base_program_id, active_snapshot):
        """münchen.example.com matches *.example.com when punycode normalized."""
        target = "https://münchen.example.com"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.WILDCARD_ALLOW

    def test_case_insensitivity_and_trailing_dots(self, base_program_id, active_snapshot):
        target = "https://APP.EXAMPLE.COM."
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW

    def test_cname_to_third_party_denied(self, base_program_id, active_snapshot):
        """
        Recon discovers customer.example.com CNAME to my-bucket.s3.amazonaws.com.
        Targeting my-bucket.s3.amazonaws.com is out-of-scope.
        """
        target = ScopeTarget.from_url("https://my-bucket.s3.amazonaws.com", is_derived=True)
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.DERIVED_CANDIDATE


# ==============================================================================
# 3. Anti-SSRF, Dangerous IP & DNS Rebinding Tests
# ==============================================================================

class TestAntiSSRFAndPrivateIPBlocks:

    @pytest.mark.parametrize(
        "ip_str",
        [
            "10.0.0.1",
            "10.254.254.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.100.50",
            "127.0.0.1",
            "127.127.127.127",
            "127.1",
            "::1",
            "[::1]",
            "169.254.1.1",
            "169.254.169.254",  # AWS/GCP/Azure IMDS
            "169.254.169.253",  # GCP DNS
            "fd00:ec2::254",    # AWS IMDSv2 IPv6
            "fe80::1",          # Link-local IPv6
            "::ffff:127.0.0.1", # IPv4-mapped loopback
            "::ffff:169.254.169.254", # IPv4-mapped metadata
            "::ffff:10.0.0.1",  # IPv4-mapped private
            "100.64.0.1",       # CGNAT
            "0.0.0.0",
        ],
    )
    def test_prohibited_ips_in_bounty_mode(self, ip_str):
        prohibited, reason = is_prohibited_ip(ip_str, environment_class="bounty")
        assert prohibited is True, f"Expected {ip_str} to be prohibited in bounty mode, got reason: {reason}"

    def test_obfuscated_decimal_ip_blocked(self):
        # 2130706433 == 127.0.0.1
        prohibited, reason = is_prohibited_ip("2130706433", environment_class="bounty")
        assert prohibited is True
        assert "LOOPBACK" in reason or "127" in reason

    def test_obfuscated_hex_ip_blocked(self):
        # 0x7f000001 == 127.0.0.1
        prohibited, reason = is_prohibited_ip("0x7f000001", environment_class="bounty")
        assert prohibited is True

    def test_obfuscated_octal_ip_blocked(self):
        # 0177.0.0.1 == 127.0.0.1
        prohibited, reason = is_prohibited_ip("0177.0.0.1", environment_class="bounty")
        assert prohibited is True

    def test_public_ips_allowed_by_ip_filter(self):
        for pub_ip in ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]:
            prohibited, _ = is_prohibited_ip(pub_ip, environment_class="bounty")
            assert prohibited is False

    def test_lab_environment_permits_private_and_loopback(self):
        # In lab mode, private RFC 1918 and loopback are permitted for local Docker test fixtures
        assert is_prohibited_ip("127.0.0.1", environment_class="lab")[0] is False
        assert is_prohibited_ip("10.0.0.5", environment_class="lab")[0] is False
        assert is_prohibited_ip("192.168.1.1", environment_class="lab")[0] is False

    def test_lab_environment_still_blocks_cloud_metadata(self):
        # CRITICAL: Cloud metadata (169.254.169.254, fd00:ec2::254) remains BLOCKED in lab mode!
        assert is_prohibited_ip("169.254.169.254", environment_class="lab")[0] is True
        assert is_prohibited_ip("169.254.169.253", environment_class="lab")[0] is True
        assert is_prohibited_ip("fd00:ec2::254", environment_class="lab")[0] is True

    def test_dns_rebinding_detection_blocks_prohibited_ips(self):
        # Hostname resolves to 169.254.169.254
        passed, ips, reason = check_dns_rebinding(
            "rebind.attacker.com",
            environment_class="bounty",
            resolved_ips=["169.254.169.254"],
        )
        assert passed is False
        assert "DNS_REBINDING_OR_PROHIBITED_IP" in reason

    def test_dns_rebinding_dual_stack_with_bad_ipv6_blocks(self):
        # Hostname resolves to public IPv4 and loopback IPv6
        passed, ips, reason = check_dns_rebinding(
            "dual-stack.example.com",
            environment_class="bounty",
            resolved_ips=["93.184.216.34", "::1"],
        )
        assert passed is False
        assert "DNS_REBINDING_OR_PROHIBITED_IP" in reason

    def test_dns_rebinding_safe_ips_permitted(self):
        passed, ips, reason = check_dns_rebinding(
            "safe.example.com",
            environment_class="bounty",
            resolved_ips=["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
        )
        assert passed is True
        assert reason == "ALL_IPS_PERMITTED"


# ==============================================================================
# 4. Hop-by-Hop Redirect Evaluation Tests
# ==============================================================================

class TestHopByHopRedirects:

    def test_redirect_relative_path_allowed(self, base_program_id, active_snapshot):
        curr_target = ScopeTarget.from_url("https://app.example.com/login")
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        allowed, next_target, reason = engine.evaluate_redirect(curr_target, "/dashboard", hop_count=0)

        assert allowed is True
        assert next_target.canonical_url == "https://app.example.com/dashboard"
        assert "REDIRECT_ALLOWED" in reason

    def test_redirect_to_authorized_sibling_allowed(self, base_program_id, active_snapshot):
        curr_target = ScopeTarget.from_url("https://auth.example.com/login")
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        allowed, next_target, reason = engine.evaluate_redirect(
            curr_target, "https://portal.example.com/oauth/callback", hop_count=0
        )

        assert allowed is True
        assert next_target.canonical_url == "https://portal.example.com/oauth/callback"

    def test_redirect_to_out_of_scope_domain_blocked(self, base_program_id, active_snapshot):
        curr_target = ScopeTarget.from_url("https://app.example.com/login")
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        allowed, next_target, reason = engine.evaluate_redirect(
            curr_target, "https://evil-phishing.com/harvest", hop_count=0
        )

        assert allowed is False
        assert "REDIRECT_OUT_OF_SCOPE" in reason

    def test_redirect_to_cloud_metadata_blocked(self, base_program_id, active_snapshot):
        curr_target = ScopeTarget.from_url("https://app.example.com/ssrf")
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        allowed, next_target, reason = engine.evaluate_redirect(
            curr_target, "http://169.254.169.254/latest/meta-data/", hop_count=0
        )

        assert allowed is False
        assert "PROHIBITED_IP" in reason

    def test_redirect_to_denied_path_blocked(self, base_program_id, active_snapshot):
        curr_target = ScopeTarget.from_url("https://app.example.com/open")
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
                denied_paths=["/admin"],
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        allowed, next_target, reason = engine.evaluate_redirect(curr_target, "/admin", hop_count=0)

        assert allowed is False
        assert "PATH_DENIED" in reason

    def test_redirect_max_hops_exceeded_blocked(self, base_program_id, active_snapshot):
        curr_target = ScopeTarget.from_url("https://app.example.com/hop3")
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        allowed, next_target, reason = engine.evaluate_redirect(
            curr_target, "/hop4", hop_count=3, max_hops=3
        )

        assert allowed is False
        assert "MAX_REDIRECT_HOPS_EXCEEDED" in reason


# ==============================================================================
# 5. Property-Based Testing (Hypothesis)
# ==============================================================================

class TestHypothesisProperties:

    @settings(max_examples=50)
    @given(st.text())
    def test_property_never_crashes_on_arbitrary_input(self, arbitrary_text):
        """No arbitrary string input can cause an unhandled exception; fail-closed is guaranteed."""
        decision = evaluate_target(arbitrary_text, rules=[], snapshot=None)
        assert isinstance(decision, ScopeDecision)
        assert decision.allowed is False

    @settings(max_examples=50)
    @given(
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
    )
    def test_property_rfc1918_10_network_ssrf_invariant(self, b, c):
        """Any address in 10.x.y.1 is strictly prohibited in bounty mode."""
        ip_str = f"10.{b}.{c}.1"
        prohibited, reason = is_prohibited_ip(ip_str, environment_class="bounty")
        assert prohibited is True
        assert "RFC1918" in reason

    @settings(max_examples=50)
    @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=20))
    def test_property_explicit_deny_dominance(self, sub):
        """If a hostname is explicitly denied, it is never allowed regardless of wildcard allows."""
        prog_id = uuid4()
        now = datetime.now(timezone.utc)
        snapshot = AuthorizationSnapshot(
            program_id=prog_id,
            policy_hash="e" * 64,
            rules_json={},
            valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=30),
        )
        hostname = f"{sub}.example.com"
        rules = [
            ScopeRule(
                program_id=prog_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            ),
            ScopeRule(
                program_id=prog_id,
                asset_type=AssetType.HOSTNAME,
                pattern=hostname,
                action=ScopeAction.DENY,
            ),
        ]
        engine = ScopeEngine(snapshot=snapshot, rules=rules)
        decision = engine.evaluate_target(f"https://{hostname}/")
        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_DENY


# ==============================================================================
# 6. Advanced Edge Cases & Invariant Hardening
# ==============================================================================

class TestAdvancedEdgeCases:

    def test_resolved_ips_with_metadata_blocks_domain_target(self, base_program_id, active_snapshot):
        """DNS rebinding defense: domain target is in scope, but its resolved IP is cloud metadata."""
        target = ScopeTarget.from_url(
            "https://app.example.com/api",
            resolved_ips=["169.254.169.254"],
        )
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_DENY
        assert "RESOLVED_IP_PROHIBITED" in decision.reason
        assert decision.resolved_ip == "169.254.169.254"

    def test_resolved_ips_with_loopback_blocks_domain_target(self, base_program_id, active_snapshot):
        target = ScopeTarget.from_url(
            "https://app.example.com/api",
            resolved_ips=["127.0.0.1"],
        )
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_DENY
        assert "RESOLVED_IP_PROHIBITED" in decision.reason

    def test_path_boundary_no_false_positive_on_longer_segment(self, base_program_id, active_snapshot):
        """Path /admin should not match /administrator."""
        target = "https://app.example.com/administrator/public"
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
                denied_paths=["/admin"],
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        decision = engine.evaluate_target(target)

        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW

    def test_6to4_embedded_private_ip_blocked(self):
        # 2002:0a00:0001:: encodes 10.0.0.1 in bytes 2..6
        prohibited, reason = is_prohibited_ip("2002:0a00:0001::", environment_class="bounty")
        assert prohibited is True
        assert "6TO4_EMBEDDED_IPV4" in reason

    def test_redirect_protocol_relative_url(self, base_program_id, active_snapshot):
        """Redirect with protocol-relative URL '//evil.com/phish' is resolved and blocked."""
        curr_target = ScopeTarget.from_url("https://app.example.com/login")
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.HOSTNAME,
                pattern="app.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
        allowed, next_target, reason = engine.evaluate_redirect(
            curr_target, "//evil.com/phish", hop_count=0
        )
        assert allowed is False
        assert "REDIRECT_OUT_OF_SCOPE" in reason

    def test_redirect_multiple_allowed_hops(self, base_program_id, active_snapshot):
        rules = [
            ScopeRule(
                program_id=base_program_id,
                asset_type=AssetType.WILDCARD_DOMAIN,
                pattern="*.example.com",
                action=ScopeAction.ALLOW,
            )
        ]
        engine = ScopeEngine(snapshot=active_snapshot, rules=rules)

        # Hop 1
        t0 = ScopeTarget.from_url("https://a.example.com/step1")
        ok1, t1, r1 = engine.evaluate_redirect(t0, "/step2", hop_count=0, max_hops=3)
        assert ok1 is True
        assert t1.canonical_url == "https://a.example.com/step2"

        # Hop 2
        ok2, t2, r2 = engine.evaluate_redirect(t1, "https://b.example.com/step3", hop_count=1, max_hops=3)
        assert ok2 is True
        assert t2.canonical_url == "https://b.example.com/step3"

        # Hop 3
        ok3, t3, r3 = engine.evaluate_redirect(t2, "/step4", hop_count=2, max_hops=3)
        assert ok3 is True
        assert t3.canonical_url == "https://b.example.com/step4"

        # Hop 4 (exceeds max_hops 3)
        ok4, t4, r4 = engine.evaluate_redirect(t3, "/step5", hop_count=3, max_hops=3)
        assert ok4 is False
        assert "MAX_REDIRECT_HOPS_EXCEEDED" in r4

    def test_scope_decision_tier_property(self):
        decision = ScopeDecision(
            allowed=False,
            matched_tier=PrecedenceTier.PATH_PORT_DENY,
            reason="test reason",
        )
        assert decision.tier == PrecedenceTier.PATH_PORT_DENY
        assert decision.matched_tier == PrecedenceTier.PATH_PORT_DENY

    def test_scope_engine_method_is_prohibited_ip(self, base_program_id, active_snapshot):
        engine = ScopeEngine(snapshot=active_snapshot, environment_class="bounty")
        proh, reason = engine.is_prohibited_ip("127.0.0.1")
        assert proh is True
        assert "LOOPBACK" in reason


