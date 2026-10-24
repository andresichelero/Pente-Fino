from __future__ import annotations

import gzip
import json
import re
from datetime import datetime, timezone

import pytest

from pentefino_proxy import (
    EvidenceTap,
    InMemoryS3Store,
    Redactor,
    S3EvidenceClient,
    redact_cookie_string,
    redact_set_cookie_string,
)


@pytest.fixture
def redactor() -> Redactor:
    return Redactor()


@pytest.fixture
def s3_client() -> S3EvidenceClient:
    # Uses real SeaweedFS S3 (port 8333) with automatic in-memory fallback
    return S3EvidenceClient()


@pytest.fixture
def evidence_tap(s3_client: S3EvidenceClient, redactor: Redactor) -> EvidenceTap:
    return EvidenceTap(s3_client=s3_client, redactor=redactor)


# ==============================================================================
# 1. Bearer Token & Authentication Header Redaction Tests
# ==============================================================================

class TestHeaderRedaction:

    def test_bearer_token_redaction(self, redactor: Redactor):
        raw_headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecrettoken",
            "Host": "api.target.com",
        }
        sanitized = redactor.redact_headers(raw_headers)
        assert sanitized["Authorization"] == "Bearer [REDACTED]"
        assert "supersecrettoken" not in sanitized["Authorization"]
        assert sanitized["Host"] == "api.target.com"

    def test_basic_auth_redaction(self, redactor: Redactor):
        raw_headers = {
            "Authorization": "Basic YWRtaW46c2VjcmV0cGFzc3dvcmQ=",
        }
        sanitized = redactor.redact_headers(raw_headers)
        assert sanitized["Authorization"] == "Basic [REDACTED]"
        assert "YWRtaW4" not in sanitized["Authorization"]

    def test_token_auth_redaction(self, redactor: Redactor):
        raw_headers = {
            "Authorization": "Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
        }
        sanitized = redactor.redact_headers(raw_headers)
        assert sanitized["Authorization"] == "Token [REDACTED]"

    def test_custom_api_key_headers_redaction(self, redactor: Redactor):
        raw_headers = {
            "X-Api-Key": "live_sk_secret_12345",
            "X-Auth-Token": "auth_token_secret_abcdef",
            "ApiKey": "key_secret_789",
            "Proxy-Authorization": "Basic cHJveHl1c2VyOnByb3h5cGFzcw==",
            "Accept": "application/json",
        }
        sanitized = redactor.redact_headers(raw_headers)
        assert sanitized["X-Api-Key"] == "[REDACTED]"
        assert sanitized["X-Auth-Token"] == "[REDACTED]"
        assert sanitized["ApiKey"] == "[REDACTED]"
        assert sanitized["Proxy-Authorization"] == "[REDACTED]"
        assert sanitized["Accept"] == "application/json"


# ==============================================================================
# 2. Cookie & Set-Cookie Sanitization Tests
# ==============================================================================

class TestCookieRedaction:

    def test_cookie_header_sanitization(self, redactor: Redactor):
        raw_cookie = "session=d3b07384d113edec49eaa6238ad5ff00; user_id=42; remember=true; csrftoken=a1b2c3d4"
        sanitized_cookie = redact_cookie_string(raw_cookie)

        assert "session=[REDACTED]" in sanitized_cookie
        assert "user_id=[REDACTED]" in sanitized_cookie
        assert "remember=[REDACTED]" in sanitized_cookie
        assert "csrftoken=[REDACTED]" in sanitized_cookie
        assert "d3b07384d113edec49eaa6238ad5ff00" not in sanitized_cookie
        assert "a1b2c3d4" not in sanitized_cookie

    def test_set_cookie_preserves_attributes(self, redactor: Redactor):
        raw_set_cookie = "PHPSESSID=super_secret_cookie_val; Path=/; Secure; HttpOnly; SameSite=Lax"
        sanitized_set_cookie = redact_set_cookie_string(raw_set_cookie)

        # Value masked, security flags intact
        assert sanitized_set_cookie.startswith("PHPSESSID=[REDACTED];")
        assert "Path=/" in sanitized_set_cookie
        assert "Secure" in sanitized_set_cookie
        assert "HttpOnly" in sanitized_set_cookie
        assert "SameSite=Lax" in sanitized_set_cookie
        assert "super_secret_cookie_val" not in sanitized_set_cookie

    def test_headers_redactor_applies_cookie_rules(self, redactor: Redactor):
        headers = {
            "Cookie": "jwt=eyJhbGciOi.token; sid=123",
            "Set-Cookie": "auth=abc; Secure; HttpOnly",
        }
        sanitized = redactor.redact_headers(headers)
        assert sanitized["Cookie"] == "jwt=[REDACTED]; sid=[REDACTED]"
        assert sanitized["Set-Cookie"] == "auth=[REDACTED]; Secure; HttpOnly"


# ==============================================================================
# 3. Payload Body & Secret Pattern Scrubbing Tests
# ==============================================================================

class TestBodyRedaction:

    def test_json_sensitive_keys_redacted(self, redactor: Redactor):
        payload = {
            "username": "bugbounty_hunter",
            "password": "ClearTextPassword123!",
            "client_secret": "oauth_secret_abc123",
            "api_key": "sk_live_very_secret",
            "nested": {
                "token": "nested_secret_token",
                "public_info": "visible",
            },
        }
        raw_json_str = json.dumps(payload)
        sanitized_str = redactor.redact_body(raw_json_str, content_type="application/json")
        sanitized_data = json.loads(sanitized_str)

        assert sanitized_data["username"] == "bugbounty_hunter"
        assert sanitized_data["password"] == "[REDACTED]"
        assert sanitized_data["client_secret"] == "[REDACTED]"
        assert sanitized_data["api_key"] == "[REDACTED]"
        assert sanitized_data["nested"]["token"] == "[REDACTED]"
        assert sanitized_data["nested"]["public_info"] == "visible"

    def test_pattern_redaction_jwt_and_aws_keys(self, redactor: Redactor):
        text_body = (
            "Found AWS Key AKIAIOSFODNN7EXAMPLE in debug dump. "
            "Also discovered JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG48e"
        )
        sanitized = redactor.redact_body(text_body)
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "[REDACTED_AWS_KEY]" in sanitized
        assert "[REDACTED_JWT]" in sanitized

    def test_large_body_truncation_at_1mb(self, redactor: Redactor):
        large_body = b"A" * (1024 * 1024 + 500)
        sanitized = redactor.redact_body(large_body)
        assert len(sanitized) <= 1024 * 1024 + 50
        assert b"[TRUNCATED_AT_1MB]" in sanitized

    def test_form_urlencoded_password_redaction(self, redactor: Redactor):
        form_payload = "username=pentester&password=SuperSecretPassword123!&client_secret=oauth_secret_xyz"
        sanitized = redactor.redact_body(
            form_payload,
            content_type="application/x-www-form-urlencoded",
        )
        assert "SuperSecretPassword123!" not in sanitized
        assert "oauth_secret_xyz" not in sanitized
        assert "password=[REDACTED]" in sanitized
        assert "client_secret=[REDACTED]" in sanitized
        assert "username=pentester" in sanitized

    def test_form_urlencoded_bytes_payload_redaction(self, redactor: Redactor):
        form_bytes = b"user=admin&passwd=ClearTextPass&token=sensitive_token_abc"
        sanitized = redactor.redact_body(
            form_bytes,
            content_type="application/x-www-form-urlencoded",
        )
        assert isinstance(sanitized, bytes)
        assert b"ClearTextPass" not in sanitized
        assert b"sensitive_token_abc" not in sanitized
        assert b"passwd=[REDACTED]" in sanitized
        assert b"token=[REDACTED]" in sanitized
        assert b"user=admin" in sanitized

    def test_form_urlencoded_auto_detection_when_content_type_omitted(self, redactor: Redactor):
        form_payload = "user=admin&password=HiddenPassword999&auth_token=my_secret_token"
        sanitized = redactor.redact_body(form_payload)
        assert "HiddenPassword999" not in sanitized
        assert "my_secret_token" not in sanitized
        assert "password=[REDACTED]" in sanitized
        assert "auth_token=[REDACTED]" in sanitized
        assert "user=admin" in sanitized

    def test_form_urlencoded_preserves_non_sensitive_and_scrubs_embedded_keys(self, redactor: Redactor):
        form_payload = "search_query=sqli_test&notes=found+key+AKIAIOSFODNN7EXAMPLE+here"
        sanitized = redactor.redact_body(
            form_payload,
            content_type="application/x-www-form-urlencoded",
        )
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "[REDACTED_AWS_KEY]" in sanitized
        assert "search_query=sqli_test" in sanitized


# ==============================================================================
# 4. Dual SHA-256 Hashing Invariant Tests
# ==============================================================================

class TestDualHashing:

    def test_dual_hash_divergence_when_credentials_present(self, evidence_tap: EvidenceTap):
        """
        Invariant: Whenever sensitive tokens are masked, original_sha256 != sanitized_sha256.
        """
        record = evidence_tap.tap_interaction(
            method="POST",
            url="https://api.target.com/v1/auth/login",
            request_headers={
                "Authorization": "Bearer sensitive_token_xyz",
                "Cookie": "session=sensitive_cookie_abc",
            },
            request_body=json.dumps({"password": "secret_password"}),
            status_code=200,
            response_headers={"Set-Cookie": "auth=secret_auth; Secure"},
            response_body=json.dumps({"access_token": "secret_access_token"}),
            program_id="prog_dual_hash",
            upload_to_s3=False,
        )

        assert record.is_redacted is True
        assert record.original_sha256 != record.sanitized_sha256
        assert len(record.original_sha256) == 64
        assert len(record.sanitized_sha256) == 64
        assert re.match(r"^[0-9a-f]{64}$", record.original_sha256)
        assert re.match(r"^[0-9a-f]{64}$", record.sanitized_sha256)

        # Inspect sanitized payload: no secrets remain
        payload_str = json.dumps(record.sanitized_payload)
        assert "sensitive_token_xyz" not in payload_str
        assert "sensitive_cookie_abc" not in payload_str
        assert "secret_password" not in payload_str
        assert "secret_auth" not in payload_str
        assert "secret_access_token" not in payload_str

    def test_dual_hash_identity_when_no_credentials_present(self, evidence_tap: EvidenceTap):
        """
        Invariant: When interaction is strictly benign/public, original_sha256 == sanitized_sha256.
        """
        record = evidence_tap.tap_interaction(
            method="GET",
            url="https://api.target.com/public/health",
            request_headers={"Accept": "application/json"},
            request_body=None,
            status_code=200,
            response_headers={"Content-Type": "application/json"},
            response_body=json.dumps({"status": "healthy"}),
            program_id="prog_clean",
            upload_to_s3=False,
        )

        assert record.is_redacted is False
        assert record.original_sha256 == record.sanitized_sha256

    def test_dual_hash_divergence_for_form_urlencoded_credentials(self, evidence_tap: EvidenceTap):
        """
        Invariant: Form-urlencoded password submission triggers hash divergence and masks secrets.
        """
        record = evidence_tap.tap_interaction(
            method="POST",
            url="https://api.target.com/login",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="username=admin&password=SecretSuperPassword123&client_secret=secret_val",
            status_code=200,
            response_headers={"Content-Type": "text/plain"},
            response_body="Login successful",
            program_id="prog_form_hash",
            upload_to_s3=False,
        )

        assert record.is_redacted is True
        assert record.original_sha256 != record.sanitized_sha256
        assert len(record.original_sha256) == 64
        assert len(record.sanitized_sha256) == 64

        req_body = record.sanitized_payload["request"]["body"]
        assert "SecretSuperPassword123" not in req_body
        assert "secret_val" not in req_body
        assert "password=[REDACTED]" in req_body
        assert "client_secret=[REDACTED]" in req_body
        assert "username=admin" in req_body


# ==============================================================================
# 5. S3 SeaweedFS Upload & Retrieval Tests
# ==============================================================================

class TestS3EvidenceUpload:

    def test_s3_upload_and_retrieval(self, evidence_tap: EvidenceTap, s3_client: S3EvidenceClient):
        prog_id = "prog_s3_test"
        record = evidence_tap.tap_interaction(
            method="GET",
            url="https://api.target.com/profile",
            request_headers={
                "Authorization": "Bearer secret_api_token_to_redact",
                "Cookie": "session=secret_session_to_redact",
            },
            status_code=200,
            response_body=json.dumps({"username": "alice", "role": "admin"}),
            program_id=prog_id,
            upload_to_s3=True,
            compress=True,
        )

        # Check object key structure: artifacts/{program_id}/{YYYY-MM-DD}/{sanitized_sha256}.json.gz
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        expected_prefix = f"artifacts/{prog_id}/{today_str}/{record.sanitized_sha256}.json.gz"
        assert record.seaweed_object_key == expected_prefix

        # Verify object exists in S3
        assert s3_client.exists(record.seaweed_object_key) is True

        # Fetch object from S3 and decompress
        s3_bytes = s3_client.get_evidence(record.seaweed_object_key)
        decompressed_json = gzip.decompress(s3_bytes).decode("utf-8")
        uploaded_data = json.loads(decompressed_json)

        # Verify data integrity and zero leaked secrets in S3
        assert uploaded_data["request"]["headers"]["Authorization"] == "Bearer [REDACTED]"
        assert uploaded_data["request"]["headers"]["Cookie"] == "session=[REDACTED]"
        assert "secret_api_token_to_redact" not in decompressed_json
        assert "secret_session_to_redact" not in decompressed_json
        assert uploaded_data["response"]["status_code"] == 200

    def test_in_memory_s3_store_isolated_operations(self):
        store = InMemoryS3Store()
        store.ensure_bucket("test-bucket")
        key = store.put_object("test-bucket", "artifacts/test.json", b'{"status": "ok"}')
        assert key == "artifacts/test.json"
        assert store.has_object("test-bucket", "artifacts/test.json") is True
        assert store.get_object("test-bucket", "artifacts/test.json") == b'{"status": "ok"}'
