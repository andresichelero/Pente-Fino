from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import pytest

from pentefino_domain.enums import ImpactClass
from pentefino_template_indexer.bundle import compute_bundle_hash
from pentefino_template_indexer.classifier import (
    StaticTemplateClassifier,
    TemplateMetadata,
)
from pentefino_template_indexer.ingester import TemplateCatalogIngester
from pentefino_template_indexer.sync import (
    TemplateSyncError,
    TemplateSyncManager,
)


@pytest.fixture
def classifier() -> StaticTemplateClassifier:
    return StaticTemplateClassifier()


# ============================================================================
# 1. AST Classification Tests: Read-Only HTTP
# ============================================================================


def test_classify_pure_get_read_only(classifier: StaticTemplateClassifier):
    """Pure GET requests inspecting static paths must be classified as safe_read_only."""
    yaml_content = """
id: apache-path-traversal
info:
  name: Apache 2.4.49 - Path Traversal
  author: pentefino
  severity: high
  tags: cve,cve-2021-41773,apache,lfi
  classification:
    cve-id: cve-2021-41773
    cwe-id: cwe-22
http:
  - method: GET
    path:
      - "{{BaseURL}}/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    matchers:
      - type: word
        words:
          - "root:.*:0:0:"
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.id == "apache-path-traversal"
    assert meta.name == "Apache 2.4.49 - Path Traversal"
    assert meta.protocol == "http"
    assert meta.http_methods == ["GET"]
    assert meta.impact_class == ImpactClass.SAFE_READ_ONLY
    assert meta.cve_id == "CVE-2021-41773"
    assert meta.cwe_id == "CWE-22"
    assert meta.severity == "high"
    assert "apache" in meta.technologies
    assert "cve" in meta.tags
    assert len(meta.bundle_hash) == 64


def test_classify_pure_head_and_options_read_only(classifier: StaticTemplateClassifier):
    """HEAD and OPTIONS inspection must be classified as safe_read_only."""
    yaml_content = """
id: cors-options-check
info:
  name: CORS Preflight Diagnostic
  severity: info
  tags: cors,config,generic
http:
  - method: OPTIONS
    path:
      - "{{BaseURL}}/"
    headers:
      Origin: "https://evil.com"
  - method: HEAD
    path:
      - "{{BaseURL}}/health"
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.protocol == "http"
    assert set(meta.http_methods) == {"OPTIONS", "HEAD"}
    assert meta.impact_class == ImpactClass.SAFE_READ_ONLY


# ============================================================================
# 2. AST Classification Tests: Analytical & Idempotent POSTs
# ============================================================================


def test_classify_analytical_post_graphql_introspection(classifier: StaticTemplateClassifier):
    """GraphQL schema introspection via POST is analytical and read-only."""
    yaml_content = """
id: graphql-schema-introspection
info:
  name: GraphQL Introspection Query Enabled
  severity: medium
  tags: graphql,api,exposure
http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
    headers:
      Content-Type: application/json
    body: '{"query": "query IntrospectionQuery { __schema { queryType { name } } }"}'
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.http_methods == ["POST"]
    assert meta.impact_class == ImpactClass.SAFE_READ_ONLY
    assert "graphql" in meta.technologies


def test_classify_analytical_post_soap_version(classifier: StaticTemplateClassifier):
    """SOAP version or diagnostic check via POST without state mutations is safe_read_only."""
    yaml_content = """
id: axis2-version-detect
info:
  name: Apache Axis2 Service Version Inquiry
  severity: info
  tags: soap,apache,axis2
http:
  - method: POST
    path:
      - "{{BaseURL}}/services/Version"
    headers:
      SOAPAction: ""
      Content-Type: text/xml; charset=utf-8
    body: |
      <?xml version="1.0" encoding="utf-8"?>
      <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
          <GetServerVersion xmlns="http://axisversion.sample"/>
        </soapenv:Body>
      </soapenv:Envelope>
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.http_methods == ["POST"]
    assert meta.impact_class == ImpactClass.SAFE_READ_ONLY
    assert "apache" in meta.technologies or "soap" in meta.technologies


def test_classify_analytical_post_xmlrpc_ping(classifier: StaticTemplateClassifier):
    """XML-RPC system.listMethods or demo.sayHello probe is analytical and safe_read_only."""
    yaml_content = """
id: xmlrpc-system-listmethods
info:
  name: XML-RPC Available Methods Listing
  severity: info
  tags: xmlrpc,api
http:
  - method: POST
    path:
      - "{{BaseURL}}/xmlrpc.php"
    body: |
      <?xml version="1.0" encoding="utf-8"?>
      <methodCall>
        <methodName>system.listMethods</methodName>
        <params></params>
      </methodCall>
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.http_methods == ["POST"]
    assert meta.impact_class == ImpactClass.SAFE_READ_ONLY


def test_classify_analytical_post_jsonrpc_version(classifier: StaticTemplateClassifier):
    """JSON-RPC version inquiry (e.g. web3 clientVersion) is analytical and safe_read_only."""
    yaml_content = """
id: ethereum-rpc-version
info:
  name: Ethereum JSON-RPC Client Version
  severity: info
  tags: rpc,ethereum,blockchain
http:
  - method: POST
    path:
      - "{{BaseURL}}/"
    headers:
      Content-Type: application/json
    body: '{"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1}'
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.http_methods == ["POST"]
    assert meta.impact_class == ImpactClass.SAFE_READ_ONLY


# ============================================================================
# 3. AST Classification Tests: Stateful POSTs & Mutating Verbs
# ============================================================================


def test_classify_stateful_post_user_registration(classifier: StaticTemplateClassifier):
    """POST to account creation or user registration endpoint is stateful."""
    yaml_content = """
id: account-registration-test
info:
  name: User Registration Probe
  severity: low
  tags: auth,stateful
http:
  - method: POST
    path:
      - "{{BaseURL}}/api/v1/users/register"
    body: "username=testadmin&password=Password123!&email=test@example.com"
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.http_methods == ["POST"]
    assert meta.impact_class == ImpactClass.STATEFUL


def test_classify_stateful_post_file_upload(classifier: StaticTemplateClassifier):
    """POST request carrying multipart file uploads is stateful."""
    yaml_content = """
id: arbitrary-file-upload
info:
  name: Arbitrary File Upload via Profile Avatar
  severity: critical
  tags: cve,cve-2023-9999,upload
http:
  - raw:
      - |
        POST /api/upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

        ------WebKitFormBoundary7MA4YWxkTrZu0gW
        Content-Disposition: form-data; name="file"; filename="shell.php"
        Content-Type: application/x-php

        <?php echo "test"; ?>
        ------WebKitFormBoundary7MA4YWxkTrZu0gW--
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.http_methods == ["POST"]
    assert meta.impact_class == ImpactClass.STATEFUL


def test_classify_stateful_mutating_verbs(classifier: StaticTemplateClassifier):
    """Templates issuing PUT, DELETE, or PATCH verbs must be classified as stateful."""
    for method in ["PUT", "DELETE", "PATCH"]:
        yaml_content = f"""
id: test-verb-{method.lower()}
info:
  name: Test {method} Verb
  severity: medium
  tags: api
http:
  - method: {method}
    path:
      - "{{{{BaseURL}}}}/resource/123"
"""
        meta = classifier.classify_yaml(yaml_content)
        assert meta.http_methods == [method]
        assert meta.impact_class == ImpactClass.STATEFUL


def test_classify_generic_unclassified_post_failsafe_stateful(classifier: StaticTemplateClassifier):
    """Any POST that does not match strict analytical read-only patterns defaults to stateful."""
    yaml_content = """
id: unknown-post-endpoint
info:
  name: Generic POST Endpoint Probe
  severity: low
http:
  - method: POST
    path:
      - "{{BaseURL}}/submit-form"
    body: "foo=bar&action=do_something"
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.http_methods == ["POST"]
    assert meta.impact_class == ImpactClass.STATEFUL


# ============================================================================
# 4. AST Classification Tests: Intrusive & Lab-Only
# ============================================================================


def test_classify_intrusive_dos_tags(classifier: StaticTemplateClassifier):
    """Templates tagged with dos, ddos, or fuzz must be classified as intrusive."""
    yaml_content = """
id: slowloris-stress-test
info:
  name: Slowloris DoS Benchmark
  severity: high
  tags: dos,ddos,stress
http:
  - method: GET
    path:
      - "{{BaseURL}}/resource"
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.impact_class == ImpactClass.INTRUSIVE


def test_classify_intrusive_clusterbomb_payloads(classifier: StaticTemplateClassifier):
    """Templates employing attack-type clusterbomb or pitchfork are intrusive."""
    yaml_content = """
id: login-credential-spray
info:
  name: Login Bruteforce Clusterbomb
  severity: critical
  tags: bruteforce,auth
http:
  - method: POST
    path:
      - "{{BaseURL}}/login"
    attack-type: clusterbomb
    payloads:
      user: helpers/users.txt
      pass: helpers/pass.txt
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.impact_class == ImpactClass.INTRUSIVE


def test_classify_intrusive_high_request_multiplier(classifier: StaticTemplateClassifier):
    """Templates with max-request > 100 indicate high-frequency fuzzing and are intrusive."""
    yaml_content = """
id: directory-fuzz-burst
info:
  name: High Multiplier Directory Fuzz
  severity: low
  tags: discovery
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{word}}"
    max-request: 500
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.impact_class == ImpactClass.INTRUSIVE


def test_classify_code_protocol_lab_only(classifier: StaticTemplateClassifier):
    """Templates utilizing the code: protocol execute shell/python commands and are lab_only."""
    yaml_content = """
id: local-code-execution-template
info:
  name: Local Exploit Verification
  severity: critical
  tags: rce,local
code:
  - engine:
      - sh
      - bash
    source: |
      whoami
      uname -a
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.protocol == "code"
    assert meta.impact_class == ImpactClass.LAB_ONLY


def test_classify_headless_protocol_lab_only(classifier: StaticTemplateClassifier):
    """Templates driving headless browsers (headless:) are lab_only."""
    yaml_content = """
id: dom-xss-headless-verification
info:
  name: DOM XSS in Search Input
  severity: medium
  tags: xss,headless
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/?q=<script>alert(1)</script>"
      - action: waitdialog
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.protocol == "headless"
    assert meta.impact_class == ImpactClass.LAB_ONLY


# ============================================================================
# 5. AST Classification Tests: Non-HTTP Protocols (DNS, SSL, TCP)
# ============================================================================


def test_classify_dns_and_ssl_protocols(classifier: StaticTemplateClassifier):
    """DNS and SSL inspection protocols are read-only and classified as safe_read_only."""
    dns_yaml = """
id: dns-spf-record-check
info:
  name: SPF Record Detection
  severity: info
  tags: dns,spf
dns:
  - name: "{{Host}}"
    type: TXT
"""
    meta_dns = classifier.classify_yaml(dns_yaml)
    assert meta_dns.protocol == "dns"
    assert meta_dns.impact_class == ImpactClass.SAFE_READ_ONLY

    ssl_yaml = """
id: tls-cipher-audit
info:
  name: TLS Cipher Suite Audit
  severity: info
  tags: ssl,tls
ssl:
  - address: "{{Host}}:{{Port}}"
"""
    meta_ssl = classifier.classify_yaml(ssl_yaml)
    assert meta_ssl.protocol == "ssl"
    assert meta_ssl.impact_class == ImpactClass.SAFE_READ_ONLY


def test_classify_tcp_protocol_active_reviewed(classifier: StaticTemplateClassifier):
    """Raw TCP port/socket probing is active and classified as active_reviewed."""
    tcp_yaml = """
id: redis-unauth-access-check
info:
  name: Redis Unauthenticated Access
  severity: high
  tags: redis,network
tcp:
  - inputs:
      - data: "INFO\r\n"
    host:
      - "{{Hostname}}"
    port: 6379
"""
    meta_tcp = classifier.classify_yaml(tcp_yaml)
    assert meta_tcp.protocol == "tcp"
    assert meta_tcp.impact_class == ImpactClass.ACTIVE_REVIEWED
    assert "redis" in meta_tcp.technologies


# ============================================================================
# 6. Technology Tag Parsing and CVE/CWE Extraction
# ============================================================================


def test_cve_cwe_extraction_from_classification(classifier: StaticTemplateClassifier):
    """Extracts CVE and CWE accurately from classification block."""
    yaml_content = """
id: wordpress-cve-2020-25213
info:
  name: WordPress File Manager CVE-2020-25213
  severity: critical
  tags: cve,cve-2020-25213,wordpress,wp-plugin
  classification:
    cve-id: cve-2020-25213
    cwe-id: cwe-434
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/wp-file-manager/readme.txt"
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.cve_id == "CVE-2020-25213"
    assert meta.cwe_id == "CWE-434"
    assert "wordpress" in meta.technologies


def test_cve_extraction_fallback_from_template_id(classifier: StaticTemplateClassifier):
    """Extracts CVE ID when classification block is omitted, matching template ID regex."""
    yaml_content = """
id: cve-2022-22965-spring4shell
info:
  name: Spring4Shell RCE
  severity: critical
  tags: spring,rce
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
"""
    meta = classifier.classify_yaml(yaml_content)
    assert meta.cve_id == "CVE-2022-22965"
    assert "spring" in meta.technologies


# ============================================================================
# 7. Bundle Hash Determinism and Tamper Sensitivity
# ============================================================================


def test_bundle_hash_determinism_and_sensitivity(tmp_path: Path):
    """Bundle hash must be strictly deterministic and sensitive to any modification."""
    yaml_content = """
id: deterministic-test
info:
  name: Test Determinism
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
"""
    hash1 = compute_bundle_hash(yaml_content)
    hash2 = compute_bundle_hash(yaml_content)
    assert hash1 == hash2
    assert len(hash1) == 64

    # Modifying one byte changes the hash
    modified_yaml = yaml_content.replace("/test", "/test2")
    hash3 = compute_bundle_hash(modified_yaml)
    assert hash1 != hash3


def test_bundle_hash_with_external_payload_files(tmp_path: Path):
    """External payload files referenced in template are bound cryptographically into the bundle hash."""
    payload_file = tmp_path / "wordlist.txt"
    payload_file.write_text("admin\nroot\nguest\n", encoding="utf-8")

    yaml_content = """
id: template-with-external-payload
info:
  name: External Payload Binding
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    payloads:
      usernames: wordlist.txt
"""
    # Hash computed with base_dir incorporating wordlist.txt
    hash_with_payload = compute_bundle_hash(yaml_content, base_dir=tmp_path)
    assert len(hash_with_payload) == 64

    # Hash without payload
    hash_without_payload = compute_bundle_hash(yaml_content, base_dir=None)
    assert hash_with_payload != hash_without_payload

    # Tampering with the payload file changes the bundle hash even if the YAML is untouched!
    payload_file.write_text("admin\nroot\nguest\nattacker\n", encoding="utf-8")
    hash_tampered_payload = compute_bundle_hash(yaml_content, base_dir=tmp_path)
    assert hash_with_payload != hash_tampered_payload


# ============================================================================
# 8. TemplateSyncManager Offline & Fixture Mode Tests
# ============================================================================


@pytest.mark.asyncio
async def test_sync_manager_offline_fixture_mode(tmp_path: Path):
    """TemplateSyncManager supports offline mode with local custom fixture directory."""
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()

    # Create dummy templates in fixtures
    t1 = fixtures_dir / "t1.yaml"
    t1.write_text("id: template-1\ninfo:\n  name: T1\nhttp:\n  - method: GET\n", encoding="utf-8")
    t2 = fixtures_dir / "t2.yaml"
    t2.write_text("id: template-2\ninfo:\n  name: T2\nhttp:\n  - method: GET\n", encoding="utf-8")

    mgr = TemplateSyncManager(custom_templates_dir=fixtures_dir)
    rev = await mgr.sync()
    assert isinstance(rev, str)
    assert len(rev) == 40  # 40-character revision SHA

    template_files = mgr.list_template_files()
    assert len(template_files) == 2
    assert t1 in template_files
    assert t2 in template_files


@pytest.mark.asyncio
async def test_sync_manager_clone_error_handling(monkeypatch):
    """TemplateSyncManager raises TemplateSyncError when git is missing and no cache exists."""
    monkeypatch.setattr("shutil.which", lambda _: None)
    mgr = TemplateSyncManager(
        local_path=Path("/nonexistent/path/that/does/not/exist"),
        custom_templates_dir=None,
    )
    with pytest.raises(TemplateSyncError, match="git executable not found"):
        await mgr.sync()


# ============================================================================
# 9. TemplateCatalogIngester Batched Ingestion Tests
# ============================================================================


@pytest.mark.asyncio
async def test_ingester_batching_and_upsert(classifier: StaticTemplateClassifier):
    """TemplateCatalogIngester batches parsed templates and upserts into database."""
    yaml1 = """
id: ingester-t1
info:
  name: Ingester Test 1
  severity: info
  tags: apache
http:
  - method: GET
    path:
      - "{{BaseURL}}/1"
"""
    yaml2 = """
id: ingester-t2
info:
  name: Ingester Test 2
  severity: high
  tags: nginx
http:
  - method: GET
    path:
      - "{{BaseURL}}/2"
"""
    m1: TemplateMetadata = classifier.classify_yaml(yaml1)
    m2: TemplateMetadata = classifier.classify_yaml(yaml2)
    assert isinstance(m1, TemplateMetadata)
    assert isinstance(m2, TemplateMetadata)

    # Use AsyncMock to verify database session operations
    mock_session = AsyncMock()
    mock_session.bind = MagicMock()
    mock_session.bind.dialect.name = "postgresql"

    ingester = TemplateCatalogIngester(db_session=mock_session)
    count = await ingester.ingest_batch(
        templates=[m1, m2],
        upstream_revision="abcdef0123456789abcdef0123456789abcdef01",
        batch_size=1,
    )

    assert count == 2
    # Verify execute was called for each batch of size 1 (2 batches)
    assert mock_session.execute.call_count == 2
    # Verify commit was called
    assert mock_session.commit.call_count == 1


@pytest.mark.asyncio
async def test_ingester_empty_batch():
    """Ingesting an empty list returns 0 and does not execute queries."""
    mock_session = AsyncMock()
    ingester = TemplateCatalogIngester(db_session=mock_session)
    count = await ingester.ingest_batch(templates=[], upstream_revision="none")
    assert count == 0
    assert mock_session.execute.call_count == 0
