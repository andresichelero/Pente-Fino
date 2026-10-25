import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone
from sqlalchemy import select
from pentefino_domain.session import get_async_session
from pentefino_domain.models.program import Program
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.template import TemplateCatalog
from pentefino_domain.models.finding import Finding
from pentefino_domain.models.evidence import Evidence
from pentefino_domain.dedup import compute_finding_dedup_key
from pentefino_proxy.s3_client import S3EvidenceClient


def calc_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def seed():
    s3_client = S3EvidenceClient()
    s3_client.ensure_bucket("evidence")

    async with get_async_session() as session:
        print("[+] Ensuring templates exist in catalog...")
        templates_data = [
            {
                "id": "altoro-sqli-login",
                "name": "Altoro Mutual SQL Injection on /login.jsp (Authentication Bypass)",
                "protocol": "http",
                "http_methods": ["POST"],
                "impact_class": "lab_only",
                "cve_id": "CVE-2023-38606",
                "cwe_id": "CWE-89",
                "severity": "critical",
                "technologies": ["Apache-Coyote", "JSP", "MySQL"],
                "tags": ["sqli", "auth-bypass", "cwe-89", "owasp-top10"],
                "raw_yaml": "id: altoro-sqli-login\ninfo:\n  name: Altoro Mutual SQL Injection\n  severity: critical\n  classification:\n    cwe-id: CWE-89\n",
            },
            {
                "id": "altoro-xss-search",
                "name": "Altoro Mutual Reflected Cross-Site Scripting (XSS) on /search.jsp",
                "protocol": "http",
                "http_methods": ["GET"],
                "impact_class": "safe_read_only",
                "cve_id": None,
                "cwe_id": "CWE-79",
                "severity": "high",
                "technologies": ["Apache-Coyote", "JSP"],
                "tags": ["xss", "reflected", "cwe-79", "owasp-top10"],
                "raw_yaml": "id: altoro-xss-search\ninfo:\n  name: Altoro Mutual Reflected XSS\n  severity: high\n  classification:\n    cwe-id: CWE-79\n",
            },
            {
                "id": "apache-coyote-version-disclosure",
                "name": "Apache Tomcat / Coyote Server Header Version Disclosure",
                "protocol": "http",
                "http_methods": ["GET"],
                "impact_class": "passive",
                "cve_id": None,
                "cwe_id": "CWE-200",
                "severity": "info",
                "technologies": ["Apache-Coyote", "Tomcat"],
                "tags": ["disclosure", "header", "cwe-200"],
                "raw_yaml": "id: apache-coyote-version-disclosure\ninfo:\n  name: Apache Coyote Version Disclosure\n  severity: info\n  classification:\n    cwe-id: CWE-200\n",
            },
            {
                "id": "dvwa-command-exec",
                "name": "DVWA OS Command Injection on /vulnerabilities/exec/",
                "protocol": "http",
                "http_methods": ["POST"],
                "impact_class": "lab_only",
                "cve_id": "CVE-2021-3129",
                "cwe_id": "CWE-78",
                "severity": "critical",
                "technologies": ["PHP", "Apache", "Linux"],
                "tags": ["rce", "command-injection", "cwe-78", "dvwa"],
                "raw_yaml": "id: dvwa-command-exec\ninfo:\n  name: DVWA OS Command Injection\n  severity: critical\n  classification:\n    cwe-id: CWE-78\n",
            },
            {
                "id": "dvwa-stored-xss",
                "name": "DVWA Stored Cross-Site Scripting (XSS) on /vulnerabilities/xss_s/",
                "protocol": "http",
                "http_methods": ["POST", "GET"],
                "impact_class": "lab_only",
                "cve_id": None,
                "cwe_id": "CWE-79",
                "severity": "high",
                "technologies": ["PHP", "MySQL", "Apache"],
                "tags": ["xss", "stored", "cwe-79", "dvwa"],
                "raw_yaml": "id: dvwa-stored-xss\ninfo:\n  name: DVWA Stored XSS\n  severity: high\n  classification:\n    cwe-id: CWE-79\n",
            },
        ]

        for t in templates_data:
            existing = (await session.execute(select(TemplateCatalog).where(TemplateCatalog.id == t["id"]))).scalar_one_or_none()
            if not existing:
                cat = TemplateCatalog(
                    id=t["id"],
                    file_path=f"nuclei-templates/custom/{t['id']}.yaml",
                    upstream_revision="official-v3.3.0",
                    bundle_hash="a" * 64,
                    name=t["name"],
                    protocol=t["protocol"],
                    http_methods=t["http_methods"],
                    impact_class=t["impact_class"],
                    cve_id=t["cve_id"],
                    cwe_id=t["cwe_id"],
                    severity=t["severity"],
                    technologies=t["technologies"],
                    tags=t["tags"],
                    raw_yaml=t["raw_yaml"],
                )
                session.add(cat)
        await session.commit()
        print("[+] Templates synchronized.")

        # 1. Target: Altoro Mutual (testfire-lab)
        print("[+] Processing testfire-lab...")
        testfire_prog = (await session.execute(select(Program).where(Program.slug == "testfire-lab"))).scalar_one_or_none()
        if not testfire_prog:
            testfire_prog = Program(
                slug="testfire-lab",
                name="Altoro Mutual Sandbox (demo.testfire.net)",
                platform="lab",
                state="active",
                default_policy_id="lab-permissive",
            )
            session.add(testfire_prog)
            await session.commit()
            await session.refresh(testfire_prog)

        testfire_asset = (await session.execute(select(Asset).where(Asset.program_id == testfire_prog.id, Asset.canonical_key == "demo.testfire.net"))).scalar_one_or_none()
        if not testfire_asset:
            testfire_asset = Asset(
                program_id=testfire_prog.id,
                canonical_key="demo.testfire.net",
                asset_type="domain",
                scope_state="in_scope_explicit",
            )
            session.add(testfire_asset)
            await session.commit()
            await session.refresh(testfire_asset)

        # 2. Target: DVWA (dvwa-lab)
        print("[+] Processing dvwa-lab...")
        dvwa_prog = (await session.execute(select(Program).where(Program.slug == "dvwa-lab"))).scalar_one_or_none()
        if not dvwa_prog:
            dvwa_prog = Program(
                slug="dvwa-lab",
                name="Damn Vulnerable Web Application (DVWA)",
                platform="lab",
                state="active",
                default_policy_id="lab-permissive",
            )
            session.add(dvwa_prog)
            await session.commit()
            await session.refresh(dvwa_prog)

        dvwa_asset = (await session.execute(select(Asset).where(Asset.program_id == dvwa_prog.id, Asset.canonical_key == "127.0.0.1:8088"))).scalar_one_or_none()
        if not dvwa_asset:
            dvwa_asset = Asset(
                program_id=dvwa_prog.id,
                canonical_key="127.0.0.1:8088",
                asset_type="url",
                scope_state="in_scope_explicit",
            )
            session.add(dvwa_asset)
            await session.commit()
            await session.refresh(dvwa_asset)

        run_id = uuid.uuid4()

        # Seed Findings Definition
        findings_to_seed = [
            # Finding 1: Altoro SQLi
            {
                "program": testfire_prog,
                "asset": testfire_asset,
                "port": 443,
                "path": "/login.jsp",
                "detector_id": "altoro-sqli-login",
                "advisory_id": "CWE-89 / CVE-2023-38606",
                "status": "validated",
                "evidence_level": "E2",
                "confidence": "high",
                "epss_score": 0.9752,
                "epss_percentile": 0.9991,
                "in_cisa_kev": True,
                "priority_tier": "critical_kev",
                "evidence_payload": {
                    "request": {
                        "method": "POST",
                        "url": "https://demo.testfire.net/login.jsp",
                        "headers": {
                            "Host": "demo.testfire.net",
                            "User-Agent": "PenteFino-SecScanner/2.1",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
                        },
                        "body": "uid=admin'%20OR%20'1'='1&pass=bounty_audit_pass&btnSubmit=Login",
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {
                            "Date": "Sun, 25 Oct 2026 05:00:00 GMT",
                            "Server": "Apache-Coyote/1.1",
                            "Set-Cookie": "JSESSIONID=4F9A7B3E91823C4D5E6F7A8B9C0D1E2F; Path=/; HttpOnly",
                            "Content-Type": "text/html;charset=ISO-8859-1",
                            "Content-Length": "3842",
                        },
                        "body": "<html><body><h2>Welcome, Admin User!</h2><div class='account-balance'>Checking Account: $8,420.50</div><div class='success'>Authentication Bypass Confirmed</div></body></html>",
                    },
                    "matched_at": "https://demo.testfire.net/login.jsp",
                    "extracted_results": ["Welcome, Admin User!", "Checking Account: $8,420.50"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            },
            # Finding 2: Altoro Reflected XSS
            {
                "program": testfire_prog,
                "asset": testfire_asset,
                "port": 443,
                "path": "/search.jsp",
                "detector_id": "altoro-xss-search",
                "advisory_id": "CWE-79",
                "status": "validated",
                "evidence_level": "E2",
                "confidence": "high",
                "epss_score": 0.7410,
                "epss_percentile": 0.9650,
                "in_cisa_kev": False,
                "priority_tier": "high_epss",
                "evidence_payload": {
                    "request": {
                        "method": "GET",
                        "url": "https://demo.testfire.net/search.jsp?query=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E",
                        "headers": {
                            "Host": "demo.testfire.net",
                            "User-Agent": "PenteFino-SecScanner/2.1",
                            "Accept": "text/html,application/xhtml+xml",
                        },
                        "body": "",
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {
                            "Server": "Apache-Coyote/1.1",
                            "Content-Type": "text/html;charset=ISO-8859-1",
                            "X-XSS-Protection": "0",
                        },
                        "body": "<html><body><h1>Search Results</h1><p>You searched for: <script>alert(document.domain)</script></p><p>0 results found.</p></body></html>",
                    },
                    "matched_at": "https://demo.testfire.net/search.jsp?query=<script>alert(document.domain)</script>",
                    "extracted_results": ["<script>alert(document.domain)</script>"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            },
            # Finding 3: Altoro Server Header Version Disclosure
            {
                "program": testfire_prog,
                "asset": testfire_asset,
                "port": 443,
                "path": "/",
                "detector_id": "apache-coyote-version-disclosure",
                "advisory_id": "CWE-200",
                "status": "candidate",
                "evidence_level": "E1",
                "confidence": "high",
                "epss_score": 0.0012,
                "epss_percentile": 0.1500,
                "in_cisa_kev": False,
                "priority_tier": "standard",
                "evidence_payload": {
                    "request": {
                        "method": "GET",
                        "url": "https://demo.testfire.net/",
                        "headers": {
                            "Host": "demo.testfire.net",
                            "User-Agent": "PenteFino-SecScanner/2.1",
                        },
                        "body": "",
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {
                            "Server": "Apache-Coyote/1.1",
                            "Content-Type": "text/html",
                        },
                        "body": "<html><head><title>Altoro Mutual</title></head><body><h1>Altoro Mutual</h1></body></html>",
                    },
                    "matched_at": "https://demo.testfire.net/",
                    "extracted_results": ["Server: Apache-Coyote/1.1"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            },
            # Finding 4: DVWA Command Injection
            {
                "program": dvwa_prog,
                "asset": dvwa_asset,
                "port": 8088,
                "path": "/vulnerabilities/exec/",
                "detector_id": "dvwa-command-exec",
                "advisory_id": "CWE-78 / CVE-2021-3129",
                "status": "validated",
                "evidence_level": "E2",
                "confidence": "high",
                "epss_score": 0.9420,
                "epss_percentile": 0.9880,
                "in_cisa_kev": True,
                "priority_tier": "critical_kev",
                "evidence_payload": {
                    "request": {
                        "method": "POST",
                        "url": "http://127.0.0.1:8088/vulnerabilities/exec/",
                        "headers": {
                            "Host": "127.0.0.1:8088",
                            "User-Agent": "PenteFino-SecScanner/2.1",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Cookie": "PHPSESSID=08f82da74e1d1cb53528f8f9d0c2424b; security=low",
                        },
                        "body": "ip=127.0.0.1%3Bid%3Buname+-a&Submit=Submit",
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {
                            "Server": "Apache/2.4.25 (Debian)",
                            "Content-Type": "text/html;charset=UTF-8",
                        },
                        "body": "<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.031 ms\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux pentefino_dvwa 5.15.167.4-microsoft-standard-WSL2 #1 SMP x86_64 GNU/Linux</pre>",
                    },
                    "matched_at": "http://127.0.0.1:8088/vulnerabilities/exec/",
                    "extracted_results": [
                        "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                        "Linux pentefino_dvwa 5.15.167.4-microsoft-standard-WSL2",
                    ],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            },
            # Finding 5: DVWA Stored XSS
            {
                "program": dvwa_prog,
                "asset": dvwa_asset,
                "port": 8088,
                "path": "/vulnerabilities/xss_s/",
                "detector_id": "dvwa-stored-xss",
                "advisory_id": "CWE-79",
                "status": "candidate",
                "evidence_level": "E2",
                "confidence": "high",
                "epss_score": 0.6850,
                "epss_percentile": 0.9410,
                "in_cisa_kev": False,
                "priority_tier": "high_epss",
                "evidence_payload": {
                    "request": {
                        "method": "POST",
                        "url": "http://127.0.0.1:8088/vulnerabilities/xss_s/",
                        "headers": {
                            "Host": "127.0.0.1:8088",
                            "User-Agent": "PenteFino-SecScanner/2.1",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Cookie": "PHPSESSID=08f82da74e1d1cb53528f8f9d0c2424b; security=low",
                        },
                        "body": "txtName=SecurityResearcher&mtxMessage=%3Cscript%3Econsole.log%28%22DVWA_STORED_XSS_VERIFIED%22%29%3C%2Fscript%3E&btnSign=Sign+Guestbook",
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {
                            "Server": "Apache/2.4.25 (Debian)",
                            "Content-Type": "text/html;charset=UTF-8",
                        },
                        "body": "<div id=\"guestbook_comments\">Name: SecurityResearcher<br />Message: <script>console.log(\"DVWA_STORED_XSS_VERIFIED\")</script></div>",
                    },
                    "matched_at": "http://127.0.0.1:8088/vulnerabilities/xss_s/",
                    "extracted_results": ["<script>console.log(\"DVWA_STORED_XSS_VERIFIED\")</script>"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            },
        ]

        for item in findings_to_seed:
            prog = item["program"]
            asset = item["asset"]
            dedup = compute_finding_dedup_key(
                program_id=prog.id,
                canonical_asset=asset.canonical_key,
                port=item["port"],
                normalized_path=item["path"],
                detector_id=item["detector_id"],
            )

            # Check if finding already exists
            existing_f = (await session.execute(
                select(Finding).where(Finding.program_id == prog.id, Finding.dedup_key == dedup)
            )).scalar_one_or_none()

            if not existing_f:
                f = Finding(
                    program_id=prog.id,
                    asset_id=asset.id,
                    dedup_key=dedup,
                    detector_id=item["detector_id"],
                    advisory_id=item["advisory_id"],
                    status=item["status"],
                    evidence_level=item["evidence_level"],
                    confidence=item["confidence"],
                    epss_score=item["epss_score"],
                    epss_percentile=item["epss_percentile"],
                    in_cisa_kev=item["in_cisa_kev"],
                    priority_tier=item["priority_tier"],
                )
                session.add(f)
                await session.flush()
                finding_id = f.id
                print(f"[+] Created finding: {item['detector_id']} (ID: {finding_id}, Dedup: {dedup[:12]})")
            else:
                finding_id = existing_f.id
                existing_f.status = item["status"]
                existing_f.evidence_level = item["evidence_level"]
                existing_f.epss_score = item["epss_score"]
                existing_f.epss_percentile = item["epss_percentile"]
                existing_f.in_cisa_kev = item["in_cisa_kev"]
                existing_f.priority_tier = item["priority_tier"]
                print(f"[=] Updated finding: {item['detector_id']} (ID: {finding_id})")

            # Upload raw evidence to SeaweedFS S3
            raw_json = json.dumps(item["evidence_payload"], indent=2).encode("utf-8")
            orig_hash = calc_sha256(raw_json)
            san_hash = orig_hash  # clean payload, already safe
            obj_key = f"evidence/findings/{finding_id}/http_interaction.json"

            s3_client.upload_evidence(
                artifact_data=raw_json,
                object_key=obj_key,
                content_type="application/json",
            )
            print(f"    Uploaded S3 evidence: s3://evidence/{obj_key} (SHA: {orig_hash[:12]}...)")

            # Check if evidence record exists
            existing_ev = (await session.execute(
                select(Evidence).where(Evidence.finding_id == finding_id, Evidence.seaweed_object_key == obj_key)
            )).scalar_one_or_none()

            if not existing_ev:
                ev = Evidence(
                    finding_id=finding_id,
                    run_id=run_id,
                    evidence_type="http_interaction",
                    original_sha256=orig_hash,
                    sanitized_sha256=san_hash,
                    seaweed_object_key=obj_key,
                    redaction_profile="bounty-safe-v1",
                )
                session.add(ev)

        await session.commit()
        print("\n[SUCCESS] All findings and S3 evidence artifacts seeded successfully!")

if __name__ == "__main__":
    asyncio.run(seed())
