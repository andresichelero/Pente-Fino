import re
from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel, Field

from pentefino_domain.enums import ImpactClass
from pentefino_template_indexer.bundle import compute_bundle_hash


class TemplateMetadata(BaseModel):
    """Normalized metadata and static impact classification for a Nuclei template."""

    id: str
    name: str
    protocol: str
    http_methods: list[str] = Field(default_factory=list)
    impact_class: ImpactClass
    cve_id: str | None = None
    cwe_id: str | None = None
    severity: str | None = None
    technologies: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    bundle_hash: str
    raw_yaml: str


# Regex patterns for CVE and CWE extraction
CVE_REGEX = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
CWE_REGEX = re.compile(r"CWE-\d+", re.IGNORECASE)

# Intrusive tags and attack types triggering INTRUSIVE classification
INTRUSIVE_TAGS = {
    "dos",
    "ddos",
    "fuzz",
    "fuzzing",
    "intrusive",
    "bruteforce",
    "brute-force",
    "stress",
    "exhaustion",
    "bomb",
    "denial-of-service",
}
INTRUSIVE_ATTACK_TYPES = {"clusterbomb", "pitchfork", "batteringram"}

# Mutating HTTP methods
MUTATING_METHODS = {"PUT", "DELETE", "PATCH"}

# Keywords indicating mutating/stateful POST operations in URL path or body
MUTATING_PATH_KEYWORDS = re.compile(
    r"/(create|register|signup|new|delete|remove|drop|update|edit|modify|"
    r"reset-password|forgot-password|change-password|upload|install|setup|"
    r"import|save|store|insert|write|set|destroy|cancel)\b",
    re.IGNORECASE,
)

# Known technologies dictionary for fingerprint extraction
KNOWN_TECHNOLOGIES = {
    "apache",
    "nginx",
    "iis",
    "tomcat",
    "caddy",
    "lighttpd",
    "traefik",
    "envoy",
    "wordpress",
    "drupal",
    "joomla",
    "magento",
    "ghost",
    "strapi",
    "php",
    "python",
    "ruby",
    "rails",
    "django",
    "flask",
    "fastapi",
    "laravel",
    "symfony",
    "spring",
    "spring-boot",
    "struts",
    "java",
    "jboss",
    "weblogic",
    "websphere",
    "coldfusion",
    "nodejs",
    "express",
    "nextjs",
    "react",
    "vue",
    "angular",
    "golang",
    "dotnet",
    "aspnet",
    "jenkins",
    "gitlab",
    "github",
    "jira",
    "confluence",
    "sonarqube",
    "artifactory",
    "grafana",
    "kibana",
    "prometheus",
    "elasticsearch",
    "elastic",
    "solr",
    "opensearch",
    "redis",
    "memcached",
    "rabbitmq",
    "activemq",
    "kafka",
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "oracle",
    "mssql",
    "mongodb",
    "couchdb",
    "keycloak",
    "shibboleth",
    "auth0",
    "okta",
    "cisco",
    "fortinet",
    "paloalto",
    "sonicwall",
    "f5",
    "citrix",
    "pulse",
    "juniper",
    "geoserver",
    "owncloud",
    "nextcloud",
    "roundcube",
    "zimbra",
    "swagger",
    "openapi",
    "graphql",
    "soap",
    "xmlrpc",
}


class StaticTemplateClassifier:
    """Inspects Nuclei template YAML definitions and deterministically classifies impact."""

    def classify_file(self, file_path: Path | str) -> TemplateMetadata:
        path = Path(file_path)
        raw_yaml = path.read_text(encoding="utf-8")
        return self.classify_yaml(raw_yaml, base_dir=path.parent)

    def classify_yaml(self, raw_yaml: str, base_dir: Path | None = None) -> TemplateMetadata:
        if not raw_yaml or not raw_yaml.strip():
            raise ValueError("Template YAML is empty")

        try:
            data = yaml.safe_load(raw_yaml)
        except Exception as e:
            raise ValueError(f"Failed to parse YAML: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("Invalid Nuclei template: root must be a YAML mapping")

        template_id = str(data.get("id") or "").strip()
        if not template_id:
            raise ValueError("Invalid Nuclei template: missing required 'id' field")

        info = data.get("info")
        if not isinstance(info, dict):
            info = {}

        name = str(info.get("name") or template_id).strip()

        # 1. Protocol Detection
        protocol = self._detect_protocol(data)

        # 2. HTTP Methods Extraction
        http_methods = self._extract_http_methods(data, protocol)

        # 3. Tags & Technology Extraction
        tags = self._extract_tags(info)
        technologies = self._extract_technologies(info, tags, template_id)

        # 4. CVE / CWE Extraction
        cve_id = self._extract_cve(info, template_id, tags)
        cwe_id = self._extract_cwe(info, template_id, tags)

        # 5. Severity Normalization
        raw_severity = info.get("severity")
        severity = str(raw_severity).strip().lower() if raw_severity else "info"

        # 6. Bundle Digest Computation
        bundle_hash = compute_bundle_hash(raw_yaml, base_dir, parsed_data=data)

        # 7. Static Impact Classification
        impact_class = self._determine_impact_class(
            data=data,
            protocol=protocol,
            http_methods=http_methods,
            tags=tags,
        )

        return TemplateMetadata(
            id=template_id,
            name=name,
            protocol=protocol,
            http_methods=http_methods,
            impact_class=impact_class,
            cve_id=cve_id,
            cwe_id=cwe_id,
            severity=severity,
            technologies=technologies,
            tags=tags,
            bundle_hash=bundle_hash,
            raw_yaml=raw_yaml,
        )

    def _detect_protocol(self, data: dict[str, Any]) -> str:
        if "code" in data:
            return "code"
        if "headless" in data:
            return "headless"
        if "javascript" in data or "js" in data:
            return "code"
        if "http" in data or "requests" in data:
            return "http"
        if "dns" in data:
            return "dns"
        if "ssl" in data or "tls" in data:
            return "ssl"
        if "tcp" in data or "network" in data:
            return "tcp"
        if "websocket" in data or "ws" in data:
            return "websocket"
        if "whois" in data:
            return "whois"
        if "file" in data:
            return "file"
        type_field = data.get("type")
        if isinstance(type_field, str):
            return type_field.lower().strip()
        return "unknown"

    def _extract_http_methods(self, data: dict[str, Any], protocol: str) -> list[str]:
        if protocol != "http":
            return []

        methods: list[str] = []
        raw_http = data.get("http") or data.get("requests")
        if not isinstance(raw_http, list):
            return methods

        method_line_regex = re.compile(
            r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b",
            re.MULTILINE,
        )

        for step in raw_http:
            if not isinstance(step, dict):
                continue

            # Standard method declaration
            if "method" in step:
                m = str(step["method"]).upper().strip()
                if m and m not in methods:
                    methods.append(m)

            # Raw request blocks
            raw_blocks = step.get("raw")
            if isinstance(raw_blocks, list):
                for raw_req in raw_blocks:
                    if isinstance(raw_req, str):
                        match = method_line_regex.search(raw_req)
                        if match:
                            m = match.group(1).upper()
                            if m not in methods:
                                methods.append(m)

        return methods

    def _extract_tags(self, info: dict[str, Any]) -> list[str]:
        raw_tags = info.get("tags")
        tag_list: list[str] = []

        if isinstance(raw_tags, str):
            items = raw_tags.split(",")
        elif isinstance(raw_tags, list):
            items = [str(x) for x in raw_tags]
        else:
            items = []

        for item in items:
            cleaned = item.strip().lower()
            if cleaned and cleaned not in tag_list:
                tag_list.append(cleaned)

        return tag_list

    def _extract_technologies(
        self, info: dict[str, Any], tags: list[str], template_id: str
    ) -> list[str]:
        techs: list[str] = []

        # 1. From info.metadata
        metadata = info.get("metadata")
        if isinstance(metadata, dict):
            for field in ("product", "vendor", "framework", "technology", "app", "software"):
                val = metadata.get(field)
                if isinstance(val, str):
                    for v in val.split(","):
                        c = v.strip().lower()
                        if c and c not in techs:
                            techs.append(c)
                elif isinstance(val, list):
                    for v in val:
                        c = str(v).strip().lower()
                        if c and c not in techs:
                            techs.append(c)

        # 2. Cross-reference tags with known technologies
        for tag in tags:
            if tag in KNOWN_TECHNOLOGIES and tag not in techs:
                techs.append(tag)

        # 3. Check template id for explicit technology prefix (e.g. apache-*, nginx-*)
        for known in KNOWN_TECHNOLOGIES:
            if template_id.lower().startswith(f"{known}-") and known not in techs:
                techs.append(known)

        return techs

    def _extract_cve(
        self, info: dict[str, Any], template_id: str, tags: list[str]
    ) -> str | None:
        # Check classification
        classification = info.get("classification")
        if isinstance(classification, dict):
            cve_val = classification.get("cve-id")
            if isinstance(cve_val, str) and cve_val.strip():
                return cve_val.strip().upper()
            if isinstance(cve_val, list) and cve_val:
                return str(cve_val[0]).strip().upper()

        # Check template ID
        id_match = CVE_REGEX.search(template_id)
        if id_match:
            return id_match.group(0).upper()

        # Check tags
        for tag in tags:
            tag_match = CVE_REGEX.search(tag)
            if tag_match:
                return tag_match.group(0).upper()

        return None

    def _extract_cwe(
        self, info: dict[str, Any], template_id: str, tags: list[str]
    ) -> str | None:
        classification = info.get("classification")
        if isinstance(classification, dict):
            cwe_val = classification.get("cwe-id")
            if isinstance(cwe_val, str) and cwe_val.strip():
                return cwe_val.strip().upper()
            if isinstance(cwe_val, list) and cwe_val:
                return str(cwe_val[0]).strip().upper()

        id_match = CWE_REGEX.search(template_id)
        if id_match:
            return id_match.group(0).upper()

        for tag in tags:
            tag_match = CWE_REGEX.search(tag)
            if tag_match:
                return tag_match.group(0).upper()

        return None

    def _determine_impact_class(
        self,
        data: dict[str, Any],
        protocol: str,
        http_methods: list[str],
        tags: list[str],
    ) -> ImpactClass:
        # 1. LAB_ONLY Gate: code protocol, headless automation, javascript, or local execution
        if protocol in ("code", "headless", "javascript", "js"):
            return ImpactClass.LAB_ONLY
        if (
            "code" in data
            or "headless" in data
            or "javascript" in data
            or "js" in data
        ):
            return ImpactClass.LAB_ONLY

        # 2. INTRUSIVE Gate: DoS, fuzzing, clusterbomb payloads, extreme request multipliers
        if any(t in INTRUSIVE_TAGS for t in tags):
            return ImpactClass.INTRUSIVE

        raw_http = data.get("http") or data.get("requests") or []
        if isinstance(raw_http, list):
            for step in raw_http:
                if isinstance(step, dict):
                    attack_type = str(step.get("attack-type") or "").strip().lower()
                    if attack_type in INTRUSIVE_ATTACK_TYPES:
                        return ImpactClass.INTRUSIVE

                    # High max-request check (> 100 requests indicates fuzzing/brute force)
                    max_req = step.get("max-request")
                    if isinstance(max_req, (int, float)) and max_req > 100:
                        return ImpactClass.INTRUSIVE

                    # Threads check (> 50)
                    threads = step.get("threads")
                    if isinstance(threads, (int, float)) and threads > 50:
                        return ImpactClass.INTRUSIVE

                    # Payload count check (> 100 entries indicates fuzzing/bruteforce)
                    payloads = step.get("payloads")
                    if isinstance(payloads, dict):
                        total_payloads = sum(
                            len(v) if isinstance(v, list) else 1
                            for v in payloads.values()
                        )
                        if total_payloads > 100:
                            return ImpactClass.INTRUSIVE

        # 3. STATEFUL Mutating Verbs Gate (PUT, DELETE, PATCH)
        if any(m in MUTATING_METHODS for m in http_methods):
            return ImpactClass.STATEFUL

        # 4. POST Method Inspection: Analytical Read-Only vs Stateful
        if "POST" in http_methods:
            if self._is_analytical_post(raw_http):
                return ImpactClass.SAFE_READ_ONLY
            return ImpactClass.STATEFUL

        # 5. Pure Read-Only HTTP: GET, HEAD, OPTIONS
        if protocol == "http":
            if not http_methods or all(m in ("GET", "HEAD", "OPTIONS") for m in http_methods):
                return ImpactClass.SAFE_READ_ONLY
            return ImpactClass.ACTIVE_REVIEWED

        # 6. Passive / Read-Only Network Protocols
        if protocol in ("dns", "ssl", "whois", "file"):
            return ImpactClass.SAFE_READ_ONLY

        # 7. Raw TCP / Probing Protocols
        if protocol == "tcp":
            return ImpactClass.ACTIVE_REVIEWED

        # 8. Default fallback: active_reviewed
        return ImpactClass.ACTIVE_REVIEWED

    def _is_analytical_post(self, raw_http: list[Any]) -> bool:
        """
        Evaluate whether a POST request is strictly analytical, idempotent, and non-mutating.

        Criteria:
        - No file uploads (multipart/form-data, Content-Disposition: form-data, upload headers).
        - No mutating paths (e.g. /create, /register, /signup, /delete, /upload, /reset-password).
        - Matches recognized analytical query patterns (GraphQL introspection, SOAP version, XML-RPC introspection, JSON-RPC read).
        """
        found_analytical_pattern = False

        for step in raw_http:
            if not isinstance(step, dict):
                continue

            method = str(step.get("method") or "").upper().strip()
            raw_blocks = step.get("raw") or []

            # Check if this step uses POST
            is_post_step = method == "POST"
            if not is_post_step and isinstance(raw_blocks, list):
                for block in raw_blocks:
                    if isinstance(block, str) and re.search(r"^\s*POST\b", block, re.MULTILINE):
                        is_post_step = True
                        break

            if not is_post_step:
                continue

            # Gather path, headers, and body for inspection
            paths: list[str] = []
            if "path" in step:
                p_val = step["path"]
                if isinstance(p_val, list):
                    paths.extend(str(x) for x in p_val)
                elif isinstance(p_val, str):
                    paths.append(p_val)

            headers_text = ""
            if "headers" in step:
                h_val = step["headers"]
                if isinstance(h_val, dict):
                    headers_text = " ".join(f"{k}: {v}" for k, v in h_val.items())
                elif isinstance(h_val, list):
                    headers_text = " ".join(str(x) for x in h_val)

            body_text = str(step.get("body") or "")

            if isinstance(raw_blocks, list):
                for block in raw_blocks:
                    if isinstance(block, str):
                        # Extract first line for path
                        lines = block.strip().splitlines()
                        if lines:
                            first_line = lines[0]
                            parts = first_line.split()
                            if len(parts) >= 2:
                                paths.append(parts[1])
                        # Append raw text to inspect body and headers
                        body_text += " " + block
                        headers_text += " " + block

            # Check 1: Mutating Path Check
            for path in paths:
                if MUTATING_PATH_KEYWORDS.search(path):
                    return False

            # Check 2: File Upload Check
            combined_text = (headers_text + " " + body_text).lower()
            if "multipart/form-data" in combined_text or "content-disposition: form-data" in combined_text:
                return False
            if "filename=" in combined_text and "name=" in combined_text:
                return False

            # Check 2b: Mutating GraphQL query
            if re.search(r"\bmutation\b", body_text, re.IGNORECASE):
                return False

            # Check 3: Analytical Pattern Matching
            # A. GraphQL Introspection Query
            if (
                "__schema" in body_text
                or "introspectionquery" in body_text.lower()
                or "__type" in body_text
            ):
                found_analytical_pattern = True
                continue

            # B. SOAP Version / Diagnostic inquiry
            is_soap = (
                "schemas.xmlsoap.org" in combined_text
                or "soapenv:" in combined_text
                or "soap:" in combined_text
                or "soapaction" in combined_text
                or "<envelope" in combined_text
                or "<soapenv" in combined_text
            )
            if is_soap and any(
                k in combined_text
                for k in (
                    "version",
                    "status",
                    "getserverversion",
                    "getversion",
                    "getserverstatus",
                    "getserverinfo",
                    "systeminfo",
                    "ping",
                )
            ):
                found_analytical_pattern = True
                continue

            # C. XML-RPC Introspection / Ping
            if (
                "system.listmethods" in combined_text
                or "system.methodsignature" in combined_text
                or "system.methodhelp" in combined_text
                or "demo.sayhello" in combined_text
            ):
                found_analytical_pattern = True
                continue

            # D. JSON-RPC Read-Only / Version Inquiry
            if (
                "web3_clientversion" in combined_text
                or "eth_blocknumber" in combined_text
                or '"method": "version"' in combined_text
                or '"method":"version"' in combined_text
                or '"method": "system_info"' in combined_text
            ):
                found_analytical_pattern = True
                continue

            # If a POST step does not match any analytical pattern, fail safe
            return False

        return found_analytical_pattern
