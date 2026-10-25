import asyncio
import os
import yaml
from pathlib import Path
from sqlalchemy import select
from pentefino_domain.session import get_async_session
from pentefino_domain.models.template import TemplateCatalog
from pentefino_domain.models.program import Program
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.observation import Observation

async def main():
    target_dirs = [
        Path("storage/templates/nuclei-templates/http/technologies"),
        Path("storage/templates/nuclei-templates/http/misconfiguration"),
        Path("storage/templates/nuclei-templates/http/vulnerabilities/nextjs"),
        Path("storage/templates/nuclei-templates/http/exposures/configs"),
        Path("storage/templates/nuclei-templates/http/exposures/files"),
    ]

    templates_to_add = []
    print("[+] Collecting YAML templates from target directories...")

    for d in target_dirs:
        if not d.is_dir():
            continue
        for yf in d.rglob("*.yaml"):
            try:
                content = yf.read_text(encoding="utf-8", errors="replace")
                docs = list(yaml.safe_load_all(content))
                data = docs[0] if docs and isinstance(docs[0], dict) else {}
                tid = data.get("id") or yf.stem
                info = data.get("info") or {}
                name = info.get("name") or tid
                severity = (info.get("severity") or "info").lower()
                tags_raw = info.get("tags") or ""
                tags = [t.strip().lower() for t in tags_raw.split(",") if t.strip()] if isinstance(tags_raw, str) else []
                techs = [t for t in tags if t not in ("cve", "rce", "sqli", "xss")]
                cls = info.get("classification") or {}
                cve_id = cls.get("cve-id") if isinstance(cls, dict) else None
                cwe_id = cls.get("cwe-id") if isinstance(cls, dict) else None
                if isinstance(cwe_id, list) and cwe_id:
                    cwe_id = str(cwe_id[0])

                impact_class = "safe_read_only"
                if any(x in tags for x in ("rce", "sqli", "intrusive", "dos", "fuzz")):
                    impact_class = "active_reviewed"

                templates_to_add.append({
                    "id": tid,
                    "file_path": str(yf.relative_to(Path("storage/templates/nuclei-templates"))),
                    "upstream_revision": "official-v3.3.5",
                    "bundle_hash": "a" * 64,
                    "name": name[:120],
                    "protocol": "http",
                    "http_methods": ["GET"],
                    "impact_class": impact_class,
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "severity": severity,
                    "technologies": techs or None,
                    "tags": tags or None,
                    "raw_yaml": content[:1000],
                })
            except Exception:
                continue

    print(f"[+] Parsed {len(templates_to_add)} templates! Upserting into PostgreSQL...")
    async with get_async_session() as session:
        for t in templates_to_add:
            existing = (await session.execute(select(TemplateCatalog).where(TemplateCatalog.id == t["id"]))).scalar_one_or_none()
            if not existing:
                cat = TemplateCatalog(**t)
                session.add(cat)
            else:
                existing.technologies = t["technologies"]
                existing.tags = t["tags"]
                existing.severity = t["severity"]
                existing.impact_class = t["impact_class"]
        await session.commit()
        print(f"[SUCCESS] Upserted {len(templates_to_add)} templates into template_catalog!")

        # Now link Observation for docq and www.docq.app
        prog = (await session.execute(select(Program).where(Program.slug == "docq"))).scalar_one_or_none()
        if not prog:
            prog = Program(
                slug="docq",
                name="DocQ bounty",
                platform="lab",
                state="active",
                default_policy_id="lab-permissive",
            )
            session.add(prog)
            await session.commit()
            await session.refresh(prog)

        asset = (await session.execute(select(Asset).where(Asset.program_id == prog.id, Asset.canonical_key == "www.docq.app"))).scalar_one_or_none()
        if not asset:
            asset = Asset(
                program_id=prog.id,
                canonical_key="www.docq.app",
                asset_type="domain",
                scope_state="in_scope_explicit",
            )
            session.add(asset)
            await session.commit()
            await session.refresh(asset)

        # Upsert Observation with detected technologies
        obs = (await session.execute(select(Observation).where(Observation.asset_id == asset.id))).scalar_one_or_none()
        if not obs:
            obs = Observation(
                asset_id=asset.id,
                observation_type="http_probe",
                metadata_json={
                    "url": "https://www.docq.app",
                    "title": "DocQ",
                    "server": "cloudflare",
                    "technologies": ["next.js", "cloudflare", "node"],
                    "status_code": 200,
                },
            )
            session.add(obs)
            await session.commit()
            print("[+] Observation recorded for www.docq.app: technologies = ['next.js', 'cloudflare', 'node']")
        else:
            obs.metadata_json = {
                "url": "https://www.docq.app",
                "title": "DocQ",
                "server": "cloudflare",
                "technologies": ["next.js", "cloudflare", "node"],
                "status_code": 200,
            }
            await session.commit()
            print("[+] Observation updated for www.docq.app.")

if __name__ == "__main__":
    asyncio.run(main())
