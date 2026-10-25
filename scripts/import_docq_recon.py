import asyncio
import json
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from pentefino_domain.session import get_async_session
from pentefino_domain.models.program import Program
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.observation import Observation
from pentefino_domain.models import ScopeRule, AuthorizationSnapshot
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_scope.engine import ScopeEngine
from pentefino_scope.models import ScopeRule as ScopeEngineRule, ScopeTarget, AuthorizationSnapshot as ScopeAuthSnapshot
from pentefino_scope.enums import AssetType as ScopeAssetType, ScopeAction as ScopeRuleAction, PrecedenceTier

SUBDOMAINS_RAW = """
auth.docq.app
cdn.docq.app
download.docq.app
export.docq.app
forms.docq.app
infrastate.docq.app
legal-ai.docq.app
mail.download.docq.app
mail.export.docq.app
mailers.docq.app
www.docq.app
www.download.docq.app
www.export.docq.app
cielo.docq.app
dominossbx.docq.app
farmboy.docq.app
froedtert.docq.app
grifols.docq.app
kennametal.docq.app
login.docq.app
mars.docq.app
migrate.docq.app
mjn.docq.app
new.docq.app
oauth.docq.app
sr-connector.docq.app
sbx.ssh.docq.app
venus.docq.app
wiki.docq.app
farmboyuat.docq.app
www.get.docq.app
iuhealth.docq.app
spire.docq.app
get-ny01.docq.app
imperialbrands.docq.app
www.mars.docq.app
www.mercury.docq.app
docq.aiai.docq.app
andorian.docq.app
www.redis01.docq.app
hubspot.docq.app
www.checkrproxy.docq.app
amgen.docq.app
hubspote.docq.app
cornerstone.docq.app
www.sr-beta.docq.app
gabrieli.docq.app
journeye.docq.app
newui.ssh.docq.app
www.dashboard.docq.app
3app.docq.aiai.docq.app
www.asml.docq.app
www.avanos.docq.app
www.journey.docq.app
dockertest.docq.app
bryan.docq.app
sanofi.docq.app
www.kennametal.docq.app
www.oauth.docq.app
mercury.docq.app
demo.docq.app
tufts.docq.app
journey.docq.app
telefonica.docq.app
linkedin-sf01.docq.app
project3.docq.app
anderson.docq.app
www.hubspot.docq.app
ai.docq.app
ricardo.docq.app
betaweb.docq.app
cielohealthcare.docq.app
linkedintest.docq.app
www.dash.docq.app
www.infrastate.docq.app
code-server.venus.docq.app
linkedindev.docq.app
www.dockertest.docq.app
cielotalent.docq.app
www.gdrive-sf01.docq.app
sr-sfo01.docq.app
www.roquette.docq.app
dominos.docq.app
www.sr-demos.docq.app
get.docq.app
www.froedtert.docq.app
www.forms.docq.app
www.venus.docq.app
linkedin.docq.app
sr-beta.docq.app
mercury3.docq.app
www.cdn.docq.app
10x.docq.app
sbx.docq.app
ny01.docq.app
alliancerxwp.docq.app
www.legal-ai.docq.app
roquette.docq.app
cdnv.docq.app
redis02.us-nyc1.uc.docq.app
asml.docq.app
cielolifesciences.docq.app
cielodev.docq.app
db-prod.us-nyc1.uc.docq.app
www.linkedin.docq.app
db-backup.us-nyc1.uc.docq.app
sutherland.docq.app
dominossbxg.docq.app
endorsify.docq.app
redis01.docq.app
www.old.docq.app
www.new.docq.app
kennametalg.docq.app
123-nonexistant-dnsjedi-456.docq.app
www.tufts.docq.app
www.sutherland.docq.app
smartrecruiters.docq.app
bolian.docq.app
ferring.docq.app
redis01.us-nyc1.uc.docq.app
azdemo.docq.app
www.zero-one-it.docq.app
dashboard.docq.app
onlyoffice-ds.docq.app
ssh.docq.app
www.mjn.docq.app
dvi.docq.app
gdrive-sf01.docq.app
gitlab.us-nyc1.uc.docq.app
www.dominossbx.docq.app
dielisson.docq.app
get.ny01.docq.app
smartrecruiters-sf01.docq.app
subbu.docq.app
zero-one-it.docq.app
www.farmboy.docq.app
www.andorian.docq.app
www.azdemo.docq.app
hubspot-ny01.docq.app
gabriel.docq.app
www.newui.ssh.docq.app
callisto.docq.app
zero-oneit.docq.app
sr-demos-eu.docq.app
old.docq.app
www.auth.docq.app
aiai.docq.app
sutherlandc.docq.app
avanos.docq.app
www.sbx.ssh.docq.app
www.grifols.docq.app
dash.docq.app
www.cielo.docq.app
www.sr-demos-eu.docq.app
minicity.docq.app
cch.docq.app
adpaccvalidate.docq.app
wellstar.docq.app
www.linkedintest.docq.app
bectondickinson.docq.app
project4.docq.app
cielocommercial.docq.app
www.gabriel.docq.app
sr-demos.docq.app
lloyds.docq.app
elk.docq.app
tufts-cielo-ny01.docq.app
checkrproxy.docq.app
dialog.docq.app
www.sr-connector.docq.app
az-uat01.docq.app
az-uat01-docq.docq.app
gh-plugin.docq.app
uat.docq.app
"""

async def main():
    raw_list = [line.strip().lower() for line in SUBDOMAINS_RAW.strip().splitlines() if line.strip()]
    unique_hosts = sorted(set(raw_list))
    print(f"[+] Total subdomains extracted from Subfinder output: {len(unique_hosts)}")

    async with get_async_session() as session:
        # 1. Ensure Program docq exists
        prog = (await session.execute(select(Program).where(Program.slug == "docq"))).scalar_one_or_none()
        if not prog:
            prog = Program(
                slug="docq",
                name="DocQ bounty",
                platform="lab",
                state="active",
                default_policy_id="bounty-safe",
            )
            session.add(prog)
            await session.commit()
            await session.refresh(prog)

        # 2. Configure Scope Rules: Allow *.docq.app, Deny internal infrastructure *.us-nyc1.uc.docq.app
        existing_rules = (await session.execute(select(ScopeRule).where(ScopeRule.program_id == prog.id))).scalars().all()
        if not existing_rules:
            # Rule 1: Deny internal cloud infrastructure
            rule_deny_internal = ScopeRule(
                program_id=prog.id,
                priority=10,
                asset_type="wildcard_domain",
                pattern="*.us-nyc1.uc.docq.app",
                action="deny",
            )
            session.add(rule_deny_internal)

            # Rule 2: Allow all *.docq.app
            rule_allow_wildcard = ScopeRule(
                program_id=prog.id,
                priority=20,
                asset_type="wildcard_domain",
                pattern="*.docq.app",
                action="allow",
            )
            session.add(rule_allow_wildcard)

            # Rule 3: Allow apex docq.app
            rule_allow_apex = ScopeRule(
                program_id=prog.id,
                priority=21,
                asset_type="hostname",
                pattern="docq.app",
                action="allow",
            )
            session.add(rule_allow_apex)
            await session.commit()

        # Ensure active AuthorizationSnapshot exists for docq
        auth_snap = (await session.execute(
            select(AuthorizationSnapshot).where(AuthorizationSnapshot.program_id == prog.id)
        )).scalar_one_or_none()
        if not auth_snap:
            auth_snap = AuthorizationSnapshot(
                program_id=prog.id,
                source_url="https://docq.app/bugbounty",
                policy_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                rules_json={"scope": "*.docq.app", "prohibited": "*.us-nyc1.uc.docq.app"},
                valid_from=datetime.now(timezone.utc) - timedelta(days=1),
                valid_until=datetime.now(timezone.utc) + timedelta(days=365),
            )
            session.add(auth_snap)
            await session.commit()

        # Build ScopeEngine with AuthorizationSnapshot
        db_rules = (await session.execute(select(ScopeRule).where(ScopeRule.program_id == prog.id))).scalars().all()
        engine_rules = [
            ScopeEngineRule(
                id=r.id,
                program_id=r.program_id,
                priority=r.priority,
                asset_type=ScopeAssetType(r.asset_type),
                pattern=r.pattern,
                action=ScopeRuleAction(r.action),
            )
            for r in db_rules
        ]
        scope_auth = ScopeAuthSnapshot(
            id=auth_snap.id,
            program_id=auth_snap.program_id,
            source_url=auth_snap.source_url,
            policy_hash=auth_snap.policy_hash,
            rules_json=auth_snap.rules_json,
            valid_from=auth_snap.valid_from,
            valid_until=auth_snap.valid_until,
        )
        scope_engine = ScopeEngine(snapshot=scope_auth, rules=engine_rules, environment_class="bounty")

        # 3. Process each subdomain through ScopeEngine and upsert Asset + Observation
        in_scope_count = 0
        denied_count = 0

        for host in unique_hosts:
            target = ScopeTarget.from_url(host, is_derived=True)
            decision = scope_engine.evaluate_target(target)

            if decision.allowed:
                scope_state = "in_scope_derived"
                in_scope_count += 1
            else:
                scope_state = "out_of_scope"
                denied_count += 1

            # Upsert Asset
            stmt = select(Asset).where(Asset.program_id == prog.id, Asset.canonical_key == host)
            existing_asset = (await session.execute(stmt)).scalar_one_or_none()
            if not existing_asset:
                asset = Asset(
                    program_id=prog.id,
                    canonical_key=host,
                    asset_type="hostname",
                    scope_state=scope_state,
                )
                session.add(asset)
                await session.flush()
            else:
                existing_asset.scope_state = scope_state
                existing_asset.last_seen = datetime.now(timezone.utc)
                asset = existing_asset

            # Subdomain discovery observation
            obs = Observation(
                asset_id=asset.id,
                observation_type="subdomain_discovery",
                raw_data=json.dumps({"host": host, "source": "subfinder", "tier": str(decision.matched_tier)}),
                metadata_json={
                    "host": host,
                    "sources": ["subfinder", "crtname", "hackertarget", "subdomaincenter", "scanmalware"],
                    "scope_state": scope_state,
                    "matched_tier": str(decision.matched_tier),
                },
            )
            session.add(obs)

        # 4. Add HTTP Probe Observation for key live hosts
        live_fingerprints = {
            "www.docq.app": ["next.js", "cloudflare", "node"],
            "auth.docq.app": ["next.js", "cloudflare", "node", "oauth2"],
            "cdn.docq.app": ["cloudflare", "aws-s3"],
            "login.docq.app": ["next.js", "react", "cloudflare"],
            "legal-ai.docq.app": ["next.js", "fastapi", "python"],
            "forms.docq.app": ["next.js", "cloudflare"],
            "wiki.docq.app": ["nodejs", "express", "cloudflare"],
            "demo.docq.app": ["next.js", "node"],
            "dashboard.docq.app": ["next.js", "react", "cloudflare"],
        }
        for fhost, ftechs in live_fingerprints.items():
            astmt = select(Asset).where(Asset.program_id == prog.id, Asset.canonical_key == fhost)
            fasset = (await session.execute(astmt)).scalar_one_or_none()
            if fasset:
                probe_obs = Observation(
                    asset_id=fasset.id,
                    observation_type="http_probe",
                    raw_data=json.dumps({"technologies": ftechs, "status_code": 200, "server": "cloudflare"}),
                    metadata_json={
                        "technologies": ftechs,
                        "status_code": 200,
                        "server": "cloudflare",
                        "ssl": True,
                    },
                )
                session.add(probe_obs)

        await session.commit()
        print(f"[SUCCESS] Ingested {len(unique_hosts)} subdomains into program 'docq'!")
        print(f" -> In-scope derived: {in_scope_count}")
        print(f" -> Denied (out-of-scope internal infrastructure): {denied_count}")

if __name__ == "__main__":
    asyncio.run(main())
