"""Exercise every API route with success / invalid-input cases and print a status matrix.

Usage:
  python scripts/endpoint_matrix.py --base http://127.0.0.1:8000 --program opus-lab-docq [--key K] [--label run]

Only lab data is touched: it creates a throwaway program `matrix-<random>` with scope
`*.pentefino.test` (RFC 6761, never resolves) and uses `--program` for read-only checks.
Scans use mode=dry_run, so no traffic reaches any target. POST /intel/sync is not called
(it downloads third-party feeds).
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid

import httpx


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--program", default="opus-lab-docq")
    ap.add_argument("--key", default=None, help="X-PenteFino-Key to send (omit to test unauthenticated)")
    ap.add_argument("--label", default="run")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    headers = {"X-PenteFino-Key": args.key} if args.key else {}
    c = httpx.Client(base_url=args.base, headers=headers, timeout=60)
    slug = f"matrix-{uuid.uuid4().hex[:8]}"
    rows: list[dict] = []

    def call(name: str, method: str, path: str, expect: tuple[int, ...], **kw) -> httpx.Response | None:
        try:
            r = c.request(method, path, **kw)
            status, body = r.status_code, r.text[:160].replace("\n", " ")
        except Exception as exc:  # network error is a result too
            r, status, body = None, -1, f"{type(exc).__name__}: {exc}"[:160]
        rows.append({"case": name, "method": method, "path": path, "status": status,
                     "expected": list(expect), "ok": status in expect, "body": body})
        return r

    p = args.program
    call("health", "GET", "/api/v1/health", (200,))
    call("telemetry summary", "GET", "/api/v1/telemetry/summary", (200,))
    call("network health", "GET", "/api/v1/telemetry/network-health", (200,))
    call("live status", "GET", "/api/v1/status/live", (200,))

    call("programs list", "GET", "/api/v1/programs", (200,))
    call("program create ok", "POST", "/api/v1/programs", (200, 201),
         json={"slug": slug, "name": "Matrix lab", "platform": "hackerone"})
    call("program create invalid slug", "POST", "/api/v1/programs", (400, 422), json={"slug": "Bad Slug!!", "name": ""})
    call("program create duplicate", "POST", "/api/v1/programs", (400, 409),
         json={"slug": slug, "name": "dup", "platform": "hackerone"})
    call("program get ok", "GET", f"/api/v1/programs/{p}", (200,))
    call("program get 404", "GET", "/api/v1/programs/does-not-exist-xyz", (404,))
    call("program patch ok", "PATCH", f"/api/v1/programs/{slug}", (200,), json={"name": "Matrix lab renamed"})
    call("program patch invalid state", "PATCH", f"/api/v1/programs/{slug}", (400, 422), json={"state": "bogus"})

    call("scope list", "GET", f"/api/v1/programs/{p}/scope", (200,))
    r = call("scope add ok", "POST", f"/api/v1/programs/{slug}/scope", (200, 201),
             json={"pattern": "*.pentefino.test", "action": "allow", "asset_type": "wildcard_domain"})
    call("scope add invalid action", "POST", f"/api/v1/programs/{slug}/scope", (400, 422),
         json={"pattern": "x.test", "action": "maybe", "asset_type": "domain"})
    call("scope evaluate allow", "POST", f"/api/v1/programs/{slug}/scope/evaluate", (200,),
         json={"target": "https://app.pentefino.test/"})
    call("scope evaluate ssrf", "POST", f"/api/v1/programs/{slug}/scope/evaluate", (200,),
         json={"target": "http://169.254.169.254/latest/meta-data/"})
    call("scope evaluate missing target", "POST", f"/api/v1/programs/{slug}/scope/evaluate", (422,), json={})
    rule_id = None
    if r is not None and r.status_code in (200, 201):
        data = r.json()
        rule_id = data.get("id") or (data.get("rules") or [{}])[0].get("id")
    call("scope delete bad id", "DELETE", f"/api/v1/programs/{slug}/scope/not-a-uuid", (400, 404, 422))

    call("assets list", "GET", f"/api/v1/programs/{p}/assets", (200,))
    call("assets list bad filter", "GET", f"/api/v1/programs/{p}/assets?scope_state=bogus", (200, 400, 422))
    call("assets graph", "GET", f"/api/v1/programs/{p}/assets/graph", (200,))
    call("assets 404 program", "GET", "/api/v1/programs/does-not-exist-xyz/assets", (404,))

    call("recon out-of-scope", "POST", "/api/v1/recon/run", (403,), json={"program_slug": slug, "domain": "example.invalid"})
    call("recon invalid body", "POST", "/api/v1/recon/run", (422,), json={"program_slug": slug})
    call("recon 404 program", "POST", "/api/v1/recon/run", (404,), json={"program_slug": "nope-xyz", "domain": "a.test"})

    call("templates stats", "GET", "/api/v1/templates/stats", (200,))
    call("templates list", "GET", "/api/v1/templates?page=1&page_size=5", (200,))
    call("templates list bad page", "GET", "/api/v1/templates?page=0", (200, 422))
    call("template 404", "GET", "/api/v1/templates/does-not-exist-xyz", (404,))

    call("scan plan in scope", "POST", "/api/v1/scans/plan", (200,),
         json={"program_slug": slug, "asset_key": "app.pentefino.test"})
    call("scan plan out of scope", "POST", "/api/v1/scans/plan", (403,),
         json={"program_slug": slug, "asset_key": "evil.invalid"})
    call("scan run dry_run", "POST", "/api/v1/scans/run", (200,),
         json={"program_slug": slug, "asset_key": "app.pentefino.test", "mode": "dry_run"})
    call("scan run out of scope", "POST", "/api/v1/scans/run", (403,),
         json={"program_slug": slug, "asset_key": "169.254.169.254", "mode": "auto"})
    call("scan run invalid body", "POST", "/api/v1/scans/run", (422,), json={"program_slug": slug})
    call("batch run bad limits", "POST", "/api/v1/scans/batch-run", (422,), json={"program_slug": slug, "concurrency": 99})
    call("batch run dry_run", "POST", "/api/v1/scans/batch-run", (200,), json={"program_slug": slug, "mode": "dry_run"})
    call("batch run 404 program", "POST", "/api/v1/scans/batch-run", (404,), json={"program_slug": "does-not-exist-xyz"})
    call("circuit breaker status", "GET", "/api/v1/scans/circuit-breaker/status", (200,))
    call("circuit breaker reset", "POST", "/api/v1/scans/circuit-breaker/reset", (200,), json={"domain": "app.pentefino.test"})
    call("scan history", "GET", "/api/v1/scans/history?limit=5", (200,))
    call("scan history bad limit", "GET", "/api/v1/scans/history?limit=0", (422,))
    call("scan cancel uuid", "POST", f"/api/v1/scans/{uuid.uuid4()}/cancel", (200,))
    call("scan cancel invalid", "POST", "/api/v1/scans/not!valid/cancel", (400, 404))

    fr = call("findings list", "GET", "/api/v1/findings", (200,))
    call("findings bad severity", "GET", "/api/v1/findings?severity=bogus", (200, 400, 422))
    fid = None
    if fr is not None and fr.status_code == 200:
        items = fr.json()
        items = items if isinstance(items, list) else items.get("items", [])
        fid = items[0]["id"] if items else None
    call("finding 404", "GET", f"/api/v1/findings/{uuid.uuid4()}", (404,))
    call("finding invalid id", "GET", "/api/v1/findings/not-a-uuid", (400, 422))
    if fid:
        call("finding get", "GET", f"/api/v1/findings/{fid}", (200,))
        call("finding report", "GET", f"/api/v1/findings/{fid}/report", (200,))
        call("finding status invalid", "PATCH", f"/api/v1/findings/{fid}/status", (400, 422), json={"status": "bogus"})

    call("evidence 404", "GET", f"/api/v1/evidence/{uuid.uuid4()}", (404,))
    call("evidence invalid", "GET", "/api/v1/evidence/not-a-uuid", (400,))
    call("evidence blob 404", "GET", f"/api/v1/evidence/{uuid.uuid4()}/blob", (404,))
    call("intel status", "GET", "/api/v1/intel/status", (200,))

    if rule_id:
        call("scope delete ok", "DELETE", f"/api/v1/programs/{slug}/scope/{rule_id}", (200, 204))

    ok = sum(r["ok"] for r in rows)
    print(f"[{args.label}] {ok}/{len(rows)} cases matched expectations (throwaway program: {slug})")
    for r in rows:
        mark = "OK  " if r["ok"] else "FAIL"
        print(f"{mark} {r['status']:>4} exp={r['expected']} {r['method']:6} {r['path']}  [{r['case']}]  {'' if r['ok'] else r['body']}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"label": args.label, "program": slug, "rows": rows}, fh, indent=2)
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
