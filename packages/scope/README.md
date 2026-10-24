# pentefino-scope

Hard-gate fail-closed scope engine for PenteFino.

## Invariants
1. Strict 7-Tier Precedence:
   `Explicit Deny > Expired Auth > Path/Port Deny > Explicit Allow > Wildcard Allow > Derived Candidate > Unknown (Deny)`
2. Direct IP Scanning Prohibition: `*.example.com` NEVER authorizes direct IP scanning.
3. Anti-SSRF & DNS Rebinding: Strict blocking of RFC 1918, loopback, link-local, cloud metadata (`169.254.169.254`, `fd00:ec2::254`), and IPv4-mapped IPv6.
4. Hop-by-Hop Redirect Validation: Re-evaluates target scope on every HTTP 3xx redirect hop.
