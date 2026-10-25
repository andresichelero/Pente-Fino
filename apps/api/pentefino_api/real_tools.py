from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

WSL_DISTRO = os.getenv("PENTEFINO_WSL_DISTRO", "Ubuntu-24.04")
WSL_USER = os.getenv("PENTEFINO_WSL_USER", "foxtrot")
NUCLEI_MAX_TEMPLATES = 20
NUCLEI_TIMEOUT_SECONDS = float(os.getenv("PENTEFINO_NUCLEI_TIMEOUT", "900"))


class UnsafeScanRequest(ValueError):
    """Raised when a scanner invocation would escape the safe_read_only template allowlist."""


def is_wsl_available() -> bool:
    """Check if WSL is installed and accessible on Windows."""
    return sys.platform == "win32" and shutil.which("wsl") is not None


def _is_python_entrypoint(binary: str) -> bool:
    """True when `binary` is a Python console script (e.g. encode/httpx's `httpx` CLI), not a ProjectDiscovery tool."""
    parent = Path(binary).resolve().parent
    return any(
        (parent / name).exists()
        for name in ("python.exe", "python", "python3", "../pyvenv.cfg")
    )


def get_tool_command(tool_name: str, args: List[str]) -> List[str]:
    """Resolve command to execute tool: PENTEFINO_<TOOL>_BIN override, native PATH, then WSL."""
    override = os.getenv(f"PENTEFINO_{tool_name.upper()}_BIN", "").strip()
    if override:
        return [override] + args

    native_bin = shutil.which(tool_name)
    if (
        native_bin
        and not native_bin.lower().endswith((".bat", ".cmd"))
        and not _is_python_entrypoint(native_bin)
    ):
        return [native_bin] + args

    if is_wsl_available():
        return ["wsl", "-d", WSL_DISTRO, "-u", WSL_USER, "--", tool_name] + args

    return [tool_name] + args


async def _drain_stream(stream: Optional[asyncio.StreamReader]) -> None:
    """Consume a pipe so a chatty child process cannot block on a full stderr buffer."""
    if stream is None:
        return
    while await stream.readline():
        pass


async def run_real_subfinder(
    domain: str,
    flags: Optional[Dict[str, Any]] = None,
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Execute real Subfinder passive enumeration, streaming discovered hosts live."""
    f = flags or {}
    args = ["-d", domain, "-silent", "-json"]
    if f.get("all", True):
        args.append("-all")
    if f.get("recursive", False):
        args.append("-recursive")

    cmd = get_tool_command("subfinder", args)
    logger.info("Executing real subfinder: %s", " ".join(cmd))

    if broadcast_cb:
        await broadcast_cb(
            "SUBFINDER",
            f"[SUBFINDER] Iniciando enumeração passiva com fontes OSINT para '{domain}' (flags: {' '.join(args)})...",
        )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    results: List[Dict[str, Any]] = []
    seen = set()

    async def _read_stdout():
        assert proc.stdout is not None
        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                break
            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            try:
                data = json.loads(line_str)
                host = data.get("host", "").strip().lower()
                source = data.get("source", "subfinder")
                if host and host not in seen:
                    seen.add(host)
                    results.append(data)
                    if broadcast_cb:
                        await broadcast_cb(
                            "SUBFINDER",
                            f"[{source}] {host}",
                        )
            except json.JSONDecodeError:
                if broadcast_cb and not line_str.startswith("{"):
                    await broadcast_cb("SUBFINDER", line_str)

    await asyncio.gather(_read_stdout(), _drain_stream(proc.stderr))
    await proc.wait()
    logger.info("Real subfinder finished with code %d. Discovered %d hosts.", proc.returncode, len(results))
    return results


async def run_real_dnsx(
    hosts: List[str],
    domain: Optional[str] = None,
    flags: Optional[Dict[str, Any]] = None,
    resolvers: Optional[List[str]] = None,
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Execute real dnsx to resolve IP addresses with optional wildcard detection (-wd)."""
    if not hosts:
        return []

    f = flags or {}
    res_list = ",".join(resolvers or f.get("resolvers") or ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    args = ["-r", res_list, "-a", "-aaaa", "-cname", "-resp", "-json", "-silent"]

    # Critical user rule: dnsx -wd <domain> to filter wildcard DNS false positives
    if f.get("wildcard_detection", True) and domain:
        args.extend(["-wd", domain])

    cmd = get_tool_command("dnsx", args)

    if broadcast_cb:
        await broadcast_cb(
            "DNSX",
            f"[DNSX] Resolvendo DNS para {len(hosts)} subdomínio(s) (wildcard-pruning={f.get('wildcard_detection', True)})...",
        )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    results: List[Dict[str, Any]] = []

    async def _feed_input():
        if proc.stdin:
            input_text = "\n".join(hosts) + "\n"
            proc.stdin.write(input_text.encode("utf-8"))
            await proc.stdin.drain()
            proc.stdin.close()

    async def _read_stdout():
        assert proc.stdout is not None
        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                break
            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                host = data.get("host", "")
                a_records = data.get("a", [])
                cname = data.get("cname", [])
                results.append(data)
                target_str = ", ".join(a_records) if a_records else ", ".join(cname)
                if broadcast_cb:
                    await broadcast_cb("DNSX", f"[dnsx:resolved] {host} -> [{target_str}]")
            except json.JSONDecodeError:
                if broadcast_cb:
                    await broadcast_cb("DNSX", line_str)

    await asyncio.gather(_feed_input(), _read_stdout(), _drain_stream(proc.stderr))
    await proc.wait()
    logger.info("Real dnsx finished with code %d. Resolved %d records.", proc.returncode, len(results))
    return results


async def run_real_httpx(
    hosts: List[str],
    flags: Optional[Dict[str, Any]] = None,
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Execute real httpx to probe live HTTP/HTTPS services and detect web technologies."""
    if not hosts:
        return []

    f = flags or {}
    args = ["-silent", "-json", "-timeout", "5"]
    if f.get("title", True):
        args.append("-title")
    if f.get("tech_detect", True):
        args.append("-tech-detect")
    if f.get("status_code", True):
        args.append("-status-code")
    if f.get("follow_redirects", True):
        # Same-host redirects only: cross-host hops would bypass the per-hop scope check.
        args.append("-follow-host-redirects")
    if f.get("ports"):
        args.extend(["-p", str(f.get("ports"))])

    cmd = get_tool_command("httpx", args)

    if broadcast_cb:
        await broadcast_cb(
            "HTTPX",
            f"[HTTPX] Verificando serviços HTTP e tecnologias em {len(hosts)} alvo(s) (flags: {' '.join(args)})...",
        )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    results: List[Dict[str, Any]] = []

    async def _feed_input():
        if proc.stdin:
            input_text = "\n".join(hosts) + "\n"
            proc.stdin.write(input_text.encode("utf-8"))
            await proc.stdin.drain()
            proc.stdin.close()

    async def _read_stdout():
        assert proc.stdout is not None
        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                break
            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                url = data.get("url", "")
                status_code = data.get("status_code", 0)
                title = data.get("title", "")
                techs = data.get("tech", []) or data.get("technologies", [])
                results.append(data)
                tech_str = f" [{', '.join(techs)}]" if techs else ""
                title_str = f" (\"{title}\")" if title else ""
                if broadcast_cb:
                    await broadcast_cb("HTTPX", f"[httpx:{status_code}] {url}{title_str}{tech_str}")
            except json.JSONDecodeError:
                if broadcast_cb:
                    await broadcast_cb("HTTPX", line_str)

    await asyncio.gather(_feed_input(), _read_stdout(), _drain_stream(proc.stderr))
    await proc.wait()
    logger.info("Real httpx finished with code %d. %d live HTTP services.", proc.returncode, len(results))
    return results


async def run_real_naabu(
    hosts: List[str],
    ports: str = "80,443,8080,8443",
    rate: int = 1000,
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Execute real naabu Layer 4 TCP port scanner."""
    if not hosts:
        return []

    cmd = get_tool_command("naabu", ["-p", ports, "-rate", str(rate), "-silent", "-json"])
    if broadcast_cb:
        await broadcast_cb(
            "NAABU",
            f"[NAABU] Varredura TCP Layer 4 (SYN) em {len(hosts)} alvos (portas={ports}, rate={rate})...",
        )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    results: List[Dict[str, Any]] = []

    async def _feed_input():
        if proc.stdin:
            input_text = "\n".join(hosts) + "\n"
            proc.stdin.write(input_text.encode("utf-8"))
            await proc.stdin.drain()
            proc.stdin.close()

    async def _read_stdout():
        assert proc.stdout is not None
        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                break
            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                results.append(data)
                ip = data.get("ip", "")
                port = data.get("port", "")
                host = data.get("host", ip)
                if broadcast_cb:
                    await broadcast_cb("NAABU", f"[naabu:open] {host}:{port} (TCP SYN-ACK)")
            except json.JSONDecodeError:
                if broadcast_cb:
                    await broadcast_cb("NAABU", line_str)

    await asyncio.gather(_feed_input(), _read_stdout(), _drain_stream(proc.stderr))
    await proc.wait()
    return results


async def run_real_tlsx(
    hosts: List[str],
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Execute real tlsx to extract Subject Alternative Names (SANs) from SSL certificates."""
    if not hosts:
        return []

    cmd = get_tool_command("tlsx", ["-san", "-cn", "-silent", "-json"])
    if broadcast_cb:
        await broadcast_cb("TLSX", f"[TLSX] Inspecionando SANs em certificados TLS para {len(hosts)} alvos...")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    results: List[Dict[str, Any]] = []

    async def _feed_input():
        if proc.stdin:
            input_text = "\n".join(hosts) + "\n"
            proc.stdin.write(input_text.encode("utf-8"))
            await proc.stdin.drain()
            proc.stdin.close()

    async def _read_stdout():
        assert proc.stdout is not None
        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                break
            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                results.append(data)
                host = data.get("host", "")
                sans = data.get("subject_an", []) or []
                if broadcast_cb and sans:
                    await broadcast_cb("TLSX", f"[tlsx:san] {host} -> {len(sans)} SANs descobertos")
            except json.JSONDecodeError:
                pass

    await asyncio.gather(_feed_input(), _read_stdout(), _drain_stream(proc.stderr))
    await proc.wait()
    return results


async def run_real_nuclei(
    target_url: str,
    template_ids: Optional[List[str]] = None,
    rate_limit: int = 10,
    tags: Optional[str] = None,
    severity: Optional[str] = None,
    flags: Optional[Dict[str, Any]] = None,
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Execute Nuclei restricted to the planner's safe_read_only template allowlist.

    Refuses to start without explicit template IDs: an empty `-id` list would make
    Nuclei fall back to its whole default catalog (intrusive templates included).
    """
    if not template_ids:
        raise UnsafeScanRequest(
            "Refusing to run nuclei without an explicit safe_read_only template allowlist."
        )
    if tags:
        logger.warning("Ignoring nuclei tags=%r: tag selection bypasses the impact-class allowlist.", tags)

    f = flags or {}
    args = [
        "-u", target_url,
        "-rl", str(rate_limit),
        "-c", "2",
        "-jsonl",
        "-silent",
        "-stats=false",
    ]

    # `-as` (automatic wappalyzer scan) is deliberately never passed: it selects
    # templates by detected tech regardless of impact class.
    if f.get("host_prune", True):
        args.append("-hpd")
    if f.get("follow_redirects", True):
        # Same-host redirects only; a cross-host hop would skip scope evaluation.
        args.append("-fhr")

    egress_proxy = os.getenv("PENTEFINO_EGRESS_PROXY", "").strip()
    if egress_proxy:
        args.extend(["-proxy", egress_proxy])
    elif os.getenv("PENTEFINO_REQUIRE_EGRESS_PROXY", "").lower() in ("1", "true", "yes"):
        raise UnsafeScanRequest(
            "PENTEFINO_REQUIRE_EGRESS_PROXY is set but PENTEFINO_EGRESS_PROXY is empty."
        )

    if len(template_ids) > NUCLEI_MAX_TEMPLATES:
        logger.warning(
            "Plan selected %d templates; nuclei invocation capped at %d.",
            len(template_ids),
            NUCLEI_MAX_TEMPLATES,
        )
    for tid in template_ids[:NUCLEI_MAX_TEMPLATES]:
        args.extend(["-id", tid])

    if severity:
        args.extend(["-severity", severity])

    cmd = get_tool_command("nuclei", args)
    logger.info("Executing real nuclei: %s", " ".join(cmd))

    if broadcast_cb:
        await broadcast_cb(
            "NUCLEI",
            f"[NUCLEI] Disparando Nuclei cirúrgico em {target_url} (rl: {rate_limit} req/s, flags: {' '.join(args)})...",
        )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    if run_id:
        from pentefino_api.activity import activity

        activity.attach_process(run_id, proc)

    results: List[Dict[str, Any]] = []

    async def _read_stdout():
        assert proc.stdout is not None
        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                break
            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            try:
                data = json.loads(line_str)
                results.append(data)
                name = data.get("info", {}).get("name", data.get("template-id", "vuln"))
                sev = data.get("info", {}).get("severity", "info").upper()
                matched = data.get("matched-at", target_url)
                if broadcast_cb:
                    await broadcast_cb("NUCLEI", f"[NUCLEI:{sev}] {name} em {matched}")
            except json.JSONDecodeError:
                if broadcast_cb:
                    await broadcast_cb("NUCLEI", line_str)

    async def _read_stderr():
        assert proc.stderr is not None
        while True:
            line_bytes = await proc.stderr.readline()
            if not line_bytes:
                break
            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if line_str and broadcast_cb:
                await broadcast_cb("NUCLEI", line_str)

    try:
        await asyncio.wait_for(
            asyncio.gather(_read_stdout(), _read_stderr()),
            timeout=NUCLEI_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.error("nuclei exceeded %.0fs against %s; killing.", NUCLEI_TIMEOUT_SECONDS, target_url)
        proc.kill()
    await proc.wait()
    logger.info("Real nuclei finished with code %d. Discovered %d findings.", proc.returncode, len(results))
    return results
