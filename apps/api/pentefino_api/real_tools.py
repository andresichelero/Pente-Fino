from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

WSL_DISTRO = "Ubuntu-24.04"
WSL_USER = "foxtrot"


def is_wsl_available() -> bool:
    """Check if WSL is installed and accessible on Windows."""
    return sys.platform == "win32" and shutil.which("wsl") is not None


def get_tool_command(tool_name: str, args: List[str]) -> List[str]:
    """Resolve command to execute tool, preferring native PATH or WSL host environment."""
    # Check if tool is on native PATH (e.g. Linux or native Windows)
    native_bin = shutil.which(tool_name)
    if native_bin and not native_bin.lower().endswith((".bat", ".cmd")):
        return [native_bin] + args

    if is_wsl_available():
        return ["wsl", "-d", WSL_DISTRO, "-u", WSL_USER, "--", tool_name] + args

    # Fallback to direct name
    return [tool_name] + args


async def run_real_subfinder(
    domain: str,
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Execute real Subfinder passive enumeration, streaming discovered hosts live."""
    cmd = get_tool_command("subfinder", ["-d", domain, "-silent", "-json"])
    logger.info("Executing real subfinder: %s", " ".join(cmd))

    if broadcast_cb:
        await broadcast_cb(
            "SUBFINDER",
            f"[SUBFINDER] Iniciando enumeração passiva com fontes OSINT para '{domain}'...",
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

    await _read_stdout()
    await proc.wait()
    logger.info("Real subfinder finished with code %d. Discovered %d hosts.", proc.returncode, len(results))
    return results


async def run_real_dnsx(
    hosts: List[str],
    resolvers: Optional[List[str]] = None,
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Execute real dnsx to resolve IP addresses and verify reachability."""
    if not hosts:
        return []

    res_list = ",".join(resolvers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    cmd = get_tool_command("dnsx", ["-r", res_list, "-a", "-aaaa", "-cname", "-resp", "-json", "-silent"])

    if broadcast_cb:
        await broadcast_cb(
            "DNSX",
            f"[DNSX] Resolvendo registros DNS para {len(hosts)} subdomínio(s)...",
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

    await asyncio.gather(_feed_input(), _read_stdout())
    await proc.wait()
    logger.info("Real dnsx finished with code %d. Resolved %d records.", proc.returncode, len(results))
    return results


async def run_real_httpx(
    hosts: List[str],
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Execute real httpx to probe live HTTP/HTTPS services and detect web technologies."""
    if not hosts:
        return []

    cmd = get_tool_command("httpx", ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-timeout", "5"])

    if broadcast_cb:
        await broadcast_cb(
            "HTTPX",
            f"[HTTPX] Verificando serviços HTTP ativos e tecnologias em {len(hosts)} alvo(s)...",
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

    await asyncio.gather(_feed_input(), _read_stdout())
    await proc.wait()
    logger.info("Real httpx finished with code %d. %d live HTTP services.", proc.returncode, len(results))
    return results


async def run_real_nuclei(
    target_url: str,
    template_ids: Optional[List[str]] = None,
    rate_limit: int = 10,
    tags: Optional[str] = None,
    severity: Optional[str] = None,
    broadcast_cb: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Execute real Nuclei vulnerability scanner with rate limiting and surgical templates."""
    args = [
        "-u", target_url,
        "-rl", str(rate_limit),
        "-c", "2",
        "-jsonl",
        "-silent",
        "-stats=false",
    ]

    if template_ids:
        for tid in template_ids[:20]:  # Limit surgical selection to top 20
            args.extend(["-id", tid])
    elif tags:
        args.extend(["-tags", tags])

    if severity:
        args.extend(["-severity", severity])

    cmd = get_tool_command("nuclei", args)
    logger.info("Executing real nuclei: %s", " ".join(cmd))

    if broadcast_cb:
        await broadcast_cb(
            "NUCLEI",
            f"[NUCLEI] Iniciando varredura cirúrgica em {target_url} (rl: {rate_limit} req/s)...",
        )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

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

    await asyncio.gather(_read_stdout(), _read_stderr())
    await proc.wait()
    logger.info("Real nuclei finished with code %d. Discovered %d findings.", proc.returncode, len(results))
    return results
