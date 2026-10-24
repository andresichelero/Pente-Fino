from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Union

# Curated catalog of modern realistic desktop browser User-Agents
MODERN_USER_AGENTS: List[str] = [
    # Chrome on Windows 11
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    # Firefox on Windows 11
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    # Safari on macOS Sonoma/Sequoia
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox on Linux x86_64
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
]

# Patterns identifying automated scanners and HTTP client libraries
SCANNER_UA_PATTERNS = [
    re.compile(r"nuclei", re.IGNORECASE),
    re.compile(r"projectdiscovery", re.IGNORECASE),
    re.compile(r"httpx", re.IGNORECASE),
    re.compile(r"subfinder", re.IGNORECASE),
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"curl/", re.IGNORECASE),
    re.compile(r"go-http-client", re.IGNORECASE),
    re.compile(r"python-requests", re.IGNORECASE),
    re.compile(r"aiohttp", re.IGNORECASE),
    re.compile(r"wpscan", re.IGNORECASE),
    re.compile(r"nmap", re.IGNORECASE),
    re.compile(r"masscan", re.IGNORECASE),
]

# Scanner signature header prefixes to strip unconditionally
STRIP_HEADER_PREFIXES = (
    "x-nuclei-",
    "x-httpx-",
    "x-scanner-",
)

# Headers to remove to prevent proxy leakage and tool fingerprinting
STRIP_EXACT_HEADERS = {
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "via",
    "proxy-connection",
    "proxy-authorization",
}


class CloakingEngine:
    """
    Stealth & Cloaking Engine.
    Strips scanner signatures, normalizes browser headers, and rotates
    realistic desktop User-Agents with session pinning via sha256(program_id + host).
    """

    def __init__(self, user_agents: Optional[List[str]] = None):
        self.user_agents = user_agents or list(MODERN_USER_AGENTS)

    def is_scanner_user_agent(self, user_agent: Optional[str]) -> bool:
        """Determines if a given User-Agent string is a known scanner signature or empty."""
        if not user_agent or not user_agent.strip():
            return True
        for pattern in SCANNER_UA_PATTERNS:
            if pattern.search(user_agent):
                return True
        return False

    def get_pinned_user_agent(self, host: str, program_id: Union[str, Any] = "default") -> str:
        """
        Deterministically pins a User-Agent based on sha256(program_id + host).
        Ensures consistent browser identity for the duration of a scan against a specific host.
        """
        host_clean = host.lower().split(":")[0].strip()
        prog_clean = str(program_id).strip()
        seed = f"{prog_clean}:{host_clean}".encode("utf-8")
        digest = hashlib.sha256(seed).hexdigest()
        index = int(digest[:8], 16) % len(self.user_agents)
        return self.user_agents[index]

    def cloak_headers(
        self,
        headers: Dict[str, str],
        host: str,
        program_id: Union[str, Any] = "default",
        force_browser_ua: bool = False,
    ) -> Dict[str, str]:
        """
        Sanitizes headers by:
        1. Stripping all X-Nuclei-*, X-Httpx-*, X-Scanner-* headers.
        2. Stripping proxy leakage headers (Via, X-Forwarded-For, etc.).
        3. Replacing scanner User-Agents with session-pinned modern browser User-Agent.
        4. Normalizing browser headers (Accept, Accept-Language, Sec-Ch-Ua).
        """
        cleaned: Dict[str, str] = {}
        ua_present = False
        current_ua = None

        for key, value in headers.items():
            key_lower = key.lower()

            # 1. Strip signature prefixes
            if any(key_lower.startswith(prefix) for prefix in STRIP_HEADER_PREFIXES):
                continue

            # 2. Strip proxy leakage headers
            if key_lower in STRIP_EXACT_HEADERS:
                continue

            if key_lower == "user-agent":
                ua_present = True
                current_ua = value
                continue

            cleaned[key] = value

        # 3. User-Agent cloaking with session pinning
        if force_browser_ua or not ua_present or self.is_scanner_user_agent(current_ua):
            pinned_ua = self.get_pinned_user_agent(host, program_id)
            cleaned["User-Agent"] = pinned_ua
        else:
            cleaned["User-Agent"] = current_ua  # Preserved if legitimate custom browser UA

        # 4. Realistic companion headers normalization
        if "Accept" not in cleaned and "accept" not in cleaned:
            cleaned["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        if "Accept-Language" not in cleaned and "accept-language" not in cleaned:
            cleaned["Accept-Language"] = "en-US,en;q=0.9"
        if "Accept-Encoding" not in cleaned and "accept-encoding" not in cleaned:
            cleaned["Accept-Encoding"] = "gzip, deflate, br"

        # Client hints for Chrome User-Agents
        effective_ua = cleaned.get("User-Agent", "")
        if "Chrome" in effective_ua and "Safari" in effective_ua:
            if "Sec-Ch-Ua" not in cleaned and "sec-ch-ua" not in cleaned:
                cleaned["Sec-Ch-Ua"] = '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"'
            if "Sec-Ch-Ua-Mobile" not in cleaned and "sec-ch-ua-mobile" not in cleaned:
                cleaned["Sec-Ch-Ua-Mobile"] = "?0"
            if "Sec-Ch-Ua-Platform" not in cleaned and "sec-ch-ua-platform" not in cleaned:
                cleaned["Sec-Ch-Ua-Platform"] = '"Windows"' if "Windows" in effective_ua else '"macOS"'

        return cleaned
