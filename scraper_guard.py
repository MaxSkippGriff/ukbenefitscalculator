"""Shared behavioral scraper/bot guard for all calculator sites."""
from __future__ import annotations
import ipaddress
import logging
import threading
import time
from collections import deque

from flask import Flask, abort, request

logger = logging.getLogger("scraper_guard")

GENERAL_PER_MIN = 300
HTML_PER_10MIN = 100
UNIQUE_PER_10MIN = 80
UNIQUE_PER_HOUR = 250
NO_ASSET_THRESHOLD = 25
BLOCK_DURATIONS = (3600, 21600, 86400)

_SCANNER_UAS = (
    "sqlmap", "nikto", "nessus", "masscan", "zgrab", "acunetix",
    "dirbuster", "gobuster", "nuclei", "openvas", "wpscan",
)

_EXPLOIT_PREFIXES = (
    "/.env", "/.git", "/.svn", "/.aws", "/.ssh", "/.htaccess", "/.htpasswd",
    "/wp-admin", "/wp-login.php", "/wp-includes", "/wp-content", "/wp-json",
    "/wp/", "/wordpress", "/xmlrpc.php", "/ms-themes",
    "/phpmyadmin", "/pma", "/adminer.php", "/cgi-bin/",
    "/config.php", "/config.json", "/server-status", "/actuator",
    "/vendor/phpunit", "/shell", "/cmd", "/boaform", "/HNAP1", "/backup",
)

# These Flask sites never serve PHP/ASP/etc. — any request for one is a probe.
# (/static/ is exempted at the check site so legitimate assets are never affected.)
_EXPLOIT_SUFFIXES = (".php", ".asp", ".aspx", ".jsp", ".cfm", ".sql", ".bak", ".old", ".env")

# ── Wanted crawlers (allowlist) ──────────────────────────────────────────────
# These identify themselves honestly and are ALWAYS allowed, even from cloud IPs:
# search engines, AI assistants/trainers, social link-unfurlers, SEO tools, monitors.
_GOOD_BOT_UAS = (
    # Search engines
    "googlebot", "google-inspectiontool", "storebot-google", "googleother",
    "google-extended", "apis-google", "feedfetcher-google", "mediapartners-google",
    "adsbot-google", "bingbot", "bingpreview", "adidxbot", "msnbot", "slurp",
    "duckduckbot", "duckduckgo", "applebot", "baiduspider", "yandex", "sogou", "seznambot",
    # AI assistants / crawlers
    "gptbot", "chatgpt-user", "oai-searchbot", "claudebot", "claude-user", "anthropic",
    "perplexitybot", "perplexity-user", "youbot", "amazonbot", "cohere-ai", "ccbot",
    "google-cloudvertexbot", "meta-externalagent", "bytespider",
    # Social / link unfurlers
    "facebookexternalhit", "facebookbot", "twitterbot", "linkedinbot", "slackbot",
    "telegrambot", "whatsapp", "discordbot", "pinterest", "redditbot",
    # SEO tools (owner is SEO-focused)
    "ahrefsbot", "semrushbot", "dotbot", "rogerbot", "mojeekbot",
    # Ad verification / monitoring (don't block these)
    "criteo", "uptimerobot", "pingdom", "statuscake", "googlehc", "google-cloud-monitoring",
)

# ── Cloud/datacenter ranges used for content scraping ────────────────────────
# A real human browser never originates here; legit crawlers declare a UA above and
# pass regardless. Curated to the clouds actually seen scraping (Tencent dominates the
# Singapore traffic) — deliberately NOT all of AWS/GCP/Azure, to avoid collateral damage.
_DATACENTER_CIDRS = (
    # Tencent Cloud (the dominant Singapore scraper)
    "43.128.0.0/10", "49.51.0.0/16", "62.234.0.0/16", "101.32.0.0/16",
    "119.28.0.0/15", "124.156.0.0/16", "129.226.0.0/16", "150.109.0.0/16",
    "170.106.0.0/16", "1.12.0.0/14", "129.211.0.0/16", "81.69.0.0/16",
    # Alibaba Cloud (international)
    "47.74.0.0/15", "47.76.0.0/14", "47.235.0.0/16", "47.236.0.0/15",
    "47.240.0.0/14", "47.244.0.0/15", "47.246.0.0/16", "47.250.0.0/15",
    "47.252.0.0/15", "8.208.0.0/12", "149.129.0.0/16", "161.117.0.0/16",
    "47.88.0.0/15", "47.90.0.0/15",
    # AWS Singapore EC2 (observed scrapers; NOT all of AWS)
    "47.128.0.0/14",
    # Huawei Cloud
    "114.115.128.0/17", "119.3.0.0/16", "121.36.0.0/16", "159.138.0.0/16",
    # DigitalOcean
    "129.212.0.0/16", "134.122.0.0/16", "137.184.0.0/16", "138.197.0.0/16",
    "138.68.0.0/16", "139.59.0.0/16", "142.93.0.0/16", "143.110.0.0/16",
    "146.190.0.0/16", "157.230.0.0/16", "159.65.0.0/16", "159.89.0.0/16",
    "161.35.0.0/16", "164.90.0.0/16", "165.22.0.0/16", "165.227.0.0/16",
    "167.71.0.0/16", "167.99.0.0/16", "178.62.0.0/16", "188.166.0.0/16",
    "206.189.0.0/16", "209.97.0.0/16", "64.227.0.0/16", "68.183.0.0/16",
    "45.55.0.0/16", "104.131.0.0/16", "192.241.0.0/16", "198.199.0.0/16",
    # Linode / Akamai compute
    "139.162.0.0/16", "172.104.0.0/15", "45.79.0.0/16", "45.33.0.0/16",
    "96.126.96.0/19", "173.255.192.0/18", "178.79.128.0/18", "50.116.0.0/16",
    # OVH
    "51.38.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16",
    "51.79.0.0/16", "51.83.0.0/16", "51.89.0.0/16", "51.91.0.0/16",
    "51.195.0.0/16", "54.36.0.0/16", "91.121.0.0/16", "92.222.0.0/16",
    "137.74.0.0/16", "139.99.0.0/16", "145.239.0.0/16", "147.135.0.0/16",
    "151.80.0.0/16", "158.69.0.0/16", "167.114.0.0/16", "178.32.0.0/15",
    "188.165.0.0/16", "213.186.32.0/19",
)

_DATACENTER_NETS = []
for _c in _DATACENTER_CIDRS:
    try:
        _DATACENTER_NETS.append(ipaddress.ip_network(_c))
    except ValueError:
        pass

_lock = threading.Lock()
_state: dict = {}
_last_cleanup = [0.0]


def _get_state(ip: str) -> dict:
    st = _state.get(ip)
    if st is None:
        st = {
            "gen": deque(),
            "html": deque(),
            "assets": deque(),
            "uniq10": {},
            "uniq1h": {},
            "offenses": 0,
            "blocked_until": 0.0,
        }
        _state[ip] = st
    return st


def _cleanup(now: float):
    if now - _last_cleanup[0] < 300:
        return
    _last_cleanup[0] = now
    cutoff = now - 3600
    dead = [ip for ip, st in _state.items()
            if not st["gen"] and not st["html"] and st["blocked_until"] < cutoff]
    for ip in dead:
        del _state[ip]


def _slide(dq: deque, window: float, now: float) -> int:
    cutoff = now - window
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)


def _slide_dict(d: dict, window: float, now: float) -> int:
    cutoff = now - window
    stale = [k for k, v in d.items() if v < cutoff]
    for k in stale:
        del d[k]
    return len(d)


def _handle_offense(ip: str, st: dict, reason: str, now: float):
    st["offenses"] += 1
    if st["offenses"] >= 3:
        idx = min(st["offenses"] - 3, len(BLOCK_DURATIONS) - 1)
        duration = BLOCK_DURATIONS[idx]
        st["blocked_until"] = now + duration
        logger.warning("scraper_guard BLOCK ip=%s reason=%s offenses=%d duration=%ds",
                       ip, reason, st["offenses"], duration)
    else:
        logger.warning("scraper_guard WARN ip=%s reason=%s offenses=%d",
                       ip, reason, st["offenses"])


def _get_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote_addr or "")


def _is_good_bot(ua: str) -> bool:
    """True if the user-agent is a wanted crawler (always allowed, even from cloud IPs)."""
    return any(g in ua for g in _GOOD_BOT_UAS)


def _is_datacenter(ip: str) -> bool:
    """True if the IP belongs to a known content-scraping cloud range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _DATACENTER_NETS:
        if addr.version == net.version and addr in net:
            return True
    return False


def _is_html(path: str) -> bool:
    last = path.split("/")[-1]
    if path.startswith("/static/") or ("." in last and not last.endswith("/")):
        return False
    accept = request.headers.get("Accept", "")
    return "text/html" in accept or not accept


def _is_asset(path: str) -> bool:
    if path.startswith("/static/"):
        return True
    last = path.split("/")[-1]
    ext = last.rsplit(".", 1)[-1].lower() if "." in last else ""
    return ext in {"css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico",
                   "woff", "woff2", "ttf", "otf", "webp", "map"}


def _guard(public_paths: tuple, honeypot_path: str, honeypot_blocked: set):
    path = request.path or ""

    # 1. Let the honeypot route reach its handler so it can record the IP
    if path == honeypot_path:
        return None

    # 2. Block exploit paths / path traversal / probe file types
    if (
        "/../" in path
        or any(path.startswith(p) for p in _EXPLOIT_PREFIXES)
        or (not path.startswith("/static/") and path.lower().endswith(_EXPLOIT_SUFFIXES))
    ):
        abort(403)

    # 3. Block scanner UAs
    ua = request.headers.get("User-Agent", "").lower()
    if any(s in ua for s in _SCANNER_UAS):
        abort(403)

    # 4. Block honeypot-flagged IPs
    ip = _get_ip()
    if ip in honeypot_blocked:
        abort(403)

    # 4b. Block cloud/datacenter content-scrapers — UNLESS they declare a wanted
    #     crawler UA (search engines, AI assistants, social, SEO tools all pass).
    #     Real human visitors never originate from these ranges.
    if not _is_good_bot(ua) and _is_datacenter(ip):
        logger.info("scraper_guard datacenter block ip=%s ua=%s", ip, ua[:80])
        abort(403)

    # 5. Public SEO / static assets bypass rate limiting
    if path in public_paths or path.startswith("/static/") or path.startswith("/.well-known/"):
        return None

    # 6. Behavioral rate limits
    now = time.monotonic()

    with _lock:
        _cleanup(now)
        st = _get_state(ip)

        if st["blocked_until"] > now:
            abort(429)

        st["gen"].append(now)
        if _slide(st["gen"], 60, now) > GENERAL_PER_MIN:
            _handle_offense(ip, st, "general_rate", now)
            abort(429)

        is_html = _is_html(path)
        is_asset = _is_asset(path)

        if is_asset:
            st["assets"].append(now)

        if is_html:
            st["html"].append(now)
            html_count = _slide(st["html"], 600, now)

            if html_count > HTML_PER_10MIN:
                _handle_offense(ip, st, "html_rate", now)
                abort(429)

            st["uniq10"][path] = now
            if _slide_dict(st["uniq10"], 600, now) > UNIQUE_PER_10MIN:
                _handle_offense(ip, st, "unique_10m", now)
                abort(429)

            st["uniq1h"][path] = now
            if _slide_dict(st["uniq1h"], 3600, now) > UNIQUE_PER_HOUR:
                _handle_offense(ip, st, "unique_1h", now)
                abort(429)

            asset_count = _slide(st["assets"], 600, now)
            if html_count > NO_ASSET_THRESHOLD and asset_count == 0:
                logger.warning("scraper_guard NO_ASSET ip=%s html=%d assets=%d",
                               ip, html_count, asset_count)

    return None


# Baseline security headers applied to every response. These are safe for normal
# visitors and for search/AI crawlers (Google, Bing, etc.) — they only restrict how
# the page may be framed/embedded and how powerful browser features are used.
_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), browsing-topics=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
}


def init_guard(app: Flask, public_paths: tuple, honeypot_path: str, honeypot_blocked: set):
    @app.before_request
    def _run_guard():
        return _guard(public_paths, honeypot_path, honeypot_blocked)

    @app.after_request
    def _apply_security_headers(response):
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        # Don't advertise the server software.
        response.headers["Server"] = "web"
        return response

