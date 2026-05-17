"""Shared behavioral scraper/bot guard for all calculator sites."""
from __future__ import annotations
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
    "/.env", "/.git", "/.svn", "/wp-admin", "/wp-login.php",
    "/xmlrpc.php", "/phpmyadmin", "/pma", "/adminer.php", "/cgi-bin/",
    "/config.php", "/config.json", "/server-status", "/actuator",
    "/vendor/phpunit", "/shell", "/cmd", "/boaform", "/HNAP1",
)

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

    # 2. Block exploit paths / path traversal
    if "/../" in path or any(path.startswith(p) for p in _EXPLOIT_PREFIXES):
        abort(403)

    # 3. Block scanner UAs
    ua = request.headers.get("User-Agent", "").lower()
    if any(s in ua for s in _SCANNER_UAS):
        abort(403)

    # 4. Block honeypot-flagged IPs
    ip = _get_ip()
    if ip in honeypot_blocked:
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


def init_guard(app: Flask, public_paths: tuple, honeypot_path: str, honeypot_blocked: set):
    @app.before_request
    def _run_guard():
        return _guard(public_paths, honeypot_path, honeypot_blocked)

