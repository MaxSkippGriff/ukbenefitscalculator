"""UK Benefits Calculator Flask application."""

from __future__ import annotations

import ipaddress
import json
import math
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from dotenv import load_dotenv
from flask import Flask, abort, make_response, redirect, render_template, request, send_from_directory, url_for

try:
    from flask_limiter import Limiter
except Exception:  # pragma: no cover - local fallback
    class Limiter:  # type: ignore[override]
        def __init__(self, *args, **kwargs):
            pass

try:
    import geoip2.database as _geoip2db
except Exception:  # pragma: no cover - optional at runtime
    _geoip2db = None

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "change-me")

CANONICAL_HOST = os.getenv("CANONICAL_HOST", "ukbenefitscalculator.co.uk").replace("https://", "").replace("http://", "")
CANONICAL_HOST = CANONICAL_HOST[4:] if CANONICAL_HOST.startswith("www.") else CANONICAL_HOST
if CANONICAL_HOST == "employercalculator.co.uk":
    CANONICAL_HOST = "ukbenefitscalculator.co.uk"
SITE_URL = f"https://{CANONICAL_HOST}"
GA_MEASUREMENT_ID = os.getenv("GA_MEASUREMENT_ID", "").strip()
ADSENSE_CLIENT = os.getenv("ADSENSE_CLIENT", "ca-pub-3932111812673824").strip()
ENABLE_ADS = os.getenv("ENABLE_ADS", "false").lower() == "true"
ADSENSE_SLOT_CONTENT = os.getenv("ADSENSE_SLOT_CONTENT", "").strip()
ADSENSE_SLOT_CALCULATOR = os.getenv("ADSENSE_SLOT_CALCULATOR", ADSENSE_SLOT_CONTENT).strip()

limiter = Limiter(
    app=app,
    key_func=lambda: (request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or ""),
    default_limits=["60 per minute"],
    storage_uri="memory://",
    strategy="fixed-window",
)

_geo = None
if _geoip2db:
    for candidate in ("/app/dbip-country.mmdb", os.path.join(os.path.dirname(__file__), "dbip-country.mmdb")):
        if os.path.exists(candidate):
            try:
                _geo = _geoip2db.Reader(candidate)
                break
            except Exception:
                _geo = None

_BLOCKED_COUNTRIES = {"SG"}
_BLOCKED_SUBNETS = [
    ipaddress.ip_network("43.172.0.0/15"),
    ipaddress.ip_network("47.82.0.0/15"),
    ipaddress.ip_network("47.128.0.0/16"),
    ipaddress.ip_network("8.222.0.0/16"),
    ipaddress.ip_network("47.245.0.0/16"),
    ipaddress.ip_network("43.129.0.0/16"),
    ipaddress.ip_network("43.134.0.0/16"),
    ipaddress.ip_network("43.156.0.0/16"),
    ipaddress.ip_network("13.212.0.0/15"),
    ipaddress.ip_network("18.136.0.0/15"),
    ipaddress.ip_network("18.138.0.0/15"),
    ipaddress.ip_network("52.76.0.0/15"),
    ipaddress.ip_network("128.199.192.0/19"),
    ipaddress.ip_network("68.183.160.0/19"),
    ipaddress.ip_network("139.59.192.0/18"),
    ipaddress.ip_network("47.128.32.0/20"),
    ipaddress.ip_network("110.249.200.0/22"),
]
_BLOCKED_UAS = (
    "bytespider", "petalbot", "ccbot", "omgili", "dataforseo", "scrapy",
    "seranking", "mj12bot", "dotbot", "blexbot", "seznambot",
    "python-httpx", "python-requests", "go-http-client", "java/",
    "curl/", "wget/", "libwww", "okhttp", "apache-httpclient", "aiohttp",
    "httpx", "mechanize", "lwp-", "guzzle", "restsharp",
    "headlesschrome", "phantomjs", "selenium",
)
_STATIC_PATHS = ("/static/", "/robots.txt", "/sitemap", "/ads.txt", "/favicon", "/.well-known", "/api/")
_GOOD_BOTS = (
    "googlebot", "google-inspectiontool", "adsbot-google", "mediapartners-google",
    "google-display-ads-bot", "googleother", "google-read-aloud",
    "bingbot", "slurp", "duckduckbot", "baiduspider", "yandexbot",
    "applebot", "facebot", "linkedinbot", "twitterbot", "whatsapp",
    "telegrambot", "ia_archiver", "ahrefsbot", "semrushbot",
    "gptbot", "chatgpt-user", "claudebot", "anthropic-ai", "oai-searchbot",
    "google-extended", "gemini", "perplexitybot", "youbot",
    "meta-externalagent", "amazonbot", "cohere-ai", "diffbot",
)
_HONEYPOT_BLOCKED: Set[str] = set()


def _get_real_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote_addr or "")


@app.before_request
def block_scrapers():
    if app.config.get("TESTING"):
        return None
    host = (request.host or "").split(":")[0].lower()
    if host and host not in {CANONICAL_HOST, f"www.{CANONICAL_HOST}", "localhost", "127.0.0.1"}:
        return None
    ip_str = _get_real_ip()
    if ip_str in _HONEYPOT_BLOCKED:
        abort(403)

    if _geo:
        try:
            country = _geo.country(ip_str).country.iso_code
            if country in _BLOCKED_COUNTRIES:
                abort(403)
        except Exception:
            pass

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for subnet in _BLOCKED_SUBNETS:
            if ip_obj in subnet:
                abort(403)
    except ValueError:
        pass

    ua = request.headers.get("User-Agent", "").lower()
    if any(token in ua for token in _BLOCKED_UAS):
        abort(403)
    if any(token in ua for token in _GOOD_BOTS):
        return None

    path = request.path or ""
    if request.method == "HEAD":
        return None
    if not any(path.startswith(prefix) for prefix in _STATIC_PATHS):
        if not request.headers.get("Accept-Language"):
            abort(403)
    return None


@app.before_request
def enforce_canonical_host():
    host = (request.host or "").split(":")[0].lower()
    if not host or host in {"localhost", "127.0.0.1"}:
        return None
    if host != CANONICAL_HOST:
        target = f"{SITE_URL}{request.full_path if request.query_string else request.path}"
        if target.endswith("?"):
            target = target[:-1]
        return redirect(target, code=301)
    return None


@app.after_request
def apply_cache_headers(response):
    path = request.path or ""
    if path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=300"
    elif path in ("/favicon.ico", "/site.webmanifest", "/apple-touch-icon.png", "/favicon-32x32.png", "/favicon-16x16.png"):
        response.headers["Cache-Control"] = "public, max-age=86400"
    elif path == "/robots.txt":
        response.headers["Cache-Control"] = "public, max-age=60"
    elif response.mimetype == "text/html":
        response.headers["Cache-Control"] = "private, no-store, max-age=0, must-revalidate"
    return response


def now_utc() -> datetime:
    return datetime.utcnow()


def request_path() -> str:
    return request.path if request.path != "" else "/"


def currency(amount: float) -> str:
    sign = "-" if amount < 0 else ""
    return f"{sign}£{abs(amount):,.2f}"


def annual_to_monthly(amount: float) -> float:
    return amount / 12


def weekly_to_monthly(amount: float) -> float:
    return amount * 52 / 12


def round_money(amount: float) -> float:
    return round(amount + 1e-9, 2)


def get_number_arg(name: str, default: float) -> float:
    raw = (request.args.get(name, "") or "").replace(",", "").replace("£", "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def get_text_arg(name: str, default: str) -> str:
    raw = (request.args.get(name, "") or "").strip()
    return raw if raw else default


def get_bool_arg(name: str, default: bool = False) -> bool:
    raw = (request.args.get(name, "") or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def parse_inputs(page: Dict[str, Any]) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    for field in page["fields"]:
        if field["type"] == "number":
            parsed[field["name"]] = get_number_arg(field["name"], field.get("default", 0))
        elif field["type"] == "select":
            value = get_text_arg(field["name"], field.get("default", ""))
            valid = {option["value"] for option in field["options"]}
            parsed[field["name"]] = value if value in valid else field.get("default", "")
        elif field["type"] == "boolean":
            parsed[field["name"]] = get_bool_arg(field["name"], field.get("default", False))
    return parsed


def uc_standard_allowance(age_band: str, household: str) -> float:
    if household == "couple":
        return 666.97 if age_band == "25_plus" else 528.34
    return 424.90 if age_band == "25_plus" else 338.58


def uc_health_element(health: str) -> float:
    if health == "severe":
        return 429.80
    if health == "standard":
        return 217.26
    return 0.0


def child_benefit_weekly(children: float) -> float:
    children = max(0, int(children))
    if children <= 0:
        return 0.0
    return 27.05 + max(0, children - 1) * 17.90


def universal_credit_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    savings = inputs["savings"]
    if savings >= 16000:
        return {
            "primary_amount": 0.0,
            "secondary_amount": 0.0,
            "primary_label": "Estimated monthly Universal Credit",
            "secondary_label": "Estimated annual Universal Credit",
            "summary": "Savings of £16,000 or more usually stop a standard Universal Credit award.",
            "breakdown": [
                ("Standard allowance", 0.0),
                ("Children", 0.0),
                ("Housing support", 0.0),
                ("Childcare support", 0.0),
                ("Health element", 0.0),
                ("Earnings deduction", 0.0),
                ("Savings deduction", 0.0),
            ],
            "notes": [
                "This estimator uses current monthly standard allowances and simplified housing assumptions.",
                "Some households can still receive transitional protection or specialist elements not modelled here.",
            ],
        }

    base = uc_standard_allowance(inputs["age_band"], inputs["household"])
    children = int(inputs["children"])
    child_element = children * 303.94
    if children > 0 and inputs["first_child_pre_2017"]:
        child_element += 47.94
    housing_support = min(inputs["housing_cost"], 1200.0)
    childcare_cap = 1836.16 if children >= 2 else 1071.09
    childcare_support = min(inputs["childcare_cost"] * 0.85, childcare_cap)
    health = uc_health_element(inputs["health"])
    work_allowance = 404.0 if housing_support > 0 else 673.0
    earnings_deduction = max(0.0, inputs["earnings"] - work_allowance) * 0.55
    savings_deduction = 0.0
    if savings > 6000:
        savings_deduction = math.ceil((savings - 6000) / 250.0) * 4.35
    monthly_total = max(0.0, base + child_element + housing_support + childcare_support + health - earnings_deduction - savings_deduction)
    return {
        "primary_amount": round_money(monthly_total),
        "secondary_amount": round_money(monthly_total * 12),
        "primary_label": "Estimated monthly Universal Credit",
        "secondary_label": "Estimated annual Universal Credit",
        "summary": "A simplified award estimate using the 55% earnings taper, a work allowance where children or a health condition apply, savings deductions over £6,000, and capped childcare support.",
        "breakdown": [
            ("Standard allowance", base),
            ("Child element", child_element),
            ("Housing support used", housing_support),
            ("Childcare support used", childcare_support),
            ("Health element", health),
            ("Earnings deduction", -earnings_deduction),
            ("Savings deduction", -savings_deduction),
        ],
        "notes": [
            "Universal Credit now pays the child element for every eligible child after the 6 April 2026 rule change.",
            "Housing support is simplified here. Actual help depends on your rent type, service charges and local housing allowance rules.",
        ],
    }


def child_benefit_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    weekly_total = child_benefit_weekly(inputs["children"])
    monthly_total = weekly_to_monthly(weekly_total)
    annual_total = weekly_total * 52
    return {
        "primary_amount": round_money(weekly_total),
        "secondary_amount": round_money(annual_total),
        "primary_label": "Estimated weekly Child Benefit",
        "secondary_label": "Estimated annual Child Benefit",
        "summary": "This uses the published 2026 to 2027 Child Benefit rates for the eldest child and any additional children.",
        "breakdown": [
            ("Eldest or only child", 27.05 if inputs["children"] >= 1 else 0.0),
            ("Additional children", max(0, int(inputs["children"]) - 1) * 17.90),
            ("Monthly equivalent", monthly_total),
        ],
        "notes": [
            "If anyone in the household has adjusted net income over £60,000, check the HICBC page next.",
            "You can claim Child Benefit and opt out of payments if you want National Insurance credits without the cash payment.",
        ],
    }


def hicbc_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    annual_benefit = child_benefit_weekly(inputs["children"]) * 52
    income = inputs["adjusted_net_income"]
    if income <= 60000:
        charge = 0.0
    elif income >= 80000:
        charge = annual_benefit
    else:
        percentage = min(1.0, (income - 60000) / 20000)
        charge = annual_benefit * percentage
    keep = max(0.0, annual_benefit - charge)
    return {
        "primary_amount": round_money(charge),
        "secondary_amount": round_money(keep),
        "primary_label": "Estimated annual HICBC charge",
        "secondary_label": "Estimated Child Benefit kept",
        "summary": "The charge starts above £60,000 adjusted net income and reaches 100% when income is £80,000 or more.",
        "breakdown": [
            ("Annual Child Benefit used", annual_benefit),
            ("Adjusted net income", income),
            ("Estimated charge", -charge),
            ("Net amount retained", keep),
        ],
        "notes": [
            "This uses the post-April 2024 HICBC taper of 1% for each £200 over £60,000.",
            "Adjusted net income can be reduced by certain pension contributions and Gift Aid, so the real charge can differ.",
        ],
    }


def pension_credit_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    base = 363.25 if inputs["household"] == "couple" else 238.0
    severe = 86.05 if inputs["severe_disability"] else 0.0
    carer = 48.15 if inputs["carer"] else 0.0
    savings_income = 0.0
    if inputs["savings"] > 10000:
        savings_income = math.floor((inputs["savings"] - 10000) / 500.0) + (1 if (inputs["savings"] - 10000) % 500 else 0)
    weekly_award = max(0.0, base + severe + carer - inputs["weekly_income"] - savings_income)
    return {
        "primary_amount": round_money(weekly_award),
        "secondary_amount": round_money(weekly_award * 52),
        "primary_label": "Estimated weekly Pension Credit",
        "secondary_label": "Estimated annual Pension Credit",
        "summary": "This focuses on Guarantee Credit and uses the standard weekly minimum income levels plus optional severe disability and carer additions.",
        "breakdown": [
            ("Guarantee Credit minimum", base),
            ("Severe disability addition", severe),
            ("Carer addition", carer),
            ("Income counted", -inputs["weekly_income"]),
            ("Savings treated as income", -savings_income),
        ],
        "notes": [
            "Savings under £10,000 are ignored. Above that, every £500 generally counts as £1 a week of income.",
            "Housing costs, Savings Credit and mixed-age couple rules are not fully modelled here.",
        ],
    }


def pip_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    daily_points = inputs["daily_living_points"]
    mobility_points = inputs["mobility_points"]
    daily_rate = 0.0
    mobility_rate = 0.0
    daily_band = "No daily living award indicated"
    mobility_band = "No mobility award indicated"
    if daily_points >= 12:
        daily_rate = 114.60
        daily_band = "Enhanced daily living indicated"
    elif daily_points >= 8:
        daily_rate = 76.70
        daily_band = "Standard daily living indicated"
    if mobility_points >= 12:
        mobility_rate = 80.00
        mobility_band = "Enhanced mobility indicated"
    elif mobility_points >= 8:
        mobility_rate = 30.30
        mobility_band = "Standard mobility indicated"
    total = daily_rate + mobility_rate
    return {
        "primary_amount": round_money(total),
        "secondary_amount": round_money(total * 52),
        "primary_label": "Indicative weekly PIP amount",
        "secondary_label": "Indicative annual PIP amount",
        "summary": f"{daily_band}. {mobility_band}. PIP is based on descriptors and evidence, not income.",
        "breakdown": [
            ("Daily living component", daily_rate),
            ("Mobility component", mobility_rate),
            ("Combined weekly amount", total),
        ],
        "notes": [
            "This is a points-based checker, not an official DWP decision tool.",
            "Real awards depend on the evidence you provide, how long your condition affects you and a formal assessment process.",
        ],
    }


def council_tax_reduction_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    council_tax = inputs["monthly_council_tax"]
    income = inputs["monthly_income"]
    reduction = 0.0
    if inputs["on_means_tested_benefit"]:
        reduction = 1.0
    elif income <= 1100:
        reduction = 0.85
    elif income <= 1600:
        reduction = 0.6
    elif income <= 2200:
        reduction = 0.35
    if inputs["single_adult"]:
        reduction = max(reduction, 0.25)
    if inputs["savings"] > 16000 and not inputs["on_guarantee_pension_credit"]:
        reduction = 0.0
    monthly_help = council_tax * min(reduction, 1.0)
    return {
        "primary_amount": round_money(monthly_help),
        "secondary_amount": round_money(monthly_help * 12),
        "primary_label": "Estimated monthly council tax help",
        "secondary_label": "Estimated annual council tax help",
        "summary": "Council Tax Reduction is set locally, so this page uses broad low-income bands and flags where means-tested benefits or a single-person discount usually strengthen entitlement.",
        "breakdown": [
            ("Current monthly council tax", council_tax),
            ("Reduction percentage used", round_money(min(reduction, 1.0) * 100)),
            ("Estimated monthly help", monthly_help),
        ],
        "notes": [
            "Each council runs its own scheme. Treat this as a directional estimate only.",
            "If you already qualify for the 25% single person discount, your remaining bill may still be reduced further by CTR depending on the local rules.",
        ],
    }


def housing_benefit_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    eligible_rent = inputs["weekly_rent"]
    income = inputs["weekly_income"]
    reduction = 0.0
    if inputs["legacy_claimant"]:
        if income <= 120:
            reduction = 1.0
        elif income <= 200:
            reduction = 0.75
        elif income <= 300:
            reduction = 0.45
        else:
            reduction = 0.2
        if inputs["spare_room"]:
            reduction -= 0.14
    if inputs["savings"] >= 16000 and not inputs["pension_age"]:
        reduction = 0.0
    weekly_help = max(0.0, eligible_rent * max(0.0, reduction))
    return {
        "primary_amount": round_money(weekly_help),
        "secondary_amount": round_money(weekly_help * 52),
        "primary_label": "Estimated weekly Housing Benefit",
        "secondary_label": "Estimated annual Housing Benefit",
        "summary": "Housing Benefit is now mainly for pension-age households and some supported or temporary housing cases, so this estimator is designed as a legacy checker rather than a new-claim tool.",
        "breakdown": [
            ("Weekly eligible rent used", eligible_rent),
            ("Income band applied", income),
            ("Estimated weekly support", weekly_help),
        ],
        "notes": [
            "Most new working-age claims now go through Universal Credit housing costs instead of Housing Benefit.",
            "Bedroom tax, local housing allowance, non-dependant deductions and service charge rules are simplified here.",
        ],
    }


def benefit_cap_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    if inputs["inside_london"]:
        cap = 2110.25 if inputs["household"] in {"couple", "single_parent"} else 1413.92
    else:
        cap = 1835.0 if inputs["household"] in {"couple", "single_parent"} else 1229.42
    monthly_benefits = inputs["monthly_benefits"]
    excess = max(0.0, monthly_benefits - cap)
    return {
        "primary_amount": round_money(excess),
        "secondary_amount": round_money(max(0.0, monthly_benefits - excess)),
        "primary_label": "Estimated monthly amount over the cap",
        "secondary_label": "Estimated capped benefit total",
        "summary": "The benefit cap depends mainly on whether you live inside Greater London and whether you are a couple, single parent or single adult.",
        "breakdown": [
            ("Monthly benefit total entered", monthly_benefits),
            ("Monthly cap used", cap),
            ("Amount over cap", -excess),
        ],
        "notes": [
            "Some households are exempt from the cap, including many people receiving disability-related benefits.",
            "If you are on Universal Credit, earnings can also stop the cap applying in some cases.",
        ],
    }


def ssp_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    weekly_rate = min(123.25, inputs["average_weekly_earnings"] * 0.8)
    weeks = min(28.0, inputs["weeks_off"])
    total = weekly_rate * weeks
    return {
        "primary_amount": round_money(weekly_rate),
        "secondary_amount": round_money(total),
        "primary_label": "Estimated weekly SSP",
        "secondary_label": "Estimated total SSP for absence",
        "summary": "This follows the April 2026 SSP structure: the lower of £123.25 a week or 80% of average weekly earnings, for up to 28 weeks.",
        "breakdown": [
            ("Average weekly earnings", inputs["average_weekly_earnings"]),
            ("Weekly SSP used", weekly_rate),
            ("Weeks used", weeks),
        ],
        "notes": [
            "From 6 April 2026, SSP is generally payable from the first full day of sickness absence for eligible employees.",
            "Your employer may pay more under a contractual sick pay scheme.",
        ],
    }


def maternity_comparison_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    awe = inputs["average_weekly_earnings"]
    smp_total = 0.0
    ma_total = 0.0
    if inputs["employed_long_enough"]:
        smp_total = min(awe * 0.9, awe) * 6 + min(187.18, awe * 0.9) * 33
    if inputs["employed_or_self_employed_long_enough"]:
        ma_total = min(194.32, awe * 0.9) * 39
    better = "Statutory Maternity Pay" if smp_total >= ma_total else "Maternity Allowance"
    return {
        "primary_amount": round_money(smp_total),
        "secondary_amount": round_money(ma_total),
        "primary_label": "Estimated total Statutory Maternity Pay",
        "secondary_label": "Estimated total Maternity Allowance",
        "summary": f"Based on the eligibility boxes you selected, {better} looks stronger on headline amount.",
        "breakdown": [
            ("SMP total", smp_total),
            ("Maternity Allowance total", ma_total),
        ],
        "notes": [
            "SMP usually requires 26 weeks with the same employer into the qualifying week. Maternity Allowance can help where SMP is not available.",
            "Both estimates assume the full 39 weeks of payable maternity support.",
        ],
    }


def esa_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    if not inputs["has_recent_ni_record"]:
        weekly_amount = 0.0
    else:
        weekly_amount = 145.90 if inputs["group"] == "support" else 95.55
        if inputs["private_pension_weekly"] > 85:
            weekly_amount -= (inputs["private_pension_weekly"] - 85) / 2
    weekly_amount = max(0.0, weekly_amount)
    return {
        "primary_amount": round_money(weekly_amount),
        "secondary_amount": round_money(weekly_amount * 52),
        "primary_label": "Indicative weekly New Style ESA",
        "secondary_label": "Indicative annual New Style ESA",
        "summary": "This page estimates New Style ESA using the work-related activity and support group weekly rates, then adjusts for private pension income above £85 a week.",
        "breakdown": [
            ("Base weekly ESA used", 145.90 if inputs["group"] == "support" else 95.55),
            ("Private pension entered", inputs["private_pension_weekly"]),
            ("Indicative ESA after pension adjustment", weekly_amount),
        ],
        "notes": [
            "You cannot usually get New Style ESA at the same time as Statutory Sick Pay.",
            "Many households can claim Universal Credit alongside or instead of ESA, but UC may then be reduced by the ESA amount.",
        ],
    }


def jsa_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    if not inputs["has_recent_ni_record"] or inputs["hours_worked"] >= 16:
        weekly_amount = 0.0
    else:
        weekly_amount = 95.55 if inputs["age_band"] == "25_plus" else 75.65
    return {
        "primary_amount": round_money(weekly_amount),
        "secondary_amount": round_money(min(182 / 7 * weekly_amount, weekly_amount * 26)),
        "primary_label": "Indicative weekly New Style JSA",
        "secondary_label": "Indicative six-month JSA total",
        "summary": "New Style JSA depends heavily on National Insurance history, age and whether you are working fewer than 16 hours a week.",
        "breakdown": [
            ("Weekly JSA used", weekly_amount),
            ("Hours worked each week", inputs["hours_worked"]),
        ],
        "notes": [
            "New claims are for New Style JSA. Income-based JSA is a legacy benefit.",
            "If your NI record is weak or your income is low, Universal Credit may be the more relevant route to check.",
        ],
    }


def working_tax_credit_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    max_award = 2435.0
    if inputs["household"] in {"couple", "lone_parent"}:
        max_award += 2500.0
    if inputs["hours_worked"] >= 30:
        max_award += 1015.0
    if inputs["disabled_worker"]:
        max_award += 3935.0
    threshold = 7955.0
    withdrawal = max(0.0, inputs["annual_income"] - threshold) * 0.41
    annual_award = max(0.0, max_award - withdrawal)
    return {
        "primary_amount": round_money(annual_award),
        "secondary_amount": round_money(annual_to_monthly(annual_award)),
        "primary_label": "Indicative annual Working Tax Credit",
        "secondary_label": "Indicative monthly equivalent",
        "summary": "Working Tax Credit ended for new claims on 5 April 2025. This page is a legacy reference estimator using the last published 2024 to 2025 rates.",
        "breakdown": [
            ("Maximum award basis used", max_award),
            ("Income reduction applied", -withdrawal),
            ("Legacy annual estimate", annual_award),
        ],
        "notes": [
            "This is mainly useful for transitional protection conversations, disputes and historic award checking.",
            "Most new low-income support claims now go through Universal Credit instead of tax credits.",
        ],
    }


def child_tax_credit_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    children = max(0, int(inputs["children"]))
    max_award = 545.0 + children * 3455.0
    threshold = 19995.0 if inputs["ctc_only"] else 7955.0
    withdrawal = max(0.0, inputs["annual_income"] - threshold) * 0.41
    annual_award = max(0.0, max_award - withdrawal)
    return {
        "primary_amount": round_money(annual_award),
        "secondary_amount": round_money(annual_to_monthly(annual_award)),
        "primary_label": "Indicative annual Child Tax Credit",
        "secondary_label": "Indicative monthly equivalent",
        "summary": "Child Tax Credit also closed to new claims on 5 April 2025. This page uses the final published legacy rates as a reference estimate.",
        "breakdown": [
            ("Family and child elements", max_award),
            ("Income reduction applied", -withdrawal),
            ("Legacy annual estimate", annual_award),
        ],
        "notes": [
            "Use this for historic or transitional cases only. New support for children is generally through Universal Credit and Child Benefit.",
            "Disability additions are not fully modelled on this simplified page.",
        ],
    }


def tax_free_childcare_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    children = max(1, int(inputs["children"]))
    quarterly_top_up_cap = 1000.0 if inputs["disabled_child"] else 500.0
    annual_top_up_cap = quarterly_top_up_cap * 4 * children
    annual_spend = max(0.0, inputs["annual_childcare_cost"])
    top_up = min(annual_spend * 0.25, annual_top_up_cap)
    return {
        "primary_amount": round_money(top_up),
        "secondary_amount": round_money(top_up / 12),
        "primary_label": "Estimated annual Tax-Free Childcare top-up",
        "secondary_label": "Estimated monthly equivalent",
        "summary": "Tax-Free Childcare adds £2 for every £8 you pay in, up to the published quarterly caps for each child.",
        "breakdown": [
            ("Annual childcare cost entered", annual_spend),
            ("Government top-up used", top_up),
        ],
        "notes": [
            "You cannot get Tax-Free Childcare at the same time as Universal Credit childcare support.",
            "The scheme normally stops the September after your child turns 11, or 16 if they are disabled.",
        ],
    }


def sure_start_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    eligible = inputs["qualifying_benefit"] and (inputs["first_child"] or inputs["multiple_birth_with_other_children"])
    amount = 500.0 if eligible else 0.0
    return {
        "primary_amount": amount,
        "secondary_amount": amount,
        "primary_label": "Indicative Sure Start Maternity Grant",
        "secondary_label": "One-off payment if eligible",
        "summary": "Sure Start Maternity Grant is a one-off £500 payment for eligible households, usually linked to a first child or some multiple birth cases.",
        "breakdown": [
            ("One-off grant", amount),
        ],
        "notes": [
            "The claim window is usually from 11 weeks before the due date until 6 months after birth.",
            "Scotland uses different family payment schemes instead of Sure Start Maternity Grant.",
        ],
    }


def healthy_start_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    eligible = inputs["pregnant_or_child_under_4"] and (inputs["qualifying_benefit"] or inputs["under_18_and_pregnant"])
    monthly_value = 17.0 if eligible else 0.0
    return {
        "primary_amount": monthly_value,
        "secondary_amount": round_money(monthly_value * 12),
        "primary_label": "Indicative monthly Healthy Start value",
        "secondary_label": "Indicative annual value",
        "summary": "This checker focuses on whether you are in the right pregnancy or child age group and whether a qualifying benefit route is in place.",
        "breakdown": [
            ("Indicative monthly support", monthly_value),
        ],
        "notes": [
            "Healthy Start support is delivered through a prepaid card and free vitamins rather than a standard benefit payment.",
            "The exact value varies by household composition and nation-specific alternatives apply in Scotland.",
        ],
    }


def free_school_meals_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    uc_route = inputs["on_universal_credit"] and inputs["annual_take_home_income"] < 7400
    eligible = uc_route or inputs["other_qualifying_benefit"] or inputs["infant_pupil"]
    meals = 190 * int(inputs["children"]) if eligible else 0
    return {
        "primary_amount": float(meals),
        "secondary_amount": float(meals),
        "primary_label": "Indicative school-year value of free meals",
        "secondary_label": "Indicative annual family value",
        "summary": "Eligibility in England depends mainly on qualifying benefits, with a specific £7,400 post-tax earnings test for most Universal Credit cases and universal infant free meals for reception to year 2.",
        "breakdown": [
            ("Children included", inputs["children"]),
            ("School-year value used", meals),
        ],
        "notes": [
            "This page is aimed at England. Scotland, Wales and Northern Ireland use different rules.",
            "The cash value shown is illustrative. Your actual gain depends on school term dates and meal pricing locally.",
        ],
    }


def winter_fuel_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    eligible = inputs["born_before_cutoff"] and inputs["lives_in_england_or_wales"]
    amount = 0.0
    if eligible:
        amount = 300.0 if inputs["born_before_older_cutoff"] else 200.0
        if inputs["income_over_35000"]:
            amount = 0.0
    return {
        "primary_amount": amount,
        "secondary_amount": amount,
        "primary_label": "Indicative Winter Fuel Payment",
        "secondary_label": "One-off winter payment",
        "summary": "This follows the 2026 to 2027 qualifying week age tests and flags the current £35,000 personal income clawback.",
        "breakdown": [
            ("Indicative payment", amount),
        ],
        "notes": [
            "Most eligible households are paid automatically in November or December.",
            "Scotland uses Pension Age Winter Heating Payment instead, and Northern Ireland has separate arrangements.",
        ],
    }


def cold_weather_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    eligible = inputs["qualifying_benefit"] and inputs["lives_outside_scotland"]
    total = 25.0 * max(0, int(inputs["triggered_periods"])) if eligible else 0.0
    return {
        "primary_amount": total,
        "secondary_amount": total,
        "primary_label": "Estimated Cold Weather Payment total",
        "secondary_label": "Winter total based on triggered periods",
        "summary": "Cold Weather Payments are £25 for each 7-day cold spell trigger in your area between 1 November and 31 March.",
        "breakdown": [
            ("Triggered cold spells entered", inputs["triggered_periods"]),
            ("Estimated total", total),
        ],
        "notes": [
            "The payment is automatic when your postcode area triggers and you meet the qualifying benefit rules.",
            "Scotland uses Winter Heating Payment instead of Cold Weather Payments.",
        ],
    }


def savings_impact_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    savings = inputs["savings"]
    threshold = 6000.0
    excess = max(0.0, savings - threshold)
    tariff_periods = math.ceil(excess / 250.0) if excess > 0 else 0
    monthly_deduction = tariff_periods * 4.35
    if savings >= 16000:
        return {
            "primary_amount": 0.0,
            "secondary_amount": 0.0,
            "primary_label": "Monthly UC deduction from savings",
            "secondary_label": "Annual UC reduction",
            "summary": "Savings of £16,000 or more mean you are not normally eligible for Universal Credit at all.",
            "breakdown": [
                ("Savings threshold", threshold),
                ("Savings entered", savings),
                ("UC award", 0.0),
            ],
            "notes": [
                "At £16,000 or more in savings, Universal Credit is not normally payable.",
                "Savings below £6,000 have no effect on your Universal Credit award.",
            ],
        }
    return {
        "primary_amount": round_money(monthly_deduction),
        "secondary_amount": round_money(monthly_deduction * 12),
        "primary_label": "Monthly UC deduction from savings",
        "secondary_label": "Annual UC reduction from savings",
        "summary": f"Savings of {currency(savings)} generate an assumed monthly income of {currency(monthly_deduction)}, which reduces your Universal Credit by that amount.",
        "breakdown": [
            ("Lower threshold", threshold),
            ("Excess savings above £6,000", excess),
            ("£250 bands above threshold", tariff_periods),
            ("Tariff income rate per band", 4.35),
            ("Monthly UC deduction", monthly_deduction),
        ],
        "notes": [
            "For every complete £250 above £6,000, DWP adds £4.35 to assumed monthly income, reducing Universal Credit by the same amount.",
            "Savings below £6,000 are fully disregarded. At £16,000 or more, UC eligibility normally stops entirely.",
        ],
    }


def earnings_impact_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    earnings = inputs["earnings"]
    household = inputs["household"]
    children = int(inputs["children"])
    housing_cost = inputs["housing_cost"]
    has_work_allowance = children > 0
    work_allowance = 404.0 if (has_work_allowance and housing_cost > 0) else (673.0 if has_work_allowance else 0.0)
    taper = 0.55
    taxable = max(0.0, earnings - work_allowance)
    uc_reduction = round_money(taxable * taper)
    extra_100_impact = round_money(100 * taper if earnings >= work_allowance else max(0.0, earnings + 100 - work_allowance) * taper)
    kept_per_100 = round_money(100 - extra_100_impact)
    return {
        "primary_amount": round_money(uc_reduction),
        "secondary_amount": round_money(kept_per_100),
        "primary_label": "Monthly UC reduction at current earnings",
        "secondary_label": "UC kept per extra £100 earned",
        "summary": f"After the {currency(work_allowance)} work allowance, the 55% taper reduces UC by {currency(uc_reduction)} a month. For each extra £100 earned, you keep {currency(kept_per_100)} net.",
        "breakdown": [
            ("Monthly earnings entered", earnings),
            ("Work allowance", work_allowance),
            ("Earnings above work allowance", max(0.0, taxable)),
            ("55% taper deduction", -uc_reduction),
            ("UC kept per £100 extra earned", kept_per_100),
        ],
        "notes": [
            "The work allowance (£404 or £673 depending on housing support) only applies if you have children or a health/disability element.",
            "Without a work allowance the 55% taper starts from the first pound of net earnings.",
        ],
    }


def maternity_pay_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    weekly_pay = inputs["weekly_pay"]
    weeks_higher = min(int(inputs["weeks_higher"]), 6)
    weeks_lower = min(int(inputs["weeks_lower"]), 33)
    smp_rate_lower = 184.03
    higher_total = weekly_pay * 0.9 * weeks_higher
    lower_total = smp_rate_lower * weeks_lower
    total = higher_total + lower_total
    return {
        "primary_amount": round_money(total),
        "secondary_amount": round_money(weekly_pay * 0.9),
        "primary_label": "Estimated total SMP over maternity leave",
        "secondary_label": "Weekly SMP in the first 6 weeks (90%)",
        "summary": f"Statutory Maternity Pay estimated at {currency(weekly_pay * 0.9)}/week for the first {weeks_higher} weeks, then {currency(smp_rate_lower)}/week for {weeks_lower} weeks.",
        "breakdown": [
            ("Average weekly pay entered", weekly_pay),
            ("First 6 weeks — 90% of pay", round_money(weekly_pay * 0.9)),
            (f"Weeks at higher rate ({weeks_higher})", higher_total),
            (f"Flat rate weeks — £{smp_rate_lower}/week", smp_rate_lower),
            (f"Weeks at flat rate ({weeks_lower})", lower_total),
            ("Estimated total SMP", total),
        ],
        "notes": [
            "SMP is normally payable for up to 39 weeks. The first 6 weeks are paid at 90% of average weekly earnings; weeks 7 to 39 are paid at the statutory flat rate (£184.03 in 2026/27) or 90% of earnings if lower.",
            "You need to have been employed for at least 26 weeks into the qualifying week and earning above the lower earnings limit to qualify.",
        ],
    }


def tax_free_childcare_monthly_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    monthly_childcare = inputs["monthly_childcare"]
    children = max(1, int(inputs["children"]))
    annual_spend = monthly_childcare * 12
    annual_cap_per_child = 2000.0
    annual_cap = annual_cap_per_child * children
    annual_top_up = min(annual_spend * 0.25, annual_cap)
    monthly_top_up = annual_top_up / 12
    return {
        "primary_amount": round_money(monthly_top_up),
        "secondary_amount": round_money(annual_top_up),
        "primary_label": "Estimated monthly government top-up",
        "secondary_label": "Estimated annual government top-up",
        "summary": f"For {currency(monthly_childcare)}/month on childcare, the government adds {currency(monthly_top_up)}/month — up to the annual cap of {currency(annual_cap)} for {children} child{'ren' if children > 1 else ''}.",
        "breakdown": [
            ("Monthly childcare entered", monthly_childcare),
            ("Annual childcare spend", annual_spend),
            ("Annual cap used", annual_cap),
            ("Government top-up (20p per 80p)", annual_top_up),
            ("Monthly equivalent", monthly_top_up),
        ],
        "notes": [
            "The government adds 20p for every 80p you pay in, up to £500 per child per quarter (£2,000 per year) for most children.",
            "You cannot use Tax-Free Childcare at the same time as Universal Credit childcare support — compare both before choosing.",
        ],
    }


def attendance_allowance_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    rate = inputs["rate"]  # "lower" or "higher"
    weekly = 73.90 if rate == "lower" else 110.40
    annual = round_money(weekly * 52)
    label = "lower rate" if rate == "lower" else "higher rate"
    return {
        "primary_amount": round_money(weekly),
        "secondary_amount": annual,
        "primary_label": "Estimated weekly Attendance Allowance",
        "secondary_label": "Estimated annual Attendance Allowance",
        "summary": f"The {label} of Attendance Allowance is {currency(weekly)} a week in 2026/27 ({currency(annual)} a year). It is not means tested — income and savings have no effect.",
        "breakdown": [
            ("Weekly Attendance Allowance", weekly),
            ("Annual equivalent (52 weeks)", annual),
        ],
        "notes": [
            "Attendance Allowance is non-means-tested — income, savings and whether you live with a partner have no effect.",
            "Lower rate: care needs during the day or night. Higher rate: care needs day and night, or terminally ill.",
            "Receiving Attendance Allowance can passport you to higher Pension Credit, Council Tax Reduction and Housing Benefit awards.",
            "Attendance Allowance is for people over State Pension age. Under State Pension age, PIP applies instead.",
        ],
    }


def carers_allowance_estimate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    weekly_earnings = inputs["weekly_earnings"]
    hours_caring = inputs["hours_caring"]
    has_qualifying_benefit = inputs["has_qualifying_benefit"]
    earnings_limit = 151.0
    weekly_rate = 81.90

    if hours_caring < 35:
        eligible = False
        reason = f"You need to care for at least 35 hours a week. You entered {hours_caring} hours."
        weekly = 0.0
    elif not has_qualifying_benefit:
        eligible = False
        reason = "The person you care for must receive a qualifying disability benefit (PIP daily living, DLA care, Attendance Allowance or similar)."
        weekly = 0.0
    elif weekly_earnings > earnings_limit:
        eligible = False
        reason = f"Your weekly earnings ({currency(weekly_earnings)}) are above the £{earnings_limit}/week earnings limit after permitted deductions."
        weekly = 0.0
    else:
        eligible = True
        reason = "Indicative eligibility: contribution conditions and other rules may apply."
        weekly = weekly_rate

    annual = round_money(weekly * 52)
    return {
        "primary_amount": round_money(weekly),
        "secondary_amount": annual,
        "primary_label": "Estimated weekly Carer's Allowance",
        "secondary_label": "Estimated annual Carer's Allowance",
        "summary": reason if not eligible else f"Carer's Allowance is {currency(weekly_rate)} a week in 2026/27 ({currency(annual)} a year) if eligible. It is taxable and may reduce Universal Credit by the same amount.",
        "breakdown": [
            ("Weekly Carer's Allowance rate", weekly_rate),
            ("Your weekly earnings", weekly_earnings),
            ("Earnings limit", earnings_limit),
            ("Hours caring per week", hours_caring),
            ("Estimated weekly award", weekly),
        ],
        "notes": [
            "Carer's Allowance is taxable and counts as income for Universal Credit purposes — UC will usually be reduced by £1 for every £1 of Carer's Allowance received.",
            "You may still have 'underlying entitlement' to Carer's Allowance even if a higher benefit (like State Pension) prevents actual payment — this can still trigger a carer element in UC.",
            "The earnings limit is £151/week net after tax, NI and 50% of pension contributions.",
            "The person you care for must receive PIP (daily living component), DLA (middle or high care), Attendance Allowance, or similar.",
        ],
    }


CALCULATION_FUNCTIONS = {
    "universal_credit": universal_credit_estimate,
    "child_benefit": child_benefit_estimate,
    "hicbc": hicbc_estimate,
    "pension_credit": pension_credit_estimate,
    "pip": pip_estimate,
    "council_tax_reduction": council_tax_reduction_estimate,
    "housing_benefit": housing_benefit_estimate,
    "benefit_cap": benefit_cap_estimate,
    "ssp": ssp_estimate,
    "maternity_comparison": maternity_comparison_estimate,
    "esa": esa_estimate,
    "jsa": jsa_estimate,
    "working_tax_credit": working_tax_credit_estimate,
    "child_tax_credit": child_tax_credit_estimate,
    "tax_free_childcare": tax_free_childcare_estimate,
    "sure_start": sure_start_estimate,
    "healthy_start": healthy_start_estimate,
    "free_school_meals": free_school_meals_estimate,
    "winter_fuel": winter_fuel_estimate,
    "cold_weather": cold_weather_estimate,
    "savings_impact": savings_impact_estimate,
    "earnings_impact": earnings_impact_estimate,
    "maternity_pay": maternity_pay_estimate,
    "tax_free_childcare_monthly": tax_free_childcare_monthly_estimate,
    "attendance_allowance": attendance_allowance_estimate,
    "carers_allowance": carers_allowance_estimate,
}


def calc_page(
    slug: str,
    name: str,
    description: str,
    summary: str,
    formula: str,
    fields: List[Dict[str, Any]],
    faq: List[Dict[str, str]],
    sections: List[Dict[str, Any]],
    aliases: List[str],
    related: List[str],
) -> Dict[str, Any]:
    return {
        "slug": slug,
        "url": f"/{slug}",
        "title": name,
        "description": description,
        "summary": summary,
        "formula": formula,
        "fields": fields,
        "faq": faq,
        "sections": sections,
        "aliases": aliases,
        "related": related,
    }


COMMON_CHILDREN_FIELD = {"name": "children", "label": "Children included", "type": "number", "default": 2, "step": 1, "min": 0}
COMMON_SAVINGS_FIELD = {"name": "savings", "label": "Savings and investments", "type": "number", "default": 0, "step": 100, "min": 0, "prefix": "£"}

CALCULATORS: Dict[str, Dict[str, Any]] = {
    "universal-credit-calculator": calc_page(
        "universal-credit-calculator",
        "Universal Credit calculator 2026/27",
        "Estimate monthly Universal Credit using household type, children, housing costs, childcare, earnings and savings. Independent UK estimator with the £6,000 and £16,000 capital rules.",
        "Estimate what support you may get through Universal Credit using a simplified but practical monthly model with savings and tariff income effects shown early.",
        "universal_credit",
        [
            {"name": "age_band", "label": "Main claimant age", "type": "select", "default": "25_plus", "options": [{"value": "under_25", "label": "Under 25"}, {"value": "25_plus", "label": "25 or over"}]},
            {"name": "household", "label": "Household type", "type": "select", "default": "single", "options": [{"value": "single", "label": "Single"}, {"value": "couple", "label": "Couple"}]},
            COMMON_CHILDREN_FIELD,
            {"name": "first_child_pre_2017", "label": "First child born before 6 April 2017", "type": "boolean", "default": False},
            {"name": "housing_cost", "label": "Monthly eligible rent", "type": "number", "default": 750, "step": 25, "min": 0, "prefix": "£"},
            {"name": "earnings", "label": "Monthly take-home earnings", "type": "number", "default": 1200, "step": 25, "min": 0, "prefix": "£"},
            COMMON_SAVINGS_FIELD,
            {"name": "childcare_cost", "label": "Monthly registered childcare cost", "type": "number", "default": 0, "step": 25, "min": 0, "prefix": "£"},
            {"name": "health", "label": "Health element assumption", "type": "select", "default": "none", "options": [{"value": "none", "label": "None"}, {"value": "standard", "label": "Lower LCWRA rate"}, {"value": "severe", "label": "Higher LCWRA rate"}]},
        ],
        [
            {"q": "Is this an official Universal Credit calculator?", "a": "No. This is an independent estimator designed to help you sense-check likely entitlement before you use an official claim or adviser route."},
            {"q": "Does it include the April 2026 child element change?", "a": "Yes. The estimator assumes the child element can apply for every eligible child from 6 April 2026, while still warning that the benefit cap can limit the outcome."},
            {"q": "Why is housing support only an estimate?", "a": "Actual housing help depends on your rent type, bedroom entitlement, local housing allowance area, service charges and whether you are in temporary or supported housing."},
        ],
        [
            {"heading": "What this Universal Credit calculator covers", "paragraphs": ["This page is built for people who want a fast but sensible Universal Credit estimate without pretending to be a full DWP decision engine. It uses the current standard allowances, child element, childcare reimbursement, savings taper and earnings taper, then shows how those pieces interact.", "The output is most useful for quick scenario planning: checking whether extra earnings are likely to reduce support sharply, seeing whether childcare support changes the picture, and understanding whether savings are the main reason an award looks low."]},
            {"heading": "Where the estimate is deliberately simplified", "paragraphs": ["Housing support is one of the most complex parts of Universal Credit, so this site uses your entered rent with a visible cap rather than pretending it knows your exact local housing allowance or service-charge position. That keeps the page useful without inventing false precision.", "The same principle applies to deductions, sanctions, transitional protection and managed migration. They can materially affect real awards, but they are specific enough that a short on-page estimator should flag them rather than fake certainty."]},
            {"heading": "Best next steps after using the estimate", "paragraphs": ["If this checker suggests you may qualify, keep a note of your monthly earnings, rent, childcare invoices and savings because those are the numbers most likely to change the final award. If your estimate looks low, compare it against the benefit cap page and the council tax reduction page because those can explain the gap.", "For childcare planning, also compare Tax-Free Childcare before you commit. You cannot normally claim both schemes at the same time, and the stronger option can change depending on your hours and childcare bill."]},
        ],
        ["universal-credit-estimator", "universal-credit-checker"],
        ["child-benefit-calculator", "benefit-cap-calculator", "council-tax-reduction-calculator", "tax-free-childcare-calculator"],
    ),
    "child-benefit-calculator": calc_page(
        "child-benefit-calculator",
        "Child Benefit calculator 2026/27",
        "Estimate weekly, monthly and annual Child Benefit for 2026 to 2027 using the latest published UK rates for 1, 2 or more children.",
        "Work out the current Child Benefit amount for your household and compare it with the HICBC charge if income is higher.",
        "child_benefit",
        [COMMON_CHILDREN_FIELD],
        [
            {"q": "What rates does this Child Benefit calculator use?", "a": "It uses the confirmed 2026 to 2027 weekly rates of £27.05 for the eldest or only child and £17.90 for each additional child."},
            {"q": "Does Child Benefit affect Universal Credit?", "a": "Child Benefit is paid separately, but it can still count towards the benefit cap if the cap applies to your household."},
            {"q": "Should higher earners still claim Child Benefit?", "a": "Often yes. Some households still claim and either pay the HICBC or opt out of payments so National Insurance credits are protected."},
        ],
        [
            {"heading": "A straightforward Child Benefit estimate", "paragraphs": ["Child Benefit is one of the simplest mainstream UK family payments to estimate because the weekly rates are fixed and not means tested. That makes this page useful as both a quick budgeting tool and a first step before checking whether the High Income Child Benefit Charge could claw some or all of it back.", "The output is shown as weekly and annual totals because many parents think about Child Benefit in weekly terms, while tax planning for HICBC usually works better on an annual basis."]},
            {"heading": "Why this page links directly to HICBC", "paragraphs": ["A Child Benefit figure on its own can be misleading for households with one higher earner. If either partner’s adjusted net income goes above the threshold, some or all of the benefit may need to be paid back through PAYE or Self Assessment.", "That is why this calculator deliberately sends you onwards to the HICBC page rather than leaving the family payment isolated. Search intent here is often a combined question: how much do I get, and do I actually keep it."]},
            {"heading": "When Child Benefit still matters even if payments stop", "paragraphs": ["Some people opt out of receiving Child Benefit payments because of the tax charge, but keep the claim live. That can still protect National Insurance credits and help make sure a child gets a National Insurance number automatically later on.", "For many households the practical question is not just whether the payment lands in the bank, but whether the claim itself should exist. This page is written with that real-world decision in mind."]},
        ],
        ["child-benefit-estimator", "child-benefit-rates", "how-much-child-benefit"],
        ["hicbc-calculator", "tax-free-childcare-calculator", "free-school-meals-checker", "universal-credit-calculator"],
    ),
    "hicbc-calculator": calc_page(
        "hicbc-calculator",
        "High Income Child Benefit Charge calculator 2026",
        "Calculate the High Income Child Benefit Charge (HICBC) using adjusted net income and 2026/27 Child Benefit rates across the £60,000 to £80,000 taper band.",
        "Check how much Child Benefit a higher earner may have to repay through the HICBC in 2026/27 and how much the household may actually keep.",
        "hicbc",
        [COMMON_CHILDREN_FIELD, {"name": "adjusted_net_income", "label": "Adjusted net income", "type": "number", "default": 68000, "step": 100, "min": 0, "prefix": "£"}],
        [
            {"q": "When does the High Income Child Benefit Charge start?", "a": "For tax years from 2024 to 2025 onwards, it starts when adjusted net income is above £60,000 and reaches 100% at £80,000."},
            {"q": "How quickly does the charge rise?", "a": "The charge increases by 1% of your Child Benefit for every £200 of adjusted net income above £60,000."},
            {"q": "Can pension contributions reduce the charge?", "a": "Often yes. Because the charge is based on adjusted net income, some pension contributions and Gift Aid donations can reduce the figure used."},
        ],
        [
            {"heading": "How this HICBC calculator works", "paragraphs": ["This page first estimates the annual Child Benefit attached to your household, then applies the current taper used by HMRC. The result is intentionally shown as an annual tax charge because that mirrors how most people eventually deal with it through PAYE coding changes or Self Assessment.", "The calculation is simple enough to be useful, but the page still uses adjusted net income language rather than basic salary because that distinction matters. A family can sit above or below the threshold depending on pension contributions, dividends, savings interest and Gift Aid."]},
            {"heading": "Why HICBC planning matters before you change salary sacrifice or pension contributions", "paragraphs": ["This is one of those tax charges where a small planning decision can have a visible impact. If you are close to the taper band, pension contributions can sometimes reduce the charge more efficiently than people expect.", "That does not mean everyone should change contributions just to avoid the charge. It means the charge should be part of the same conversation as childcare costs, household cashflow and tax planning rather than treated as a surprise later."]},
            {"heading": "Use this alongside the Child Benefit page", "paragraphs": ["Families often search for HICBC after hearing they may need to repay Child Benefit, but the right next question is usually whether they should still claim or whether they should opt out of payments. This site is built so the Child Benefit and HICBC pages support that full decision path.", "If your income is volatile, run a couple of scenarios rather than one. The charge is tax-year based, so bonuses and dividend changes can shift the answer late in the year."]},
        ],
        ["high-income-child-benefit-charge-calculator", "child-benefit-tax-charge-calculator"],
        ["child-benefit-calculator", "tax-free-childcare-calculator", "working-tax-credit-calculator"],
    ),
    "pension-credit-calculator": calc_page(
        "pension-credit-calculator",
        "Pension Credit calculator 2026/27",
        "Estimate Guarantee Credit using weekly income, savings and key additions such as severe disability or carer status.",
        "Check whether low retirement income could translate into Pension Credit, even with savings, and the wider passported help that often comes with it.",
        "pension_credit",
        [
            {"name": "household", "label": "Household type", "type": "select", "default": "single", "options": [{"value": "single", "label": "Single"}, {"value": "couple", "label": "Couple"}]},
            {"name": "weekly_income", "label": "Weekly income before Pension Credit", "type": "number", "default": 180, "step": 1, "min": 0, "prefix": "£"},
            COMMON_SAVINGS_FIELD,
            {"name": "severe_disability", "label": "Severe disability addition likely", "type": "boolean", "default": False},
            {"name": "carer", "label": "Carer addition likely", "type": "boolean", "default": False},
        ],
        [
            {"q": "Can you get Pension Credit if you own your home?", "a": "Yes. Home ownership does not stop Pension Credit on its own."},
            {"q": "Do savings rule Pension Credit out?", "a": "Not necessarily. Savings under £10,000 are ignored, and amounts above that are usually treated as extra weekly income rather than an automatic disqualification."},
            {"q": "Why check Pension Credit even for a small award?", "a": "Because even a modest award can unlock other help such as council tax support, cold weather support, NHS cost help and sometimes heating discounts."},
        ],
        [
            {"heading": "Why Pension Credit is often missed", "paragraphs": ["A common mistake is assuming Pension Credit is only for people with no savings or no pension income. In reality the scheme is designed to top income up to a minimum level, and small occupational pensions or modest savings do not automatically remove entitlement.", "That makes a quick checker genuinely useful. Many households are not asking whether they will receive a large benefit. They are asking whether they may qualify for the gateway to wider support."]},
            {"heading": "The importance of passported support", "paragraphs": ["Pension Credit can trigger help that matters as much as the weekly cash top-up itself. Council Tax Reduction, Cold Weather Payments, NHS support and housing help can change a household budget materially once entitlement is in place.", "For that reason, this calculator shows the core Guarantee Credit estimate but the page copy repeatedly points to the wider system around it. Ranking value comes from answering the real search intent, not just the arithmetic."]},
            {"heading": "Where this estimate is still only a guide", "paragraphs": ["This page does not fully model Savings Credit, housing costs, mixed-age couples or all disability-linked additions. Those details can shift the final award, especially where legacy entitlement overlaps with current claims.", "Even so, it is a practical first-pass checker because it highlights the main thresholds and the savings treatment that many people misunderstand."]},
        ],
        ["pension-credit-estimator", "can-i-get-pension-credit"],
        ["winter-fuel-payment-checker", "cold-weather-payment-checker", "council-tax-reduction-calculator"],
    ),
    "pip-eligibility-checker": calc_page(
        "pip-eligibility-checker",
        "PIP eligibility checker 2026/27",
        "Use a simplified points-based PIP checker to estimate whether a daily living or mobility award may be in range, plus the current weekly, monthly and annual amounts.",
        "Sense-check a likely PIP band by entering your likely points for daily living and mobility activities, then see the current PIP rates.",
        "pip",
        [
            {"name": "daily_living_points", "label": "Daily living points", "type": "number", "default": 8, "step": 1, "min": 0},
            {"name": "mobility_points", "label": "Mobility points", "type": "number", "default": 4, "step": 1, "min": 0},
        ],
        [
            {"q": "Is PIP based on income or savings?", "a": "No. PIP is not means tested. It depends on how your condition affects you in daily living and mobility activities."},
            {"q": "What points usually trigger an award?", "a": "Standard rate generally starts at 8 points and enhanced rate at 12 points within either component."},
            {"q": "Can you get only one component?", "a": "Yes. Some people qualify for only daily living, some only mobility, and some receive both."},
        ],
        [
            {"heading": "What this PIP checker is designed to do well", "paragraphs": ["PIP is one of the most searched-for UK benefits because the official process feels opaque. This page does not try to replace the descriptor-by-descriptor assessment, but it does give you a quick way to translate points into likely rate bands and weekly amounts.", "That makes it useful for preparation. If your likely points are close to 8 or 12 in a component, the priority becomes evidence quality and descriptor accuracy rather than just the headline amount."]},
            {"heading": "Why this checker avoids pretending to predict a DWP decision", "paragraphs": ["PIP outcomes depend on the detail behind each activity: whether help is needed safely, repeatedly, to an acceptable standard and in a reasonable time. A two-box checker cannot replicate that properly, so this page is explicit that the result is indicative only.", "That honesty is useful for both users and search quality. A misleadingly precise PIP calculator would look stronger on first glance but would be worse in practice."]},
            {"heading": "Use the estimate to guide evidence gathering", "paragraphs": ["If this checker suggests a standard or enhanced rate could be in range, the next step is usually to map your points against the evidence you already have: letters, care plans, prescriptions, specialist reports or symptom diaries. That is where many PIP claims become stronger.", "If the estimate looks low but your condition still affects you heavily, it may mean the issue is how your likely descriptor points are being framed rather than whether support exists."]},
        ],
        ["pip-calculator", "personal-independence-payment-checker"],
        ["esa-calculator", "universal-credit-calculator", "cold-weather-payment-checker"],
    ),
    "council-tax-reduction-calculator": calc_page(
        "council-tax-reduction-calculator",
        "Council Tax Reduction estimator",
        "Estimate possible council tax support using local-bill size, income, benefits and savings. Independent UK checker.",
        "Check whether a low income or means-tested benefit could reduce your council tax bill.",
        "council_tax_reduction",
        [
            {"name": "monthly_council_tax", "label": "Monthly council tax bill", "type": "number", "default": 165, "step": 1, "min": 0, "prefix": "£"},
            {"name": "monthly_income", "label": "Monthly household income", "type": "number", "default": 1350, "step": 25, "min": 0, "prefix": "£"},
            COMMON_SAVINGS_FIELD,
            {"name": "single_adult", "label": "Single adult in the home", "type": "boolean", "default": False},
            {"name": "on_means_tested_benefit", "label": "On a means-tested benefit", "type": "boolean", "default": False},
            {"name": "on_guarantee_pension_credit", "label": "On Guarantee Pension Credit", "type": "boolean", "default": False},
        ],
        [{"q": "Is Council Tax Reduction the same everywhere?", "a": "No. Each local authority runs its own scheme, so this page is a broad estimator rather than a final decision tool."}, {"q": "Can you get help if you work?", "a": "Often yes. Many working households still qualify if income is low enough."}, {"q": "Does the 25% single person discount matter?", "a": "Yes. It is separate from means-tested Council Tax Reduction, and some households can benefit from both."}],
        [
            {"heading": "A practical local-scheme estimator", "paragraphs": ["Council Tax Reduction is one of the hardest benefits to model nationally because the rule set is local, not single-source. That is why this estimator uses transparent income bands and clear warning text rather than pretending every council behaves the same way.", "Even with that limitation, the page is useful because the search intent is usually directional: am I likely to get meaningful help, and is it worth applying."]},
            {"heading": "What usually changes the result most", "paragraphs": ["The biggest variables are your local scheme, household income, savings, whether you are on a means-tested benefit already and whether there are other adults in the property. People often focus only on income, but local rules can be just as important.", "Single-person discount is another area that confuses users. It is not the same as CTR, so this page explains how the two can interact."]},
            {"heading": "Why this page links to rent and heating support pages", "paragraphs": ["People searching for Council Tax Reduction are often facing wider affordability pressure rather than an isolated bill issue. That means rent support, Pension Credit, Free School Meals and winter help are commonly part of the same search journey.", "The site architecture keeps those pages tightly linked on purpose so the calculator cluster behaves like a serious support hub, not a one-page tool."]},
        ],
        ["council-tax-support-calculator", "council-tax-reduction-estimator"],
        ["housing-benefit-calculator", "pension-credit-calculator", "winter-fuel-payment-checker"],
    ),
    "housing-benefit-calculator": calc_page(
        "housing-benefit-calculator",
        "Housing Benefit estimator",
        "Check whether a legacy Housing Benefit case may still qualify using weekly rent, income, savings and pension-age status.",
        "Estimate possible Housing Benefit in legacy or pension-age cases and understand when Universal Credit housing costs are more relevant.",
        "housing_benefit",
        [
            {"name": "weekly_rent", "label": "Weekly eligible rent", "type": "number", "default": 140, "step": 1, "min": 0, "prefix": "£"},
            {"name": "weekly_income", "label": "Weekly household income", "type": "number", "default": 180, "step": 1, "min": 0, "prefix": "£"},
            COMMON_SAVINGS_FIELD,
            {"name": "legacy_claimant", "label": "Legacy or pension-age route", "type": "boolean", "default": True},
            {"name": "pension_age", "label": "At least one claimant is over State Pension age", "type": "boolean", "default": False},
            {"name": "spare_room", "label": "Social housing spare room reduction may apply", "type": "boolean", "default": False},
        ],
        [{"q": "Can working-age households still make new Housing Benefit claims?", "a": "Usually no, unless the case falls into a specialist category such as supported or temporary accommodation. Most new working-age housing support is through Universal Credit."}, {"q": "Does savings matter?", "a": "Yes. For many working-age cases, savings of £16,000 or more can stop entitlement."}, {"q": "Is rent covered in full?", "a": "Not always. Bedroom rules, service charge rules, income deductions and local caps can all reduce the final award."}],
        [
            {"heading": "Built as a legacy Housing Benefit checker", "paragraphs": ["This page is intentionally framed as an estimator rather than a universal rent calculator because Housing Benefit is now mostly a legacy or specialist route. That positioning matters: it helps the site answer the search term while steering most new claimants towards the more relevant Universal Credit housing path.", "The logic focuses on broad weekly support bands, which is usually enough for someone trying to understand whether a historic award or pension-age claim is plausible."]},
            {"heading": "Why rent help is difficult to model perfectly", "paragraphs": ["Housing support depends on the kind of tenancy you have, whether your accommodation is private or social, local housing allowance rules, eligible service charges and any spare room deductions. Those are too specific to model cleanly in a lightweight public-facing page without postcode-level data.", "Rather than hide that, the page keeps the calculation modest and pushes users towards the exact issues most likely to change the answer."]},
            {"heading": "When to use Universal Credit instead", "paragraphs": ["If you are working age and thinking about a new housing support claim, Universal Credit housing costs are usually the first page to understand, especially if you also need help with living costs. That is why this page cross-links back into the broader benefits cluster.", "The aim is not to trap users on a legacy route, but to meet the search intent and then guide them towards the right next step."]},
        ],
        ["housing-benefit-estimator", "rent-benefit-calculator"],
        ["universal-credit-calculator", "council-tax-reduction-calculator", "benefit-cap-calculator"],
    ),
    "benefit-cap-calculator": calc_page(
        "benefit-cap-calculator",
        "Benefit Cap calculator",
        "Check whether your monthly benefits appear to be above the current cap inside or outside Greater London, using the current family and single-adult limits.",
        "See whether a household benefit total looks higher than the current Benefit Cap limit and whether an exemption is the next thing to check.",
        "benefit_cap",
        [
            {"name": "monthly_benefits", "label": "Monthly benefits total", "type": "number", "default": 1950, "step": 10, "min": 0, "prefix": "£"},
            {"name": "inside_london", "label": "Home is inside Greater London", "type": "boolean", "default": False},
            {"name": "household", "label": "Household type", "type": "select", "default": "single_parent", "options": [{"value": "single_adult", "label": "Single adult"}, {"value": "single_parent", "label": "Single parent"}, {"value": "couple", "label": "Couple"}]},
        ],
        [{"q": "Which benefits count towards the cap?", "a": "Universal Credit, Housing Benefit, Child Benefit and several income-replacement benefits can count towards the cap."}, {"q": "Are some households exempt?", "a": "Yes. Many people receiving disability-related benefits are exempt, and earnings can also stop the cap applying in some Universal Credit cases."}, {"q": "Why show monthly figures?", "a": "The cap is often discussed monthly in Universal Credit and household budgeting, even though some official tables also show weekly figures."}],
        [
            {"heading": "Why the Benefit Cap still matters in calculator journeys", "paragraphs": ["People often leave a Universal Credit estimator wondering why the number still looks lower than expected. One of the main reasons is the Benefit Cap, especially for larger households with rent support. This page is designed to answer that follow-up question quickly.", "It does not try to check every exemption because that would turn a practical page into a maze. Instead, it shows the cap amount clearly and warns where exemptions commonly apply."]},
            {"heading": "Greater London and household type are the key first split", "paragraphs": ["Most users do not need a detailed legal explainer to start. They need to know whether they should use the London or outside-London figure, and whether the household is treated as a single adult or a family household for cap purposes.", "That is why the interface is simple: it captures the two variables that explain most of the headline outcome before pushing further into exemptions if needed."]},
            {"heading": "Use this after the Universal Credit and Child Benefit pages", "paragraphs": ["The Benefit Cap page is deliberately integrated with the wider benefits cluster because the cap often explains why adding children or rent does not produce the increase users expect. That connection is important for both UX and internal linking depth.", "In practice, if this page suggests you are over the cap, the next step is usually checking disability-linked exemptions, earnings rules or specialist housing advice."]},
        ],
        ["benefits-cap-calculator", "benefit-cap-estimator"],
        ["universal-credit-calculator", "child-benefit-calculator", "housing-benefit-calculator"],
    ),
    "ssp-calculator": calc_page(
        "ssp-calculator",
        "Statutory Sick Pay calculator",
        "Estimate weekly and total Statutory Sick Pay under the current 2026 rules using average weekly earnings and time off.",
        "Quickly estimate SSP under the latest weekly-rate or 80%-of-earnings rule.",
        "ssp",
        [
            {"name": "average_weekly_earnings", "label": "Average weekly earnings", "type": "number", "default": 420, "step": 1, "min": 0, "prefix": "£"},
            {"name": "weeks_off", "label": "Weeks off sick", "type": "number", "default": 4, "step": 1, "min": 0},
        ],
        [{"q": "What weekly rate does this use?", "a": "It uses the 2026 to 2027 SSP rule of the lower of £123.25 a week or 80% of average weekly earnings."}, {"q": "How long can SSP be paid for?", "a": "Up to 28 weeks."}, {"q": "Can my employer pay more?", "a": "Yes. Contractual or occupational sick pay can be more generous than SSP."}],
        [
            {"heading": "SSP changed materially in April 2026", "paragraphs": ["This page reflects the updated SSP framework now used from 6 April 2026, where eligible employees can receive the lower of the flat weekly rate or 80% of average weekly earnings. That makes an updated estimator genuinely useful because older SSP pages can now be wrong.", "The calculator is intentionally simple because the core search intent is usually immediate: what is the likely weekly amount, and what does a period off sick add up to."]},
            {"heading": "Where real-world payroll can still differ", "paragraphs": ["Employers calculate SSP using average weekly earnings, qualifying days and payroll timing rules. If your absences cross the April 2026 change point or involve linked periods, the real payment can differ from this clean estimate.", "There is also a separate question of whether an employer offers contractual sick pay. Many people search SSP when what they really need is to compare the statutory minimum with their workplace scheme."]},
            {"heading": "Why SSP fits naturally on a broader benefits site", "paragraphs": ["Statutory Sick Pay sits at the boundary between payroll and the benefits system. If SSP is low or ending, the next search is often ESA, Universal Credit or PIP depending on how long the condition lasts and whether work is still possible.", "That is why this page is included in the benefits suite rather than treated as an isolated employment-law tool."]},
        ],
        ["statutory-sick-pay-calculator", "sick-pay-calculator"],
        ["esa-calculator", "universal-credit-calculator", "pip-eligibility-checker"],
    ),
    "maternity-pay-comparison": calc_page(
        "maternity-pay-comparison",
        "Maternity Allowance vs Statutory Maternity Pay calculator",
        "Compare likely Statutory Maternity Pay and Maternity Allowance totals using average weekly earnings and basic eligibility checks.",
        "Compare the two main maternity payment routes and see which looks more relevant for your situation.",
        "maternity_comparison",
        [
            {"name": "average_weekly_earnings", "label": "Average weekly earnings", "type": "number", "default": 380, "step": 1, "min": 0, "prefix": "£"},
            {"name": "employed_long_enough", "label": "Employed long enough for SMP route", "type": "boolean", "default": True},
            {"name": "employed_or_self_employed_long_enough", "label": "Worked or self-employed long enough for MA route", "type": "boolean", "default": True},
        ],
        [{"q": "Which is usually worth more?", "a": "If you qualify, SMP is often stronger for the first 6 weeks because it pays 90% of average weekly earnings with no flat-rate cap in that period."}, {"q": "Can self-employed people get SMP?", "a": "No. Self-employed claimants normally look at Maternity Allowance instead."}, {"q": "Are both paid for 39 weeks?", "a": "Yes, both are typically payable for up to 39 weeks."}],
        [
            {"heading": "Two routes, very different entry rules", "paragraphs": ["Many maternity-related searches are not really asking for one flat number. They are trying to work out whether Statutory Maternity Pay or Maternity Allowance is the route that actually applies. This page is built around that decision rather than treating everything as one benefit.", "The calculator therefore compares totals side by side and explains why one route may be stronger even when the other is not available."]},
            {"heading": "Why a comparison page works better than a single figure", "paragraphs": ["If you are employed with one employer for long enough, SMP is usually the first route to test. If not, Maternity Allowance often becomes the important fallback. A comparison page lets users see both without making legalistic assumptions they may not be ready to verify yet.", "That structure also makes the page stronger from an SEO perspective because it serves both direct calculator intent and the very common 'SMP vs Maternity Allowance' comparison query."]},
            {"heading": "Use this alongside SSP and Universal Credit pages", "paragraphs": ["For some households maternity support is not the only moving part. Childcare support, rent help and other means-tested support may change once work patterns and income shift. That makes the maternity page a natural hub into Universal Credit and childcare pages.", "The site keeps those links dense on purpose so the whole cluster behaves like a serious family-support resource."]},
        ],
        ["maternity-allowance-calculator", "statutory-maternity-pay-calculator", "smp-vs-ma"],
        ["tax-free-childcare-calculator", "universal-credit-calculator", "sure-start-maternity-grant-checker"],
    ),
    "esa-calculator": calc_page(
        "esa-calculator",
        "ESA guide and estimator",
        "Estimate New Style ESA using likely group, private pension income and contribution history.",
        "Check whether New Style ESA could be relevant and what the weekly amount may look like.",
        "esa",
        [
            {"name": "group", "label": "Likely ESA group", "type": "select", "default": "work_related", "options": [{"value": "work_related", "label": "Work-related activity"}, {"value": "support", "label": "Support group"}]},
            {"name": "private_pension_weekly", "label": "Weekly private pension income", "type": "number", "default": 0, "step": 1, "min": 0, "prefix": "£"},
            {"name": "has_recent_ni_record", "label": "Recent NI record likely strong enough", "type": "boolean", "default": True},
        ],
        [{"q": "What are the current ESA weekly amounts used here?", "a": "This estimator uses up to £95.55 a week for the work-related activity group and up to £145.90 for the support group in 2026/27."}, {"q": "Does private pension income affect ESA?", "a": "Yes. If private pension income is over £85 a week, half of the amount above £85 is usually deducted from New Style ESA."}, {"q": "Can you get ESA and Universal Credit together?", "a": "Sometimes, but Universal Credit is usually reduced by the ESA amount."}, {"q": "How do I calculate ESA back pay?", "a": "ESA back pay arises when a claim is awarded from a date in the past — for example after a successful appeal or a delayed work capability assessment. To estimate ESA back pay, multiply the weekly rate by the number of weeks the award is backdated. Use the work-related activity rate (up to £95.55/week) or support group rate (up to £145.90/week) as applicable, then deduct any weeks already paid at a lower rate or weeks where private pension income above £85/week would have reduced the award."}, {"q": "How far back can an ESA claim be backdated?", "a": "New Style ESA can normally be backdated by up to 3 months if you were unable to claim earlier due to your health condition. If an award results from a successful appeal, back pay covers the period from the original decision date."}],
        [
            {"heading": "ESA is now mostly a New Style decision", "paragraphs": ["Most searchers still type ESA calculator, but what they usually need is a New Style ESA guide with a realistic amount estimate and a clear warning that NI record matters. This page is written around that modern search intent rather than old income-related ESA assumptions.", "That matters for usefulness. A page that simply recites old ESA terms without explaining the current route is not genuinely helpful."]},
            {"heading": "Where the simple estimate is strongest", "paragraphs": ["The estimator is most useful for people trying to sense-check whether the support group or work-related activity rate is the main range to think about, and whether a private pension will reduce the final payment. Those are two of the most practical questions before a claim or appeal conversation.", "It is deliberately not trying to predict the work capability assessment outcome. That would be false precision."]},
            {"heading": "How ESA fits into the wider benefits cluster", "paragraphs": ["ESA sits close to SSP, Universal Credit and PIP in real user journeys. People often move across those pages as their health condition, work status and contribution history become clearer. That is why the site links them tightly together.", "It also strengthens the site's topical authority because the disability-and-work support topic is covered through calculators and explanatory guides rather than just one article."]},
        ],
        ["employment-support-allowance-calculator", "new-style-esa-calculator"],
        ["ssp-calculator", "pip-eligibility-checker", "universal-credit-calculator"],
    ),
    "jsa-calculator": calc_page(
        "jsa-calculator",
        "Contribution-based JSA calculator (New Style)",
        "Estimate contribution-based New Style Jobseeker’s Allowance using age, hours worked and recent National Insurance contribution history.",
        "Check whether contribution-based New Style JSA may apply and what the weekly amount could be.",
        "jsa",
        [
            {"name": "age_band", "label": "Age band", "type": "select", "default": "25_plus", "options": [{"value": "under_25", "label": "18 to 24"}, {"value": "25_plus", "label": "25 or over"}]},
            {"name": "hours_worked", "label": "Hours worked each week", "type": "number", "default": 0, "step": 1, "min": 0},
            {"name": "has_recent_ni_record", "label": "Recent NI record likely strong enough", "type": "boolean", "default": True},
        ],
        [{"q": "How much contribution-based JSA does this estimator use?", "a": "It uses up to £75.65 a week for ages 18 to 24 and up to £95.55 a week for age 25 or over — the 2026/27 New Style (contribution-based) JSA rates."}, {"q": "What is the difference between contribution-based JSA and income-based JSA?", "a": "New Style (contribution-based) JSA is based on your National Insurance record and is available for up to 182 days. Income-based JSA is no longer open to new claims — Universal Credit replaces it."}, {"q": "Can you get JSA if you work 16 hours or more a week?", "a": "Usually no, which is why this page sets the estimate to zero once hours reach 16 or more."}, {"q": "Does contribution-based JSA depend on savings?", "a": "No. New Style (contribution-based) JSA is not means tested and is not affected by your savings or partner's income. Only your NI record and hours worked matter."}],
        [
            {"heading": "A modern JSA page for current search intent", "paragraphs": ["Many search results for JSA are still mixed with old legacy information. This page is aimed at the live reality: New Style JSA, contribution conditions, and the interaction with low-hours work. That makes it more useful for someone trying to decide what to claim now.", "The output is intentionally modest because a lot of the real value is in showing whether JSA is even the right route to investigate."]},
            {"heading": "Why hours and NI record matter most", "paragraphs": ["The two questions that knock out many would-be JSA claims are whether recent Class 1 contributions are strong enough and whether work exceeds the low-hours limit. Those are handled directly in the page rather than buried in long eligibility text.", "That keeps the experience practical while still leaving room for explanatory content underneath the tool."]},
            {"heading": "When Universal Credit is likely to be the more important page", "paragraphs": ["If your NI record is weak, your savings are low and you need broader support with rent or children, Universal Credit is often the more relevant next page. The architecture of this site assumes that users move across those clusters rather than staying inside one benefit only.", "That cross-linking is deliberate: it improves usefulness and preserves the internal-topic-cluster strengths of the original site."]},
        ],
        ["jobseekers-allowance-calculator", "new-style-jsa-calculator"],
        ["universal-credit-calculator", "esa-calculator", "free-school-meals-checker"],
    ),
    "working-tax-credit-calculator": calc_page(
        "working-tax-credit-calculator",
        "Working Tax Credit legacy calculator",
        "Reference calculator for legacy Working Tax Credit using the last published 2024 to 2025 rates and thresholds.",
        "Use a legacy Working Tax Credit estimate for historic or transitional cases only.",
        "working_tax_credit",
        [
            {"name": "annual_income", "label": "Annual household income", "type": "number", "default": 18000, "step": 100, "min": 0, "prefix": "£"},
            {"name": "hours_worked", "label": "Hours worked each week", "type": "number", "default": 30, "step": 1, "min": 0},
            {"name": "household", "label": "Household type", "type": "select", "default": "couple", "options": [{"value": "single", "label": "Single without children"}, {"value": "lone_parent", "label": "Lone parent"}, {"value": "couple", "label": "Couple"}]},
            {"name": "disabled_worker", "label": "Disabled worker element likely", "type": "boolean", "default": False},
        ],
        [{"q": "Is Working Tax Credit still open to new claims?", "a": "No. Working Tax Credit ended on 5 April 2025, so this page is for legacy or historic reference use only."}, {"q": "Why keep a Working Tax Credit page on this site?", "a": "Because people still search for it during migration, transitional protection or historic award checks."}, {"q": "Which rates are used?", "a": "The final published 2024 to 2025 maximum rates and threshold structure."}],
        [
            {"heading": "A legacy page that still answers live search demand", "paragraphs": ["Working Tax Credit has ended for new claims, but search demand has not disappeared. People still need to understand historic awards, migration notices and how older entitlement compared with Universal Credit. This page is built for that reality rather than pretending the topic no longer exists.", "That makes the page useful commercially and editorially: it serves genuine user intent while strengthening the site's broader low-income family cluster."]},
            {"heading": "Why the calculator uses the last published rates", "paragraphs": ["The page uses the final published 2024 to 2025 rates and thresholds because those are the last meaningful reference point for Working Tax Credit. It is labelled clearly as a legacy estimate so there is no ambiguity about whether it can be used for a new claim.", "That clear labelling matters for trust. Users should never be left thinking they can still open a fresh Working Tax Credit claim in 2026."]},
            {"heading": "Where to go next", "paragraphs": ["If the historic award matters because you are moving to Universal Credit or checking what support now replaces it, the key next pages are Universal Credit, Tax-Free Childcare and Child Benefit. Those links are part of the page by design.", "The site is intended to behave like a support ecosystem, not just a stack of disconnected calculators."]},
        ],
        ["working-tax-credit-estimator", "legacy-working-tax-credit"],
        ["universal-credit-calculator", "child-tax-credit-calculator", "tax-free-childcare-calculator"],
    ),
    "child-tax-credit-calculator": calc_page(
        "child-tax-credit-calculator",
        "Child Tax Credit legacy calculator",
        "Reference calculator for legacy Child Tax Credit using the last published 2024 to 2025 rates and thresholds.",
        "Use a legacy Child Tax Credit estimate for historic, dispute or migration-reference purposes.",
        "child_tax_credit",
        [
            {"name": "annual_income", "label": "Annual household income", "type": "number", "default": 15000, "step": 100, "min": 0, "prefix": "£"},
            COMMON_CHILDREN_FIELD,
            {"name": "ctc_only", "label": "Child Tax Credit only case", "type": "boolean", "default": True},
        ],
        [{"q": "Can you make a new Child Tax Credit claim?", "a": "No. Child Tax Credit ended for new claims on 5 April 2025."}, {"q": "Why does this page still exist?", "a": "Because people still need legacy-reference figures for migrations, historic awards and family support comparisons."}, {"q": "Are disability additions included?", "a": "Not fully. This is a simplified legacy estimator focused on the family and child elements."}],
        [
            {"heading": "Why a Child Tax Credit reference page still matters", "paragraphs": ["Child Tax Credit is another legacy benefit that continues to attract live search intent because families are comparing old support with new support, checking managed migration outcomes or trying to understand past awards. A good benefits site should answer that intent cleanly rather than ignoring it.", "This page therefore keeps the calculation transparent and the warning language explicit: legacy reference only, not a new-claim tool."]},
            {"heading": "How the estimate is framed", "paragraphs": ["The estimator uses the final family and child element framework and applies the published withdrawal structure. That gives a useful directional answer without trying to replicate every corner case in a system that has already closed to new claims.", "It is best used for comparison and understanding rather than final entitlement work."]},
            {"heading": "Why this page strengthens the family support cluster", "paragraphs": ["Legacy tax-credit pages sit naturally beside Universal Credit, Child Benefit, Free School Meals and childcare support content. Together they answer the broader search question of what support exists for low-income families and how the system changed.", "That cluster value is important for topical authority and for preserving the scale potential of the original site architecture."]},
        ],
        ["child-tax-credit-estimator", "legacy-child-tax-credit"],
        ["universal-credit-calculator", "child-benefit-calculator", "free-school-meals-checker"],
    ),
    "tax-free-childcare-calculator": calc_page(
        "tax-free-childcare-calculator",
        "Tax-Free Childcare calculator",
        "Estimate how much government top-up you could get through Tax-Free Childcare based on annual childcare spending.",
        "Estimate the annual Tax-Free Childcare top-up and compare it with other childcare support routes.",
        "tax_free_childcare",
        [
            COMMON_CHILDREN_FIELD,
            {"name": "annual_childcare_cost", "label": "Annual childcare cost", "type": "number", "default": 6000, "step": 100, "min": 0, "prefix": "£"},
            {"name": "disabled_child", "label": "A child qualifies for the disabled-child limit", "type": "boolean", "default": False},
        ],
        [{"q": "How does Tax-Free Childcare work?", "a": "For every £8 you pay in, the government adds £2. That is effectively a 25% top-up on what you deposit."}, {"q": "What is the annual top-up cap?", "a": "Normally up to £2,000 a year per child, or up to £4,000 for a disabled child."}, {"q": "Can I use this with Universal Credit childcare support?", "a": "No. You cannot usually claim Tax-Free Childcare and Universal Credit childcare support at the same time."}],
        [
            {"heading": "A childcare support calculator built for comparison", "paragraphs": ["Tax-Free Childcare is simple enough to estimate accurately on headline amounts, but users rarely search it in isolation. They are usually comparing it against Universal Credit childcare help or trying to understand whether the top-up is worth the admin.", "That is why this page makes the top-up obvious and then directs people to the Universal Credit cluster rather than pretending one scheme is always better."]},
            {"heading": "Where this estimate is strongest", "paragraphs": ["The page is particularly useful for moderate and higher earners who want a fast sense check on how much the account could add over a year. It is also useful for families whose circumstances change during the year and want to see how different childcare spend levels affect the top-up.", "Because the cap is per child, the page keeps the child count visible and easy to change."]},
            {"heading": "Scheme choice matters more than the headline top-up", "paragraphs": ["A smaller-looking top-up can still be the better option if you are not eligible for Universal Credit, while a larger-looking annual figure can be the wrong route if it blocks stronger means-tested help. That is why scheme comparison is built into the content strategy here.", "This is a benefits site built for decisions, not just arithmetic."]},
        ],
        ["tax-free-childcare-estimator", "childcare-top-up-calculator"],
        ["universal-credit-calculator", "child-benefit-calculator", "free-school-meals-checker"],
    ),
    "sure-start-maternity-grant-checker": calc_page(
        "sure-start-maternity-grant-checker",
        "Sure Start Maternity Grant checker",
        "Check whether a household may qualify for the one-off £500 Sure Start Maternity Grant.",
        "Quickly check the main first-child and qualifying-benefit routes for Sure Start Maternity Grant.",
        "sure_start",
        [
            {"name": "qualifying_benefit", "label": "Receiving a qualifying benefit", "type": "boolean", "default": True},
            {"name": "first_child", "label": "This is your first child", "type": "boolean", "default": True},
            {"name": "multiple_birth_with_other_children", "label": "Multiple birth while already responsible for children", "type": "boolean", "default": False},
        ],
        [{"q": "How much is the Sure Start Maternity Grant?", "a": "It is a one-off payment of £500."}, {"q": "Is it usually only for a first child?", "a": "Usually yes, although there are some multiple-birth and special household exceptions."}, {"q": "When do you need to claim?", "a": "Normally from 11 weeks before the due date until 6 months after birth."}],
        [
            {"heading": "A focused grant checker rather than a broad maternity article", "paragraphs": ["Sure Start Maternity Grant search intent is narrow and practical. Most people just want to know whether the £500 grant could apply. This page is built around that narrow intent, with the wider explanation sitting underneath rather than getting in the way.", "That makes it a good fit for a scalable benefits site because not every page needs the same interface weight."]},
            {"heading": "Why this page still matters", "paragraphs": ["One-off grants are easy to miss because they are not always discussed alongside mainstream maternity pay. For lower-income households, though, the grant can be one of the more immediate and useful pieces of support around birth costs.", "That is why this checker is linked tightly with the maternity comparison and Healthy Start pages. They answer adjacent questions for the same life stage."]},
            {"heading": "Nation-specific warning", "paragraphs": ["The page also flags that Scotland uses different family payment routes. That distinction matters because a lot of UK-wide benefits content becomes less trustworthy the moment nation-specific differences are ignored.", "This site keeps those differences visible rather than burying them in fine print."]},
        ],
        ["sure-start-grant-checker", "maternity-grant-checker"],
        ["maternity-pay-comparison", "healthy-start-checker", "universal-credit-calculator"],
    ),
    "healthy-start-checker": calc_page(
        "healthy-start-checker",
        "Healthy Start checker",
        "Check whether pregnancy or having a child under 4 could make you eligible for Healthy Start support.",
        "Use a quick eligibility-style checker for Healthy Start food support and vitamins.",
        "healthy_start",
        [
            {"name": "pregnant_or_child_under_4", "label": "Pregnant or responsible for a child under 4", "type": "boolean", "default": True},
            {"name": "qualifying_benefit", "label": "Receiving a qualifying benefit", "type": "boolean", "default": True},
            {"name": "under_18_and_pregnant", "label": "Under 18 and pregnant", "type": "boolean", "default": False},
        ],
        [{"q": "What is Healthy Start for?", "a": "Healthy Start can help with food such as milk, fruit and infant formula, and it also includes free vitamins."}, {"q": "Who can qualify without benefits?", "a": "People who are under 18 and pregnant can qualify even if they do not receive benefits."}, {"q": "Does Scotland use Healthy Start?", "a": "No. Scotland uses Best Start Foods instead."}],
        [
            {"heading": "An eligibility checker built around the real decision points", "paragraphs": ["Healthy Start is best understood as a route check rather than a cash-benefit calculator. The key issues are whether the household includes a pregnancy or child under 4, and whether a qualifying benefit route exists.", "That is why this page is framed as a checker with a modest indicative value rather than a high-precision payment calculator."]},
            {"heading": "Why Healthy Start belongs in a serious benefits network", "paragraphs": ["This is exactly the kind of support page that rounds out a topical authority site. It may not be the biggest payment, but it answers a high-intent practical question and fits naturally beside maternity, low-income family and food-support searches.", "Those pages help the whole site look like a complete support resource, which is important for topical relevance."]},
            {"heading": "What the checker does not try to do", "paragraphs": ["The page does not try to replicate every immigration-status edge case or nation-specific alternative in a short form. Instead, it explains the main routes clearly and tells users where the scheme changes by nation.", "That keeps the page useful without creating false certainty."]},
        ],
        ["healthy-start-voucher-checker", "healthy-start-eligibility"],
        ["sure-start-maternity-grant-checker", "free-school-meals-checker", "universal-credit-calculator"],
    ),
    "free-school-meals-checker": calc_page(
        "free-school-meals-checker",
        "Free School Meals eligibility checker",
        "Check likely Free School Meals eligibility in England using Universal Credit income, other qualifying benefits and infant-year rules.",
        "Estimate whether Free School Meals look likely and the rough school-year value of that support.",
        "free_school_meals",
        [
            COMMON_CHILDREN_FIELD,
            {"name": "annual_take_home_income", "label": "Annual take-home income from work", "type": "number", "default": 6000, "step": 100, "min": 0, "prefix": "£"},
            {"name": "on_universal_credit", "label": "Receiving Universal Credit", "type": "boolean", "default": True},
            {"name": "other_qualifying_benefit", "label": "Receiving another qualifying benefit", "type": "boolean", "default": False},
            {"name": "infant_pupil", "label": "Child in reception, year 1 or year 2", "type": "boolean", "default": False},
        ],
        [{"q": "What Universal Credit earnings limit is used here?", "a": "For most England applications made on or after 1 April 2018, this page uses the £7,400 a year post-tax earnings test."}, {"q": "Do infant pupils need the means test?", "a": "No. Reception, year 1 and year 2 pupils in state-funded schools in England generally get universal infant free school meals."}, {"q": "Does this checker cover the whole UK?", "a": "No. It is mainly designed around England. Other nations use different rules."}],
        [
            {"heading": "Why Free School Meals searches are usually urgent", "paragraphs": ["Searchers often arrive here because they need a yes-or-no direction quickly rather than a long policy history. This page is built around that reality, showing the key Universal Credit threshold and alternative qualifying benefit routes near the top.", "The page still adds context underneath because users often need to understand why a school or council asked for evidence even when meals are available to younger pupils automatically."]},
            {"heading": "Why this page fits a broader low-income family cluster", "paragraphs": ["Free School Meals sit naturally beside Child Benefit, Universal Credit, Healthy Start and Council Tax Reduction. Families rarely think about these supports in isolation, so the internal linking reflects how the questions are actually searched.", "That dense interlinking is one of the SEO strengths preserved from the original site structure."]},
            {"heading": "Cash value shown as a planning aid", "paragraphs": ["The school-year value shown on this page is illustrative. It helps families understand the practical weight of the support, but it is not an official reimbursement figure or a guarantee of what any school meal would cost locally.", "That sort of directional value still improves usability because it turns an eligibility question into a budgeting question too."]},
        ],
        ["free-school-meals-estimator", "school-meals-eligibility-checker"],
        ["universal-credit-calculator", "healthy-start-checker", "child-benefit-calculator"],
    ),
    "winter-fuel-payment-checker": calc_page(
        "winter-fuel-payment-checker",
        "Winter Fuel Payment checker",
        "Check age, location and income assumptions against the current Winter Fuel Payment rules.",
        "Estimate whether a Winter Fuel Payment looks likely and what one-off amount may apply.",
        "winter_fuel",
        [
            {"name": "born_before_cutoff", "label": "Born on or before 27 June 1960", "type": "boolean", "default": True},
            {"name": "born_before_older_cutoff", "label": "Born before 28 September 1946", "type": "boolean", "default": False},
            {"name": "lives_in_england_or_wales", "label": "Lives in England or Wales", "type": "boolean", "default": True},
            {"name": "income_over_35000", "label": "Personal income over £35,000", "type": "boolean", "default": False},
        ],
        [{"q": "How much can Winter Fuel Payment be?", "a": "For winter 2026 to 2027, the published amount is generally £200 or £300 depending on age and circumstances."}, {"q": "What income threshold matters now?", "a": "This page flags the current £35,000 personal income clawback threshold."}, {"q": "Does this apply in Scotland?", "a": "No. Scotland uses Pension Age Winter Heating Payment instead."}],
        [
            {"heading": "Winter Fuel Payment changed meaningfully for higher-income households", "paragraphs": ["This page includes the current income clawback rule because it is one of the main reasons searchers now need an eligibility checker rather than just a static age table. Older Winter Fuel content can look current while still missing the income point entirely.", "That makes current-date accuracy especially important here."]},
            {"heading": "A simple one-off payment checker", "paragraphs": ["The page is intentionally simple because Winter Fuel Payment is mostly a one-off eligibility question. Users usually want to know whether they are in the age range, whether the nation is right and whether income means the payment will be taken back.", "That clarity also makes the page a strong supporting entry point into Pension Credit and other pension-age support content."]},
            {"heading": "Built as part of the pension-age support cluster", "paragraphs": ["Winter Fuel, Cold Weather Payments and Pension Credit belong together in search behaviour and in site structure. A serious UK benefits site should treat them as a cluster rather than three disconnected pages.", "This page therefore uses tight internal linking and matching content patterns so the pension-age support section can scale further later."]},
        ],
        ["winter-fuel-payment-estimator", "winter-heating-payment-checker"],
        ["pension-credit-calculator", "cold-weather-payment-checker", "council-tax-reduction-calculator"],
    ),
    "cold-weather-payment-checker": calc_page(
        "cold-weather-payment-checker",
        "Cold Weather Payment checker",
        "Estimate Cold Weather Payments using qualifying-benefit assumptions and the number of triggered cold spells in your area.",
        "Check whether Cold Weather Payments may apply and how much they could add up to in a cold winter.",
        "cold_weather",
        [
            {"name": "qualifying_benefit", "label": "On a qualifying benefit route", "type": "boolean", "default": True},
            {"name": "lives_outside_scotland", "label": "Lives outside Scotland", "type": "boolean", "default": True},
            {"name": "triggered_periods", "label": "7-day cold weather triggers", "type": "number", "default": 2, "step": 1, "min": 0},
        ],
        [{"q": "How much is each Cold Weather Payment?", "a": "£25 for each qualifying 7-day period of very cold weather."}, {"q": "Do you need to apply?", "a": "Usually no. The payment is automatic if you qualify and your weather station area triggers."}, {"q": "Does Scotland use Cold Weather Payments?", "a": "No. Scotland uses Winter Heating Payment instead."}],
        [
            {"heading": "A weather-linked support checker", "paragraphs": ["Cold Weather Payments are unusual because entitlement depends on both benefit status and local weather triggers. This page turns that into a simple seasonal estimate by combining the qualifying-benefit question with the number of triggered periods you expect or have seen.", "That makes it useful in winter traffic spikes and as a supporting page inside the pension-age and low-income heating cluster."]},
            {"heading": "Why this page works best as a seasonal estimator", "paragraphs": ["The exact answer depends on weather station data and payment automation, so a public-facing page should not pretend to know your postcode trigger history unless it really does. This site keeps the logic honest by letting users enter the number of triggered periods instead.", "That approach is simple, transparent and still useful."]},
            {"heading": "Where this fits in the site structure", "paragraphs": ["Cold Weather Payment is a strong supporting keyword because it connects naturally with Winter Fuel Payment, Pension Credit and broader low-income support queries. It broadens topical coverage without forcing every page to be a complex means-tested calculator.", "That type of page is important for scaling the site into a wider UK benefits authority."]},
        ],
        ["cold-weather-payment-estimator", "cold-weather-checker"],
        ["winter-fuel-payment-checker", "pension-credit-calculator", "healthy-start-checker"],
    ),
    "savings-impact-calculator": calc_page(
        "savings-impact-calculator",
        "Savings and Universal Credit calculator",
        "See how savings between £6,000 and £16,000 reduce your Universal Credit through the tariff income rule of £4.35 a month per £250 above the lower limit.",
        "Work out the monthly UC deduction generated by savings above the £6,000 threshold and when the £16,000 capital limit stops entitlement.",
        "savings_impact",
        [
            {"name": "savings", "label": "Total savings and investments", "type": "number", "default": 8000, "step": 250, "min": 0, "prefix": "£"},
            {"name": "household", "label": "Household type", "type": "select", "default": "single", "options": [{"value": "single", "label": "Single"}, {"value": "couple", "label": "Couple"}]},
            {"name": "children", "label": "Number of children", "type": "number", "default": 0, "step": 1, "min": 0},
        ],
        [
            {"q": "How do savings reduce Universal Credit?", "a": "For every complete £250 above £6,000, DWP adds £4.35 to your assumed monthly income. That assumed income reduces your UC award by the same amount."},
            {"q": "At what savings level does UC stop entirely?", "a": "For most claimants, UC is not payable when savings reach £16,000 or more."},
            {"q": "Are savings below £6,000 counted?", "a": "No. Savings up to £6,000 are fully disregarded and have no effect on UC."},
        ],
        [
            {"heading": "The £6,000 and £16,000 savings thresholds", "paragraphs": ["Universal Credit uses two capital thresholds. Below £6,000, savings are completely ignored. Between £6,000 and £16,000, the system applies a tariff income rule. For every complete £250 above £6,000, DWP adds £4.35 a month to assumed income — which reduces the UC award by the same amount.", "At £16,000 or more, eligibility for a standard UC award stops entirely. This is stricter than Pension Credit, which has more lenient savings rules and no hard upper cut-off for pension-age claimants."]},
            {"heading": "What counts as savings for UC purposes", "paragraphs": ["Savings, investments, Premium Bonds, shares and most cash accounts count. Your main home does not count. Some compensation payments can be disregarded, and money specifically set aside for care needs may also be treated differently.", "Couples are assessed jointly. If one partner has £3,000 and the other has £5,000, the combined £8,000 falls into the tapered range."]},
            {"heading": "Spending savings to qualify — what to know", "paragraphs": ["DWP can treat you as still holding money you have deliberately spent or given away to qualify for UC. This is called deprivation of capital. Normal spending on living costs is unlikely to trigger this, but large transfers to family members shortly before a claim can be questioned.", "If you are near either threshold, keeping a clear record of your savings position when you claim matters."]},
        ],
        ["savings-and-universal-credit", "how-savings-affect-uc"],
        ["universal-credit-calculator", "earnings-impact-calculator", "benefit-cap-calculator"],
    ),
    "earnings-impact-calculator": calc_page(
        "earnings-impact-calculator",
        "Earnings and Universal Credit calculator",
        "See how working more hours affects your Universal Credit award — work allowance, 55% taper and net change per £100 earned.",
        "Understand how earnings reduce Universal Credit through the work allowance and 55% earnings taper.",
        "earnings_impact",
        [
            {"name": "earnings", "label": "Monthly take-home earnings", "type": "number", "default": 1000, "step": 25, "min": 0, "prefix": "£"},
            {"name": "household", "label": "Household type", "type": "select", "default": "single", "options": [{"value": "single", "label": "Single"}, {"value": "couple", "label": "Couple"}]},
            {"name": "children", "label": "Number of children", "type": "number", "default": 0, "step": 1, "min": 0},
            {"name": "housing_cost", "label": "Monthly eligible rent", "type": "number", "default": 600, "step": 25, "min": 0, "prefix": "£"},
        ],
        [
            {"q": "What is the UC earnings taper?", "a": "55%. For every £1 of net earnings above your work allowance, UC is reduced by 55p — meaning you keep 45p."},
            {"q": "Who gets a work allowance?", "a": "Only households with a child element or a limited capability for work element. Households without children or a qualifying health condition have no work allowance."},
            {"q": "How does the work allowance differ?", "a": "It is £404 a month if housing costs are included in your UC award, or £673 a month if they are not."},
        ],
        [
            {"heading": "How the 55% taper works in practice", "paragraphs": ["The earnings taper is one of the most important things to understand about Universal Credit. For every £1 of net earnings above your work allowance, UC is reduced by 55p. That means you keep 45p of each additional pound you earn — a real financial gain, though lower than many people expect.", "A household without a work allowance faces the taper from the first pound of earnings. That makes the taper especially sharp for couples without children or health conditions."]},
            {"heading": "The work allowance changes the picture significantly", "paragraphs": ["If your household includes children or a limited capability for work element, you receive a work allowance — a band of earnings that are fully disregarded before the taper kicks in. In 2026/27 that is £673 a month where no housing costs element is in payment, or £404 a month where housing support is included.", "Up to the allowance, every pound you earn is kept in full. Above it, you keep 45p per pound. That means there is a strong incentive to work at least enough to use the work allowance each month."]},
            {"heading": "Understanding the net change per £100 earned", "paragraphs": ["A useful way to think about the taper is in terms of what happens to a hypothetical extra £100 of earnings. If you are already above the work allowance, earning £100 more reduces UC by £55 — leaving you £45 better off overall.", "If your earnings are below the work allowance, some or all of the £100 extra may be in the disregarded band, meaning you could keep more than £45. This calculator shows both the current deduction and the net effect of an extra £100."]},
        ],
        ["earnings-and-universal-credit", "uc-taper-rate-calculator"],
        ["universal-credit-calculator", "savings-impact-calculator", "benefit-cap-calculator"],
    ),
    "maternity-pay-calculator": calc_page(
        "maternity-pay-calculator",
        "Statutory Maternity Pay calculator",
        "Estimate SMP for the first 39 weeks — 90% of weekly pay for 6 weeks, then the flat rate for up to 33 weeks.",
        "Calculate estimated Statutory Maternity Pay across the higher-rate and lower-rate periods.",
        "maternity_pay",
        [
            {"name": "weekly_pay", "label": "Average weekly pay", "type": "number", "default": 550, "step": 10, "min": 0, "prefix": "£"},
            {"name": "weeks_higher", "label": "Weeks at 90% rate (max 6)", "type": "number", "default": 6, "step": 1, "min": 0},
            {"name": "weeks_lower", "label": "Weeks at flat rate (max 33)", "type": "number", "default": 33, "step": 1, "min": 0},
        ],
        [
            {"q": "How long is SMP paid for?", "a": "Up to 39 weeks — 6 weeks at 90% of average weekly earnings, then up to 33 weeks at the flat statutory rate (£184.03 in 2026/27)."},
            {"q": "What is the flat SMP rate for 2026/27?", "a": "£184.03 a week for weeks 7 to 39, or 90% of average weekly earnings if that is lower."},
            {"q": "How do I qualify for SMP?", "a": "You normally need to have worked for the same employer for at least 26 weeks into the qualifying week and be earning above the lower earnings limit."},
        ],
        [
            {"heading": "SMP over 39 weeks — two distinct phases", "paragraphs": ["Statutory Maternity Pay works in two phases. The first 6 weeks are paid at 90% of your average weekly earnings with no flat-rate cap. This is often the highest-value period and where SMP is most clearly linked to what you were earning before maternity leave.", "Weeks 7 to 39 are paid at the statutory flat rate — £184.03 a week in 2026/27 — or 90% of your average weekly earnings if that is lower. For most employees earning above around £205 a week, the flat rate applies from week 7 onwards."]},
            {"heading": "How SMP compares to Maternity Allowance", "paragraphs": ["SMP is generally the better route for employees who have been with the same employer long enough, because the 90% first-6-weeks phase has no flat cap. Maternity Allowance, which is available to those who do not qualify for SMP, uses a different eligibility test and a different rate structure.", "If you are self-employed or have recently changed jobs, the maternity comparison page is the place to check both routes side by side."]},
            {"heading": "Other support that can run alongside SMP", "paragraphs": ["SMP is taxable and counts as income, which can affect means-tested support. Universal Credit can still be claimed alongside SMP, but the SMP is counted as income and will reduce the UC award through the earnings taper.", "Sure Start Maternity Grant and Healthy Start support can also be relevant around the time of birth and early months. Those sit outside the main SMP calculation but are worth checking if income is under pressure."]},
        ],
        ["statutory-maternity-pay-calculator", "smp-calculator", "maternity-pay-estimator"],
        ["maternity-pay-comparison", "sure-start-maternity-grant-checker", "universal-credit-calculator"],
    ),
    "tax-free-childcare-monthly-calculator": calc_page(
        "tax-free-childcare-monthly-calculator",
        "Tax-Free Childcare monthly calculator",
        "Estimate the monthly government top-up on childcare costs — 20p for every 80p spent, up to £2,000 per child per year.",
        "Calculate your monthly Tax-Free Childcare top-up from monthly childcare spend.",
        "tax_free_childcare_monthly",
        [
            {"name": "monthly_childcare", "label": "Monthly childcare cost", "type": "number", "default": 800, "step": 25, "min": 0, "prefix": "£"},
            {"name": "children", "label": "Number of children", "type": "number", "default": 1, "step": 1, "min": 1},
        ],
        [
            {"q": "How much does the government top up?", "a": "20p for every 80p you pay in — effectively a 25% top-up on what you deposit, or 20% of the final childcare cost."},
            {"q": "Is there an annual cap per child?", "a": "Yes. The maximum government top-up is £2,000 per child per year (£500 per quarter). For disabled children the limit is £4,000 per year."},
            {"q": "Can I use this with Universal Credit childcare support?", "a": "No. You must choose one or the other. For households on UC with high childcare bills, UC childcare support is often more valuable."},
        ],
        [
            {"heading": "How the monthly top-up is calculated", "paragraphs": ["Tax-Free Childcare works by matching your deposits at a ratio of 20p for every 80p you put in. If you spend £800 a month on childcare, you deposit £800 and the government adds £200. The cap is £500 per child per quarter, which works out at roughly £167 per child per month.", "For two children, the combined monthly cap is around £333. For three, around £500. Once you hit the cap, additional spending above that level does not attract further top-up."]},
            {"heading": "Comparing the monthly route against the UC childcare element", "paragraphs": ["Tax-Free Childcare gives a flat 20% top-up capped by family size. Universal Credit childcare support reimburses up to 85% of eligible costs, but is reduced as earnings rise and is only available to UC claimants. For low-income families already on UC with large childcare bills, UC childcare support is usually worth significantly more.", "For moderate to higher earners who are not on UC, or families whose income is above the UC taper-out point, Tax-Free Childcare is the main option. The comparison calculator on the full Tax-Free Childcare page shows the trade-off side by side."]},
            {"heading": "Applying and maintaining your account", "paragraphs": ["Applications are through the Government Gateway. Both partners in a couple must be working and earning at least the equivalent of 16 hours at the National Minimum Wage to qualify. Eligibility is reconfirmed every 3 months — missing the reconfirmation window pauses the top-up.", "Free childcare hours (15 or 30 hours depending on age and entitlement) can be combined with Tax-Free Childcare. The free hours are applied to the nursery invoice first; TFC top-up then applies to the remaining privately paid portion."]},
        ],
        ["tfc-monthly-calculator", "tax-free-childcare-estimator"],
        ["tax-free-childcare-calculator", "universal-credit-calculator", "child-benefit-calculator"],
    ),
    "attendance-allowance-calculator": calc_page(
        "attendance-allowance-calculator",
        "Attendance Allowance calculator 2026/27",
        "Check the weekly and annual Attendance Allowance amount for lower and higher rate in 2026/27. Non-means-tested and available over State Pension age.",
        "Check the Attendance Allowance rate that applies — lower or higher — and what it may unlock in additional support.",
        "attendance_allowance",
        [
            {"name": "rate", "label": "Care needs", "type": "select", "default": "lower", "options": [{"value": "lower", "label": "Day or night care needs (lower rate — £73.90/week)"}, {"value": "higher", "label": "Day and night care needs, or terminally ill (higher rate — £110.40/week)"}]},
        ],
        [
            {"q": "What is the Attendance Allowance rate for 2026/27?", "a": "Lower rate: £73.90 a week. Higher rate: £110.40 a week. Both rates are non-means-tested."},
            {"q": "Who can claim Attendance Allowance?", "a": "People over State Pension age who need help with personal care because of a physical or mental disability. Age under State Pension age: PIP applies instead."},
            {"q": "Does income or savings affect Attendance Allowance?", "a": "No. Attendance Allowance is not means tested. Income, savings and whether you live with a partner have no effect on entitlement."},
            {"q": "Can Attendance Allowance increase other benefits?", "a": "Yes. Receiving Attendance Allowance can passport you to a higher Pension Credit award (the severe disability addition), higher Council Tax Reduction and higher Housing Benefit."},
            {"q": "What is the difference between Attendance Allowance lower and higher rate?", "a": "Lower rate (£73.90/week) is for people who need frequent attention or supervision during the day or night. Higher rate (£110.40/week) is for people who need attention or supervision both day and night, or who are terminally ill."},
        ],
        [
            {"heading": "Attendance Allowance is for pension-age adults — PIP is for working age", "paragraphs": ["Attendance Allowance and PIP are separate non-means-tested disability benefits for different age groups. Attendance Allowance is for people who have reached State Pension age. PIP is for people aged 16 to State Pension age. You cannot receive both at the same time.", "If you were already receiving PIP when you reached State Pension age, your PIP award continues. New claims after State Pension age must be made as Attendance Allowance."]},
            {"heading": "Why claiming Attendance Allowance is often worth doing even when other income is decent", "paragraphs": ["A common reason for not claiming is the assumption that income or savings will disqualify you. That is wrong — Attendance Allowance is non-means-tested. The only eligibility tests are age, residency and the care needs threshold.", "Even if the weekly payment itself is modest relative to other income, the bigger impact can be in what it unlocks: the Severe Disability Addition to Pension Credit adds £81.50 a week on top of Pension Credit if you receive Attendance Allowance and no one claims Carer's Allowance for looking after you. That alone can be worth more than the Attendance Allowance itself."]},
            {"heading": "Lower rate and higher rate — what the care conditions actually mean", "paragraphs": ["The lower rate is for people who need frequent attention throughout the day in connection with bodily functions, or continual supervision throughout the day to avoid danger, or repeated or prolonged attention during the night. The higher rate requires both day and night care needs, or being terminally ill.", "DWP considers reliability and frequency. Needing help with washing, dressing, eating, medication or getting around the home on most days is the relevant test — not occasional help or general supervision."]},
        ],
        ["attendance-allowance-checker", "aa-calculator"],
        ["pension-credit-calculator", "council-tax-reduction-calculator", "pip-eligibility-checker"],
    ),
    "carers-allowance-calculator": calc_page(
        "carers-allowance-calculator",
        "Carer's Allowance calculator 2026/27",
        "Check whether Carer's Allowance may apply and estimate the weekly amount. Uses the 2026/27 rate of £81.90/week, 35-hour care rule and £151/week earnings limit.",
        "Check whether Carer's Allowance may be in range based on your caring hours, earnings and the disability benefit the person you care for receives.",
        "carers_allowance",
        [
            {"name": "hours_caring", "label": "Hours caring per week", "type": "number", "default": 35, "step": 1, "min": 0},
            {"name": "weekly_earnings", "label": "Your weekly earnings (net, after tax and NI)", "type": "number", "default": 0, "step": 1, "min": 0, "prefix": "£"},
            {"name": "has_qualifying_benefit", "label": "The person I care for receives PIP, DLA, Attendance Allowance or similar", "type": "boolean", "default": True},
        ],
        [
            {"q": "How much is Carer's Allowance in 2026/27?", "a": "£81.90 a week, which is £4,258.80 a year. It is taxable income."},
            {"q": "How many hours do you need to care to claim?", "a": "At least 35 hours a week providing care for someone who receives a qualifying disability benefit."},
            {"q": "What is the earnings limit for Carer's Allowance?", "a": "£151 per week net of tax, National Insurance and 50% of pension contributions in 2026/27. Earnings above this disqualify you."},
            {"q": "Does Carer's Allowance affect Universal Credit?", "a": "Yes. Carer's Allowance counts as income for UC. UC is normally reduced pound-for-pound, but you receive a carer element addition of £198.31/month which often more than offsets the reduction."},
            {"q": "What if I get the State Pension — can I still get Carer's Allowance?", "a": "State Pension and Carer's Allowance cannot usually both be paid at full rate — the higher of the two is paid. But you may still have 'underlying entitlement', which can trigger a carer element addition in Universal Credit."},
        ],
        [
            {"heading": "The earnings limit — what counts and what does not", "paragraphs": ["The £151/week earnings limit for 2026/27 applies to net earnings after deducting income tax, National Insurance contributions, and 50% of any pension contributions you make. If you work part-time and stay below that net figure, earnings do not prevent a claim.", "Earnings from self-employment use the same threshold but can be complex — allowable business expenses are deducted before comparing against the limit."]},
            {"heading": "How Carer's Allowance interacts with Universal Credit", "paragraphs": ["Carer's Allowance is counted as income in UC and reduces your UC award pound-for-pound. However, claiming Carer's Allowance also triggers a carer element addition in Universal Credit of £198.31 a month. For most UC claimants, the net effect of claiming Carer's Allowance is positive.", "If you receive a higher 'overlapping benefit' such as the State Pension or Contributory ESA that is already equal to or greater than Carer's Allowance, actual payment is blocked. But you still have 'underlying entitlement', which is enough to trigger the UC carer element."]},
            {"heading": "Why Carer's Allowance is one of the most under-claimed benefits", "paragraphs": ["Two common misconceptions stop people claiming: that earnings will definitely disqualify them (only earnings over £151/week net do), and that getting State Pension means they can no longer claim anything related (underlying entitlement still applies). Around 400,000 eligible carers are estimated to be missing Carer's Allowance each year.", "The carer element in Universal Credit is also frequently missed because people do not realise that even without actual Carer's Allowance payment, underlying entitlement triggers the addition."]},
        ],
        ["carers-allowance-estimator", "carer-allowance-calculator"],
        ["universal-credit-calculator", "pip-eligibility-checker", "pension-credit-calculator"],
    ),
}

GUIDES: Dict[str, Dict[str, Any]] = {
    "what-benefits-can-i-claim": {
        "title": "What benefits can I claim?",
        "description": "A practical UK guide to the main benefits and support routes for low income, disability, children, rent and pension-age households.",
        "topic": "Benefits basics",
        "sections": [
            {"heading": "Start with your household, not with one benefit name", "paragraphs": ["The quickest way to get lost in the UK benefits system is to search for one payment in isolation. Most households are not really asking whether one specific benefit exists. They are trying to work out which mix of support might apply to their income, rent, children, health and age.", "That is why the better starting question is usually: what type of household am I, and which support routes normally fit households like mine. Working-age low-income households often begin with Universal Credit. Pension-age households often need to look at Pension Credit, council tax help and winter support. Families with children may also need Child Benefit, childcare help and school-related support."]},
            {"heading": "The main support groups most people need to check", "paragraphs": ["If your income is low, Universal Credit is often the first route to check because it can cover day-to-day living costs and sometimes rent. If you are over State Pension age, Pension Credit may be more relevant. If you have a long-term health condition or disability, PIP, ESA and sometimes Universal Credit health elements become more important.", "Families should usually check Child Benefit separately because it is not the same thing as means-tested support. Childcare help, Free School Meals, Healthy Start and Sure Start Maternity Grant also sit in their own part of the system and are easy to miss if you focus only on one monthly payment."]},
            {"heading": "You can often get more than one kind of support", "paragraphs": ["A common mistake is assuming support comes as one single award. In reality, a household might receive Universal Credit, Child Benefit and Council Tax Reduction at the same time. A pensioner might get Pension Credit and then unlock help with heating or council tax on top of it.", "That overlap is why this site is built as a network of connected pages rather than one giant calculator with a false sense of precision. The right answer is often a combination of support routes rather than one headline number."]},
            {"heading": "Work does not automatically rule support out", "paragraphs": ["Many people still assume benefits stop the moment you start work. That is not how the system works. Plenty of working households qualify for support, especially through Universal Credit, Council Tax Reduction, Child Benefit and childcare schemes.", "In practical terms, the better question is not 'do I work', but 'how much do I earn, what other costs do I have, and which support rules still apply once those details are taken into account'."]},
            {"heading": "Use independent estimators the right way", "paragraphs": ["Independent calculators are most useful at the planning stage. They help you see whether a claim looks worth exploring, which figures matter most, and which other pages you should check next. They are less useful if you expect them to reproduce every official rule exactly.", "That is the standard this site aims for: useful enough to guide your next step, but clear where an estimate is simplified and where only an official service or specialist adviser can give a final answer."]},
        ],
        "related": ["universal-credit-calculator", "pension-credit-calculator", "pip-eligibility-checker", "council-tax-reduction-calculator"],
        "faq": [
            {"q": "What is usually the main benefit for working-age low-income households?", "a": "Universal Credit is often the main route, especially if you also need help with rent or children."},
            {"q": "Can you get more than one type of support?", "a": "Yes. Many households receive a mix of support, such as Universal Credit, Child Benefit and Council Tax Reduction."},
            {"q": "What if I am not sure where to start?", "a": "Start with your biggest pressure point. If it is rent and bills, check Universal Credit and council tax help. If it is children, check Child Benefit and childcare support. If it is health, look at PIP and ESA-related pages."},
        ],
        "related_guides": ["universal-credit-explained", "benefits-for-low-income-families", "help-with-rent-and-council-tax", "pension-credit-explained", "pip-explained-simply"],
    },
    "universal-credit-explained": {
        "title": "Universal Credit explained 2026/27 — rates, capital limits and working-family rules",
        "description": "Plain-English guide to Universal Credit 2026/27 — rates, work allowance, £6,000 and £16,000 capital limits, tariff income and what working families should check next.",
        "topic": "Universal Credit",
        "sections": [
            {"heading": "Universal Credit is one payment built from several elements", "paragraphs": [
                "Universal Credit replaced six legacy benefits — income-based JSA, income-related ESA, Income Support, Housing Benefit, Working Tax Credit and Child Tax Credit — and brought them into a single monthly payment. Understanding it means understanding how those parts combine rather than treating it as one flat amount.",
                "The award starts with a standard allowance, which is set by age and household type. For a single person aged 25 or over, the standard allowance in 2026/27 is £424.90 a month. For a couple where both are 25 or over, it is £666.97 a month. These are the floor amounts before any additions or deductions.",
                "On top of the standard allowance, the system may add a child element for each dependent child, a housing costs element to help with rent, a childcare costs element for registered childcare, a limited capability for work or work-related activity element if a health condition is relevant, and a carer element if you care for a severely disabled person.",
            ]},
            {"heading": "How earnings affect the award — the taper and work allowance", "paragraphs": [
                "Most working-age claimants face a 55% earnings taper. For every £1 of net earnings above your work allowance, Universal Credit is reduced by 55p. That means you keep 45p in every additional pound you earn, which is still a meaningful gain even if it feels modest.",
                "The work allowance is only available to households with a child or a limited capability for work element. In 2026/27 it is £673 a month where no housing costs element is included, or £404 a month where housing costs are part of the award. Earnings up to that level are fully disregarded before the taper kicks in.",
                "For households without a work allowance — typically couples or single adults without children or a health condition — the taper starts from the first pound of net earnings. That is one reason why the same gross wage can produce a very different Universal Credit figure depending on household composition.",
            ]},
            {"heading": "How housing costs are handled inside Universal Credit", "paragraphs": [
                "The housing costs element covers rent for private tenants, social tenants and some supported accommodation. For private renters, the maximum support is capped at the Local Housing Allowance rate for your area, which is the 30th percentile of local rents in a given Broad Rental Market Area. That can leave a gap between the LHA cap and actual rent.",
                "Social tenants receive a notional rent figure subject to bedroom rules. If you have more bedrooms than the social size criteria allow, a deduction of 14% (one spare room) or 25% (two or more spare rooms) typically applies.",
                "Service charges and some other housing costs may or may not be covered, depending on whether they are eligible under the rules. Owner-occupiers in Universal Credit face different rules again — support for mortgage interest now comes through the Support for Mortgage Interest loan scheme rather than directly inside the Universal Credit award.",
            ]},
            {"heading": "Savings, capital and the £16,000 rule", "paragraphs": [
                "Universal Credit uses a capital limit. If you or your partner have savings and investments totalling £16,000 or more, you are generally not eligible for a standard Universal Credit award. This applies to most types of savings, investments and property other than the home you live in.",
                "Between £6,000 and £16,000, savings are treated as generating assumed income. For every £250 above £6,000, the system adds £4.35 to your assumed monthly income — regardless of what the savings actually earn. That assumed income reduces the award in the same way as real earnings.",
                "Some capital is fully disregarded, including some compensation payments and money set aside to meet specific care or housing needs. If your savings have recently changed significantly, a benefits adviser can help clarify the treatment.",
            ]},
            {"heading": "Children and the two-child limit (April 2026 change)", "paragraphs": [
                "From 6 April 2026, the government removed the two-child limit for Universal Credit child elements. All eligible dependent children in a household now generate a child element, regardless of when they were born. This is a significant change for larger families who were previously capped at two children in the UC child element.",
                "The child element for each child is £303.94 a month in 2026/27. An additional amount applies for the first child if they were born before April 2017, reflecting legacy transitional rules.",
                "Child Benefit is a separate payment and sits entirely outside Universal Credit. Receiving Child Benefit does not reduce your Universal Credit award directly, though very high child benefit amounts could theoretically interact with the Benefit Cap in some larger households.",
            ]},
            {"heading": "The Benefit Cap and when it applies", "paragraphs": [
                "Even a correctly calculated award can be reduced by the Benefit Cap, which sets a ceiling on the total monthly benefits a household can receive. For 2026/27, the cap is broadly £1,835 a month outside Greater London and £2,110 inside London for families or single parents. Single adults without children face lower caps.",
                "Several groups are exempt from the cap — including households receiving PIP, DLA, ESA in the support group, the limited capability for work-related activity element of Universal Credit, carer's allowance or Working Tax Credit. Earning enough to cross the earnings threshold can also lift the cap.",
                "If your estimate comes out lower than expected and the household has multiple children or high rent, it is worth checking whether the Benefit Cap is the reason.",
            ]},
            {"heading": "Use Universal Credit as the starting point, not the endpoint", "paragraphs": [
                "Universal Credit is usually the largest monthly support for a working-age household, but it rarely covers everything. Council Tax Reduction is a separate local scheme with its own application process. Child Benefit is paid separately and should always be claimed, even if HICBC could reduce its value. Tax-Free Childcare and the UC childcare element cannot be used at the same time, so a comparison is worth doing.",
                "Disability-related support such as PIP is not part of Universal Credit and is not affected by UC income rules. ESA may interact with Universal Credit, but the details depend on whether the claim is New Style ESA or a legacy route.",
            ]},
        ],
        "related": ["universal-credit-calculator", "benefit-cap-calculator", "tax-free-childcare-calculator", "council-tax-reduction-calculator"],
        "faq": [
            {"q": "Is Universal Credit paid weekly or monthly?", "a": "Universal Credit is normally paid monthly. The first payment usually takes about five weeks to arrive, and an advance is available to cover the gap."},
            {"q": "Can you get Universal Credit if you work full time?", "a": "Yes, in some circumstances. It depends on your earnings, household size, rent and other factors. The 55% taper means higher earners usually receive less, but the award does not cut off immediately when you start working."},
            {"q": "What is the work allowance in 2026/27?", "a": "It is £673 a month if you do not have a housing costs element, or £404 a month if you do. Only households with a child or a limited capability for work element receive a work allowance."},
            {"q": "Do savings always stop Universal Credit?", "a": "Not until they reach £16,000 for most standard cases. Between £6,000 and £16,000 they reduce the award through an assumed income calculation. Below £6,000 they are usually fully disregarded."},
            {"q": "Does Universal Credit cover council tax?", "a": "No. Council Tax Reduction is a separate local scheme and usually needs its own application to the local authority."},
        ],
        "related_guides": ["how-savings-affect-benefits", "universal-credit-if-my-wages-go-up", "universal-credit-rent-increase-explained", "help-with-rent-and-council-tax", "what-counts-as-income-for-benefits"],
    },
    "universal-credit-if-my-wages-go-up": {
        "title": "Universal Credit if my wages go up",
        "description": "What usually happens to Universal Credit when wages rise, with the taper, work allowance and practical budgeting impact explained in plain English.",
        "topic": "Universal Credit scenarios",
        "sections": [
            {"heading": "A pay rise usually reduces Universal Credit, but does not wipe out the gain", "paragraphs": ["The most common worry is that a pay rise will make the extra work pointless because Universal Credit will simply take it all back. In most cases that is not what happens. The award usually falls gradually rather than disappearing in a single jump.", "Once earnings are above any work allowance, Universal Credit normally falls by 55p for every extra £1 of net earnings. That still means you keep 45p of the extra pound before thinking about any tax, council tax support or childcare changes."]},
            {"heading": "The work allowance is what makes some pay rises feel much better than others", "paragraphs": ["If your household has a child or a health-related work capability element, part of your earnings can be ignored before the taper starts. That ignored amount is the work allowance. It makes the first slice of extra earnings more valuable.", "Households without a work allowance still gain from earning more, but the Universal Credit reduction starts from the first pound. That is one reason two people with the same wage rise can experience very different outcomes."]},
            {"heading": "The useful next step is to compare before and after, not just read the rule", "paragraphs": ["A quick estimator is best used as a scenario tool here. Run the Universal Credit calculator with your current wages, then run it again with the higher figure. The difference between the two results is usually more useful than trying to picture the taper abstractly.", "If the result still feels tight, check council tax support and childcare pages as well. The real household position is often shaped by more than one scheme moving at once."]},
        ],
        "related": ["universal-credit-calculator", "earnings-impact-calculator", "council-tax-reduction-calculator"],
        "faq": [
            {"q": "Do you always keep some of a pay rise on Universal Credit?", "a": "Usually yes. Universal Credit is reduced by a taper, but it does not normally remove the whole increase."},
            {"q": "Does overtime affect Universal Credit?", "a": "Yes. Universal Credit uses actual earnings reported in the assessment period, so overtime can reduce the award in the same month."},
        ],
    },
    "universal-credit-if-partner-moves-in": {
        "title": "Universal Credit if a partner moves in",
        "description": "What usually changes when a partner moves in while you claim Universal Credit, including household assessment, joint savings and what to re-check next.",
        "topic": "Universal Credit scenarios",
        "sections": [
            {"heading": "Universal Credit switches from a single claim to a household assessment", "paragraphs": ["If a partner moves in, Universal Credit is usually no longer assessed just on you. The system starts looking at the household as a couple instead. That changes the standard allowance, but it also brings the other person's earnings and savings into the same calculation.", "The couple allowance is higher than the single allowance, but that does not guarantee a higher final award. In practice, the new partner's income is often the bigger driver."]},
            {"heading": "Savings and earnings are combined", "paragraphs": ["Couples are assessed on joint capital. A partner's savings can therefore move the household into the tapered range or above the usual capital limit even if you had little saved yourself.", "The same is true for wages. A partner moving in can change the whole result because their net earnings become part of the same assessment."]},
            {"heading": "Treat this as both a reporting issue and a planning issue", "paragraphs": ["A partner moving in is one of the clearest examples of why this site is built around connected pages rather than a single headline estimate. Child Benefit, HICBC, council tax help and childcare support can all change when the household changes.", "Use the calculator to understand the direction of travel, but report the change promptly to the official service once it becomes real."]},
        ],
        "related": ["universal-credit-calculator", "child-benefit-calculator", "council-tax-reduction-calculator"],
        "faq": [
            {"q": "Do I need to report a partner moving in?", "a": "Yes. Universal Credit should reflect the current household, so a new partner is normally a reportable change."},
            {"q": "Can the award go down even though the couple allowance is higher?", "a": "Yes. The higher couple allowance can be outweighed by the partner's earnings or savings."},
        ],
    },
    "how-savings-affect-benefits": {
        "title": "How savings affect benefits — UC capital limits, tariff income and capital disregards",
        "description": "How savings affect Universal Credit 2026/27: the £6,000 lower limit, £16,000 upper limit, tariff income of £4.35 per £250 and what counts as capital or capital disregards.",
        "topic": "Savings rules",
        "sections": [
            {"heading": "There is no single savings rule for the whole benefits system", "paragraphs": [
                "The most common mistake people make with savings and benefits is assuming one rule covers everything. In reality, different benefits use different capital thresholds, different assumed-income formulas, and different lists of disregarded amounts.",
                "Universal Credit has a lower capital limit and a relatively strict treatment of amounts between the thresholds. Pension Credit is much more lenient and uses a different formula. Non-means-tested benefits like PIP, Carer's Allowance and Child Benefit are not affected by savings at all.",
                "Before you assume savings rule out any benefit, it is worth identifying which benefit is in play and what that specific scheme says about capital — rather than applying a rule you heard about a different benefit.",
            ]},
            {"heading": "Universal Credit: the £6,000 and £16,000 thresholds in 2026/27", "paragraphs": [
                "For Universal Credit, savings and capital below £6,000 are fully disregarded. They do not reduce your award at all. Savings between £6,000 and £15,999 are treated as generating assumed income: for every complete £250 above £6,000, DWP adds £4.35 a month to your assumed income. That assumed income then reduces your award through the standard calculation.",
                "If savings reach £16,000 or more, you generally lose eligibility for a normal Universal Credit award. This applies to most savings accounts, investments, and some other assets, but your main home is disregarded.",
                "Couples are assessed on combined capital. So if one partner has £3,000 and the other has £5,000, the joint total is £8,000 — which takes the household into the tapered range rather than the fully disregarded range.",
            ]},
            {"heading": "Pension Credit: a much gentler treatment of capital", "paragraphs": [
                "Pension Credit ignores the first £10,000 of capital entirely. Above £10,000, the rules use a similar assumed-income calculation to Universal Credit but with a more generous starting point and the same £1 per £500 formula rather than a strict cut-off.",
                "There is no equivalent of the £16,000 stop-point that Universal Credit uses. That means a pensioner with £25,000 in savings can still receive Pension Credit, though the award will be reduced by the assumed weekly income generated by the capital above £10,000.",
                "This matters enormously for older people who have accumulated modest savings over working life. Many self-exclude from Pension Credit because they have savings, not realising how much more forgiving the rules are compared with working-age benefits.",
            ]},
            {"heading": "Some types of capital are disregarded or treated differently", "paragraphs": [
                "Not all money is treated as capital. Personal injury compensation payments can be disregarded, sometimes indefinitely and sometimes for a set period, depending on the circumstances. Money specifically set aside to meet care needs may also be disregarded under certain conditions.",
                "Property you own beyond your main home can count as capital, with a notional value calculation applied. Joint savings accounts, ISAs and some investment accounts are usually counted. Premium Bonds are generally counted. The face value of the bonds, not any prize money already paid out, is what matters.",
                "If you have recently received a lump sum — an inheritance, a redundancy payment, a compensation settlement — the treatment can be complex. Timing of the payment and how it has been used since can affect whether and how it is counted.",
            ]},
            {"heading": "Deliberate deprivation: spending savings to claim benefits", "paragraphs": [
                "DWP can treat you as still holding capital you have deliberately given away or spent to get below a threshold. This is called deprivation of capital, and it can result in a notional capital figure being used even after the money is gone.",
                "The rules are not as aggressive as some people assume for ordinary spending. Paying off debt, covering living expenses and making reasonable purchases are unlikely to be treated as deliberate deprivation. Giving large amounts to family members specifically before claiming is where problems arise.",
                "If you are concerned about how a recent capital change might be treated, talking to Citizens Advice or a welfare rights adviser before making a claim is sensible.",
            ]},
            {"heading": "What to do when savings are close to a threshold", "paragraphs": [
                "If your savings are close to a threshold, it is worth tracking the exact amount carefully and understanding how it relates to the relevant benefit's rules. A small difference can shift you from fully eligible to slightly reduced or from reduced to ineligible.",
                "It is also worth noting that Pension Credit savings rules and Universal Credit savings rules work independently of each other. Someone transitioning from UC to pension-age support does not carry the same capital thresholds across.",
                "A benefits calculator gives you a useful starting estimate, but for edge cases around capital — especially inherited money, property, business assets or compensation payments — taking specific advice from a welfare rights specialist gives the most reliable answer.",
            ]},
        ],
        "related": ["universal-credit-calculator", "housing-benefit-calculator", "pension-credit-calculator"],
        "faq": [
            {"q": "Do savings affect PIP or Carer's Allowance?", "a": "No. PIP, DLA and Carer's Allowance are not means tested. Income and savings do not affect them."},
            {"q": "Does Universal Credit stop at exactly £16,000 in savings?", "a": "Yes, for most standard cases the award stops when capital reaches £16,000 or more. Between £6,000 and £16,000 the award is reduced through an assumed-income calculation of £4.35 a month per £250 above the lower threshold."},
            {"q": "Does an ISA count as capital for Universal Credit?", "a": "Yes. ISAs usually count as capital for Universal Credit in the same way as ordinary savings accounts and investments."},
            {"q": "What are Universal Credit capital disregards?", "a": "Your main home is disregarded, and some compensation payments, business assets and care-related amounts can also be ignored for a period or in full depending on the circumstances."},
            {"q": "Does Pension Credit have the same £16,000 limit?", "a": "No. Pension Credit uses different rules. It disregards the first £10,000 and then applies an assumed-income formula above that, but there is no hard upper limit equivalent to the £16,000 UC stop-point."},
            {"q": "Does a joint account count as capital for one person or two?", "a": "Joint accounts are usually split 50:50 between partners for benefits purposes unless there is evidence of a different beneficial ownership split."},
            {"q": "Can spending savings before claiming be a problem?", "a": "It can be. DWP can apply a deprivation of capital rule if they believe savings were deliberately reduced to get below a threshold. Ordinary spending on living expenses is unlikely to trigger this, but large transfers to family members shortly before a claim may be questioned."},
        ],
    },
    "help-with-rent-and-council-tax": {
        "title": "Help with rent and council tax",
        "description": "UK rent and council tax support 2026/27: Universal Credit housing costs, Housing Benefit eligibility and Council Tax Reduction explained.",
        "topic": "Housing support",
        "sections": [
            {"heading": "Help with rent and council tax usually comes from different places", "paragraphs": ["One of the most common misunderstandings is assuming rent support and council tax support are part of the same claim. They are not. Rent help is often routed through Universal Credit or, in some cases, Housing Benefit. Council tax help usually sits in a separate local authority scheme.", "That split matters because many households claim one type of support and miss the other entirely."]},
            {"heading": "Rent help usually starts with Universal Credit now", "paragraphs": ["For most working-age households making a new claim, help with rent usually sits inside Universal Credit rather than Housing Benefit. That means the rent question is often tied closely to earnings, children and other living-cost support.", "Housing Benefit still matters in pension-age cases and some specialist housing situations, which is why it still deserves its own page rather than being written off as a dead topic."]},
            {"heading": "Council Tax Reduction is local, which is why it feels inconsistent", "paragraphs": ["Council Tax Reduction schemes are run locally, so two councils can handle low-income cases differently. That is one reason people find council tax help harder to understand than headline national benefits.", "A national estimator can still be useful, but it needs to be honest about local variation instead of pretending there is one single UK formula."]},
            {"heading": "A gap after support does not always mean there is no more help", "paragraphs": ["If your rent support or council tax support estimate still leaves a big shortfall, it may be worth checking discretionary housing help, local welfare support or council hardship routes. The mainstream award is not always the full picture.", "That matters especially for households dealing with temporary income drops, arrears pressure or unusually high housing costs."]},
            {"heading": "The strongest next step is to check both bills together", "paragraphs": ["If housing costs are the reason you are searching for support, check rent help and council tax help side by side rather than one after the other. A partial answer on only one bill can make the overall situation look worse than it really is.", "That is why this guide sits between Universal Credit, Housing Benefit and Council Tax Reduction pages in the site structure."]},
        ],
        "related": ["universal-credit-calculator", "housing-benefit-calculator", "council-tax-reduction-calculator"],
        "faq": [
            {"q": "Can you get help with council tax if you work?", "a": "Yes. Many working households with a low income still qualify for Council Tax Reduction."},
            {"q": "Is Housing Benefit still available?", "a": "Yes, but it is now mainly relevant for pension-age households and some specialist accommodation cases."},
            {"q": "Does Universal Credit automatically reduce council tax?", "a": "No. Council Tax Reduction is usually a separate local scheme and often needs its own application."},
        ],
    },
    "benefits-for-low-income-families": {
        "title": "Benefits for low-income families",
        "description": "UK support for low-income families 2026/27: Universal Credit, Child Benefit, Free School Meals, Healthy Start and childcare help explained.",
        "topic": "Families",
        "sections": [
            {"heading": "Family support usually comes in layers", "paragraphs": ["Low-income family support rarely comes through one single payment. A family may have Universal Credit as the core award, but Child Benefit, school support, childcare help and local council support can all sit around it.", "That is why looking only for one number often gives the wrong impression. The better question is which pieces of help may stack together for your household."]},
            {"heading": "Universal Credit is often the centre, but not the whole picture", "paragraphs": ["For many working-age families, Universal Credit is the biggest means-tested support route. But it does not replace Child Benefit, and it does not make school-related help or food support irrelevant.", "Families often miss smaller schemes because they are focused on the monthly Universal Credit amount. In practice, those smaller schemes can still make a visible difference to the weekly budget."]},
            {"heading": "Childcare support is one of the biggest decision areas", "paragraphs": ["Universal Credit childcare support and Tax-Free Childcare cannot usually be used together. That makes childcare one of the most important comparisons for working parents.", "The better option depends on earnings, hours worked, childcare bills and whether the family is already relying on means-tested support. There is no single answer that suits everyone."]},
            {"heading": "School and food support often gets overlooked", "paragraphs": ["Free School Meals and Healthy Start do not always dominate headlines, but they can still matter a lot to family budgets. They also tend to fit the same search journey as Child Benefit and Universal Credit, which is why they deserve strong standalone pages rather than a passing mention.", "A good support check for a family should always look beyond the biggest monthly payment."]},
            {"heading": "Use the family pages together, not in isolation", "paragraphs": ["The cleanest way to use a benefits site as a parent is to move through the family cluster together: Universal Credit, Child Benefit, HICBC if relevant, childcare help, Free School Meals and Healthy Start. That gives a much better sense of the real support picture.", "That is also how these pages are written. They are meant to work as a connected set rather than as disconnected blog posts."]},
        ],
        "related": ["universal-credit-calculator", "child-benefit-calculator", "tax-free-childcare-calculator", "free-school-meals-checker"],
        "faq": [
            {"q": "Can working families still get help?", "a": "Yes. Work does not automatically stop support, especially through Universal Credit, Child Benefit and some childcare schemes."},
            {"q": "What is often missed by low-income families?", "a": "Free School Meals, Healthy Start and childcare support are commonly missed because people focus only on Universal Credit."},
            {"q": "Should I check Child Benefit separately from Universal Credit?", "a": "Yes. Child Benefit sits outside Universal Credit and should usually be checked on its own."},
        ],
    },
    "pip-explained-simply": {
        "title": "PIP explained simply",
        "description": "PIP explained 2026/27 — daily living and mobility components, how the points system works, weekly rates, and what evidence strengthens a claim.",
        "topic": "Disability support",
        "sections": [
            {"heading": "What PIP is and who it is for", "paragraphs": [
                "Personal Independence Payment (PIP) is a non-means-tested benefit for people aged 16 to State Pension age who have a long-term physical or mental health condition or disability that affects their ability to carry out daily activities or move around.",
                "Non-means-tested means income and savings do not affect it at all. It does not matter how much you earn, what savings you have, or whether your partner works. PIP is assessed purely on how your condition affects you.",
                "PIP has two components: daily living (for difficulties with things like cooking, washing, dressing, communicating or managing medication) and mobility (for difficulties getting around). Each is assessed separately using a points-based descriptors system.",
            ]},
            {"heading": "The 2026/27 PIP weekly rates", "paragraphs": [
                "Standard daily living rate: £76.70 a week. Enhanced daily living rate: £114.60 a week. Standard mobility rate: £30.30 a week. Enhanced mobility rate: £80.00 a week.",
                "If you qualify for both components, the total can be up to £194.60 a week — over £10,000 a year. Even the standard daily living rate alone adds up to nearly £4,000 a year.",
                "PIP is usually paid every four weeks. It is generally not taxable. Receiving PIP does not reduce Universal Credit directly (though it may affect whether you are included in certain benefit cap exemptions).",
            ]},
            {"heading": "How the points system works", "paragraphs": [
                "Each component has a list of activities. For daily living, these include preparing food, eating and drinking, managing treatments, washing and bathing, managing toilet needs, dressing and undressing, communicating verbally, reading, engaging with other people face to face and making budgeting decisions. For mobility, the activities are planning and following journeys, and moving around.",
                "Each activity has several descriptors describing different levels of difficulty. Each descriptor has a point value, typically from 0 to 12. DWP selects the highest-scoring descriptor that consistently applies to you.",
                "Standard rate starts at 8 points in a component. Enhanced rate starts at 12 points. You need at least 8 points in the daily living component for a daily living award, and at least 8 points in the mobility component for a mobility award. You can score points in one component only, both, or neither.",
            ]},
            {"heading": "The four tests that apply to every descriptor", "paragraphs": [
                "A descriptor does not just apply because you occasionally struggle with an activity. DWP applies four tests when scoring each one. First, can you carry out the activity safely? Second, can you carry it out to an acceptable standard? Third, can you do it repeatedly throughout the day if needed? Fourth, can you do it within a reasonable time period?",
                "If you can do something technically, but only unsafely (risking harm), or only once but not repeatedly, or only with significant pain or fatigue — these factors can lead to a higher-scoring descriptor being applied.",
                "The word 'reliably' summarises these tests. The question is not whether you can do something on your best day. It is whether you can do it reliably, across your typical range of days, as your condition actually presents.",
            ]},
            {"heading": "Why evidence quality is often the decisive factor", "paragraphs": [
                "The PIP assessment process involves a face-to-face or phone assessment conducted by a healthcare professional contracted by DWP. Their report informs — but does not determine — the DWP decision maker's outcome.",
                "The quality of evidence you provide before and during the assessment makes a significant difference. Useful evidence includes GP letters that describe the functional impact of your condition (not just the diagnosis), letters from specialists or consultants, care plans, physiotherapy notes, occupational health reports and records from social care.",
                "A symptom diary kept for several weeks before the assessment can help demonstrate the variability of the condition. Many conditions fluctuate, and showing that bad days are frequent matters. The assessor sees you on one day — evidence shows the pattern.",
                "Many unsuccessful PIP claims or appeals succeed after additional evidence is submitted. The initial decision is not final. Mandatory reconsideration and appeal to a tribunal are options if the outcome seems wrong.",
            ]},
            {"heading": "What PIP can unlock beyond the direct payment", "paragraphs": [
                "Certain rates of PIP can passport into other support. Enhanced mobility PIP usually qualifies for the Motability scheme, Blue Badge eligibility, and Vehicle Excise Duty exemption. Standard mobility PIP is also relevant for Blue Badge in many areas.",
                "PIP can exempt a household from the Benefit Cap in Universal Credit, because claimants receiving PIP (or DLA) are usually exempt. A carer who receives Carer's Allowance for a PIP recipient may also gain entitlement to carer-related elements in their own benefits.",
                "PIP is not a one-off award. It is reviewed periodically and can also be renewed when awards expire. If circumstances worsen, a change of circumstances can be reported and a reassessment requested.",
            ]},
        ],
        "related": ["pip-eligibility-checker", "esa-calculator", "benefit-cap-calculator"],
        "faq": [
            {"q": "Does PIP stop if you start working?", "a": "No. PIP is not affected by whether you work, how much you earn, or any savings you have. It is assessed purely on how your condition affects daily activities and mobility."},
            {"q": "What are the 2026/27 PIP weekly rates?", "a": "Standard daily living: £76.70. Enhanced daily living: £114.60. Standard mobility: £30.30. Enhanced mobility: £80.00. Both components can be paid together."},
            {"q": "How many points do you need for standard PIP?", "a": "At least 8 points in the daily living component for a daily living award, or at least 8 points in the mobility component for a mobility award."},
            {"q": "What if the PIP assessment seems wrong?", "a": "You can request a mandatory reconsideration and then appeal to an independent tribunal. A significant proportion of PIP appeals succeed, particularly when additional evidence is provided."},
            {"q": "Does receiving PIP affect Universal Credit?", "a": "Not directly in terms of reducing UC. However, PIP can exempt a household from the Benefit Cap and may affect whether certain elements of Universal Credit are in scope."},
        ],
        "related_guides": ["pip-points-explained", "pip-daily-living-explained", "pip-mobility-explained", "esa-vs-universal-credit", "what-benefits-can-i-claim"],
    },
    "pip-points-explained": {
        "title": "PIP points explained",
        "description": "A plain-English guide to how PIP points work, what 8 and 12 points mean, and how the daily living and mobility components are scored.",
        "topic": "Disability support",
        "sections": [
            {"heading": "PIP points decide the rate, not the diagnosis", "paragraphs": ["PIP is built around activities and descriptors. Points are awarded because of the level of difficulty you have with those activities, not simply because of the name of a condition.", "That is why understanding the points system matters so much. It tells you where a claim looks strong, borderline or likely to need better evidence."]},
            {"heading": "The key thresholds are 8 points and 12 points", "paragraphs": ["In each component, 8 points usually means standard rate and 12 points usually means enhanced rate. The components are separate, so you can score enough in one component without qualifying in the other.", "This is the reason even a simple checker can be useful. It helps you sense-check the likely band before getting lost in the full assessment language."]},
            {"heading": "Points only matter if the descriptor applies reliably", "paragraphs": ["A point total is only useful if the descriptor genuinely applies most of the time and meets the reliability tests: safely, repeatedly, to an acceptable standard and within a reasonable time.", "Use a points guide to orient yourself, but use evidence and examples to make the case stronger."]},
        ],
        "related": ["pip-eligibility-checker", "esa-calculator", "benefit-cap-calculator"],
        "faq": [
            {"q": "How many points do you need for standard PIP?", "a": "Usually 8 points in a component."},
            {"q": "How many points do you need for enhanced PIP?", "a": "Usually 12 points in a component."},
        ],
    },
    "esa-vs-universal-credit": {
        "title": "ESA vs Universal Credit",
        "description": "When ESA, Universal Credit or both may apply, and why the two systems often overlap for people with health conditions.",
        "topic": "Health and work",
        "sections": [
            {"heading": "ESA and Universal Credit answer different questions", "paragraphs": ["New Style ESA is mainly about contribution history and capability for work. Universal Credit is means tested and can include rent, children and other household support. That is why some people can be entitled to both, even though one can reduce the other.", "If you only look at one system, you can misunderstand the overall position."]},
            {"heading": "Why SSP often sits before both", "paragraphs": ["If you are employed and off sick, SSP may be the first payment in the chain. Once SSP ends or is too low, ESA and Universal Credit become more relevant.", "That is why the site architecture connects SSP, ESA and Universal Credit closely."]},
            {"heading": "Use the right estimator for the right question", "paragraphs": ["Use an ESA page to sense-check contribution-based support and pension interactions. Use Universal Credit pages when household income, rent and children are the bigger issue. The real-world answer is often not either-or.", "This guide exists to make that split easier to understand."]},
        ],
        "related": ["esa-calculator", "ssp-calculator", "universal-credit-calculator"],
        "faq": [{"q": "Can Universal Credit replace ESA?", "a": "For some households UC becomes the main means-tested route, but New Style ESA can still matter if the NI record is there."}],
    },
    "child-benefit-and-hicbc": {
        "title": "Child Benefit and HICBC explained",
        "description": "Child Benefit 2026/27: £27.05/week first child. How the High Income Child Benefit Charge applies above £60,000 and why some higher earners still claim.",
        "topic": "Family tax",
        "sections": [
            {"heading": "Child Benefit in 2026/27 — rates and who gets it", "paragraphs": [
                "Child Benefit is a universal payment available to anyone responsible for a child under 16 (or under 20 if they are in approved education or training). Unlike Universal Credit, it is not means tested at the point of claim. The current 2026/27 weekly rates are £27.05 for the eldest or only child and £17.90 for each additional child.",
                "Those rates add up. A family with two children receives £44.95 a week — £2,337 a year — just in Child Benefit. A family with three children receives £62.85 a week. The amounts are meaningful for family budgets and worth claiming even when other support is not available.",
                "Child Benefit is paid every four weeks into a bank account. You can claim as soon as your child is born or as soon as a child comes to live with you. Claims can be backdated by up to three months.",
            ]},
            {"heading": "What the High Income Child Benefit Charge is", "paragraphs": [
                "The High Income Child Benefit Charge (HICBC) is a tax charge that recovers some or all of Child Benefit if anyone in the household has adjusted net income over a threshold. From the 2024/25 tax year onwards, the threshold is £60,000 and the charge reaches 100% — meaning the full Child Benefit is recovered — at £80,000.",
                "The charge applies to the highest earner in the household, not both earners. So a couple where one earns £75,000 and the other earns £30,000 are subject to HICBC based on the £75,000 figure, not the combined income.",
                "The rate of the charge is 1% of the annual Child Benefit for every £200 of adjusted net income above £60,000. At £70,000, that is 50% of Child Benefit repaid. At £80,000 or above, the full amount is repaid through the charge.",
            ]},
            {"heading": "Adjusted net income — the figure that actually matters", "paragraphs": [
                "Adjusted net income is not the same as gross salary. It is your gross income minus certain deductions. The most important deductions for many higher earners are pension contributions paid into a registered pension scheme and Gift Aid donations to charity.",
                "If you earn £65,000 and make £6,000 a year in pension contributions, your adjusted net income is £59,000 — below the £60,000 HICBC threshold. In that case, no charge applies at all.",
                "This is why salary sacrifice pension contributions can make sense for earners close to the threshold. They reduce the adjusted net income figure dollar-for-dollar (up to the pension contribution rules), which can move a household from a partial or full HICBC position to no charge at all.",
            ]},
            {"heading": "Why keeping the claim alive still makes sense for some families", "paragraphs": [
                "Even when a household decides to opt out of receiving Child Benefit payments — to avoid the hassle of registering for Self Assessment and repaying the charge — it usually makes sense to keep the claim active.",
                "An active claim protects National Insurance credits for the non-working or lower-earning partner. These credits count toward the State Pension and are valuable over a working life. Without them, a career break for childcare can leave a permanent gap in the NI record.",
                "A live claim also ensures the child receives a National Insurance number automatically at age 16. Without a claim, the child may need to apply separately later.",
                "Opting out of payments is straightforward. HMRC allows this online, and the claim continues to exist even with payments suspended. If circumstances change and the income position improves, payments can be reinstated.",
            ]},
            {"heading": "How to pay the HICBC — Self Assessment", "paragraphs": [
                "The person subject to the charge needs to register for Self Assessment and declare the Child Benefit received through a tax return. HMRC can also collect it through a tax code adjustment if you prefer.",
                "If you have not been completing Self Assessment and realise HICBC may have applied in past years, HMRC has a backdating process. The rules on penalties and interest for late registration have been updated in recent years, and many families who came forward voluntarily received a reduced penalty.",
                "Once registered, the charge is straightforward to calculate. It is the annual Child Benefit received, adjusted by the taper rate for your income above the threshold.",
            ]},
            {"heading": "The planning question — should we claim or not?", "paragraphs": [
                "For households with a higher earner significantly above £80,000, the charge equals 100% of Child Benefit. In that case, many families opt out of payments entirely. The claim still exists (protecting NI credits and the child's NI number), but no money changes hands.",
                "For households with the higher earner between £60,000 and £80,000, the decision is more nuanced. The net benefit after the charge is partial but real. Running the HICBC calculator alongside a pension contribution review can show whether small changes to contributions change the position meaningfully.",
                "For households where pension contributions could bring adjusted net income below £60,000, the full Child Benefit can be retained without any charge. That is often the most financially attractive outcome and worth planning before the tax year rather than after.",
            ]},
        ],
        "related": ["child-benefit-calculator", "hicbc-calculator", "tax-free-childcare-calculator"],
        "faq": [
            {"q": "Should a higher earner still claim Child Benefit if they will repay it all?", "a": "Often yes, because a live claim protects National Insurance credits for the non-working or lower-earning partner and ensures the child gets an NI number automatically. Payments can be opted out of while the claim stays active."},
            {"q": "At what income does HICBC reach 100%?", "a": "At £80,000 adjusted net income and above (from 2024/25 onwards), the charge equals 100% of Child Benefit. Between £60,000 and £80,000, the charge is proportional."},
            {"q": "Can pension contributions really reduce HICBC?", "a": "Yes. Because HICBC is based on adjusted net income, pension contributions reduce the figure used. If contributions bring income below £60,000, no charge applies at all."},
            {"q": "What if my employer pays pension contributions?", "a": "Only contributions you make yourself (including salary sacrifice) reduce adjusted net income. Employer contributions made directly by the employer do not reduce your adjusted net income for HICBC purposes."},
            {"q": "Do I need to do a tax return for HICBC?", "a": "Yes, if you or your partner received Child Benefit and anyone in the household had adjusted net income over £60,000 in any year since 2012/13. You need to register for Self Assessment and complete a tax return."},
        ],
        "related_guides": ["how-much-child-benefit-for-1-2-3-children", "child-benefit-tax-charge-examples", "tax-free-childcare-guide", "benefits-for-low-income-families"],
    },
    "how-much-child-benefit-for-1-2-3-children": {
        "title": "How much Child Benefit for 1, 2 or 3 children?",
        "description": "Child Benefit amounts for 1, 2 and 3 children in 2026/27 — weekly, monthly and annual totals, plus what to check if the High Income Charge may apply.",
        "topic": "Child Benefit examples",
        "sections": [
            {"heading": "One child is the cleanest place to start", "paragraphs": ["For one child, Child Benefit uses the eldest-or-only-child rate. That makes it the simplest example and a useful starting point for understanding the value of the claim in weekly, monthly and annual terms.", "It is also the clearest way to compare the value of Child Benefit with other support such as childcare help or council tax support if the household budget is tight."]},
            {"heading": "Two or three children increase the award, but not in a straight line", "paragraphs": ["Once there is more than one child, the first child uses the higher rate and each additional child uses the lower additional-child rate. So the total rises, but it does not simply double or triple in a straight line.", "That is why worked examples are useful. They show the real scale of the payment rather than leaving parents to guess from a rate table."]},
            {"heading": "If household income is higher, the next question is HICBC", "paragraphs": ["For some households the more important question is not just how much Child Benefit is paid, but how much is kept after the High Income Child Benefit Charge. That is especially true where one partner has adjusted net income above the threshold.", "The practical workflow is simple: check the household Child Benefit amount first, then test the HICBC page if higher income is in the picture."]},
        ],
        "related": ["child-benefit-calculator", "hicbc-calculator", "free-school-meals-checker"],
        "faq": [
            {"q": "Does Child Benefit double when you have two children?", "a": "No. The first child uses the higher rate and each additional child uses the lower additional-child rate."},
            {"q": "Should I check HICBC after this page?", "a": "Yes, if anyone in the household has adjusted net income above the HICBC threshold."},
        ],
    },
    "child-benefit-tax-charge-examples": {
        "title": "Child Benefit tax charge examples",
        "description": "Worked HICBC examples showing how much Child Benefit is repaid at different incomes and child counts, in plain English.",
        "topic": "Family tax examples",
        "sections": [
            {"heading": "The charge builds through a taper band", "paragraphs": ["The High Income Child Benefit Charge does not arrive all at once. It rises through the taper band, which is why examples are often easier to understand than a written formula.", "A household just inside the band can still keep some of the Child Benefit, while a household much further through it may effectively lose most or all of it."]},
            {"heading": "The number of children changes the size of the charge", "paragraphs": ["The charge is based on the Child Benefit attached to the household, so more children means more benefit potentially being clawed back. A family with three children faces a visibly different charge profile from a family with one child.", "That is why this site separates the Child Benefit amount and the tax charge examples rather than treating them as one blurred topic."]},
            {"heading": "Adjusted net income keeps the examples practical", "paragraphs": ["Examples are most useful when they show why adjusted net income matters more than rough salary. Pension contributions and Gift Aid can shift the figure used for the charge and therefore change the real outcome.", "Use the examples for orientation, then run your own household numbers through the calculator for a more realistic sense-check."]},
        ],
        "related": ["hicbc-calculator", "child-benefit-calculator", "tax-free-childcare-calculator"],
        "faq": [
            {"q": "Is HICBC based on salary only?", "a": "No. It is based on adjusted net income, which can differ from headline salary."},
            {"q": "Can a household still keep some Child Benefit in the taper band?", "a": "Yes. Households inside the taper band often keep part of the Child Benefit rather than losing all of it immediately."},
        ],
    },
    "pension-credit-explained": {
        "title": "Pension Credit explained",
        "description": "Pension Credit 2026/27: who qualifies, Guarantee Credit rates, savings rules, and how a small award unlocks council tax, heating and NHS support.",
        "topic": "Pension age support",
        "sections": [
            {"heading": "What Pension Credit is and who it is for", "paragraphs": [
                "Pension Credit is a means-tested benefit for people who have reached State Pension age and whose income falls below a minimum weekly level. In 2026/27, the Guarantee Credit standard minimum is £238.00 a week for a single person and £363.25 a week for a couple.",
                "If your income from all sources — State Pension, private pensions, earnings, savings income and other benefits — comes in below that figure, Pension Credit tops it up to the minimum. If it is above, you receive nothing in Guarantee Credit, though you may still be eligible for Savings Credit in some legacy cases.",
                "Around 880,000 households eligible for Pension Credit are not currently claiming it, according to government estimates. Many have self-excluded based on incorrect assumptions about savings, home ownership or occupational pension income.",
            ]},
            {"heading": "Guarantee Credit — the core of Pension Credit", "paragraphs": [
                "The Guarantee Credit element is the main part of Pension Credit. It tops income up to the minimum figures above. The calculation is broadly: take the standard minimum, add any applicable additions (explained below), and subtract all counted income. If the result is positive, that is the weekly Guarantee Credit award.",
                "Income counted includes State Pension, private or occupational pension payments, earnings and most other income. Some income is fully or partially disregarded — for example, £5 a week of earnings is normally disregarded, and earnings from self-employment or part-time work may be treated more generously in some circumstances.",
                "Owning your home has no effect on Guarantee Credit eligibility. Home ownership is not treated as capital or income. A pensioner living in a house worth £400,000 can still receive Pension Credit if their weekly income is below the minimum.",
            ]},
            {"heading": "Additional elements that can increase the award", "paragraphs": [
                "Pension Credit is not just the standard minimum figure. Several additions can increase it significantly. The Severe Disability Addition (£86.05 a week in 2026/27) applies where the claimant or partner receives the highest rate DLA care component, enhanced daily living PIP or similar, and no one is paid Carer's Allowance for caring for them.",
                "The Carer Addition (£48.15 a week) can be included where the claimant is caring for a severely disabled person, even if Carer's Allowance is not currently being received (because the claimant's State Pension might be higher than Carer's Allowance).",
                "Housing costs can sometimes be included within Pension Credit assessments for owner-occupiers, covering some mortgage interest or certain service charges through the Support for Mortgage Interest route. Transitional protection and specific individual circumstances can also affect the total.",
            ]},
            {"heading": "How savings are treated — much more gently than Universal Credit", "paragraphs": [
                "Pension Credit ignores the first £10,000 of capital entirely. Above £10,000, each £500 of additional savings is treated as £1 a week of assumed income. So savings of £14,000 would generate £8 a week of assumed income — which reduces the award by £8, not eliminates it.",
                "There is no hard upper capital cut-off equivalent to Universal Credit's £16,000 rule. A pensioner with £25,000 in savings has £30,000 of excess above the £10,000 disregard. At £1 per £500, that generates £60 of assumed weekly income. If their other income is below the minimum, they may still qualify for a reduced Guarantee Credit award.",
                "This is fundamentally different from Universal Credit, where £16,000 in savings typically means no award at all. Many pensioners with moderate savings wrongly assume they are in the same position as Universal Credit claimants would be.",
            ]},
            {"heading": "Why Pension Credit matters beyond the weekly cash amount", "paragraphs": [
                "Even a small Pension Credit award can trigger a package of other support that collectively makes a much bigger difference than the direct weekly payment alone.",
                "Guarantee Credit receipt passports entitlement to maximum Council Tax Reduction, full Housing Benefit for those who still receive it, and Cold Weather Payments. It can also provide access to NHS cost help including free prescriptions, dental treatment and sight tests, as well as the Warm Home Discount.",
                "From 2026, the Winter Fuel Payment also carries an income-based condition in England and Wales, and Pension Credit receipt is one of the key qualifying routes. A pensioner with income just above the minimum and no Pension Credit award could miss both the Winter Fuel Payment and the other passported support — representing a significant annual gap.",
            ]},
            {"heading": "How to claim and what happens next", "paragraphs": [
                "Pension Credit can be claimed by phone (the Pension Credit claim line), online or by post. The claim normally covers both Guarantee Credit and any applicable Savings Credit in one application. A successful claim can sometimes be backdated by up to three months.",
                "The claim process involves providing details of all income, savings, property and relevant personal circumstances. DWP may ask for supporting evidence, particularly for savings, pension income and disability-related additions.",
                "If you are unsure whether to claim, a benefits calculator or a welfare rights adviser can give a reasonably accurate indication before you go through the full application. Many councils and charities also offer free benefit checks specifically designed for older people.",
            ]},
        ],
        "related": ["pension-credit-calculator", "winter-fuel-payment-checker", "cold-weather-payment-checker", "council-tax-reduction-calculator"],
        "faq": [
            {"q": "Can you claim Pension Credit if you have savings?", "a": "Yes. Savings up to £10,000 are ignored completely. Above that, they generate assumed income rather than stopping the claim outright. There is no hard savings cut-off for Pension Credit like the £16,000 limit in Universal Credit."},
            {"q": "Does home ownership affect Pension Credit?", "a": "No. Owning your home — regardless of its value — does not count as capital or affect Pension Credit eligibility."},
            {"q": "What is the 2026/27 Pension Credit minimum?", "a": "£238.00 a week for a single person and £363.25 a week for a couple (Guarantee Credit standard minimum)."},
            {"q": "How does Pension Credit affect other benefits?", "a": "It can passport you into maximum Council Tax Reduction, Cold Weather Payments, full Housing Benefit, NHS cost help and potentially the Winter Fuel Payment in England and Wales."},
            {"q": "Can you get Pension Credit if you have a private pension?", "a": "Yes. Private or occupational pension income reduces the award, but does not automatically remove eligibility if total income is still below the minimum."},
        ],
        "related_guides": ["what-pension-credit-unlocks", "pension-credit-examples-for-single-pensioner", "pension-credit-examples-for-couple", "how-savings-affect-benefits", "what-benefits-can-i-claim"],
    },
    "pension-credit-examples-for-single-pensioner": {
        "title": "Pension Credit examples for a single pensioner",
        "description": "Pension Credit worked examples 2026/27: how weekly income, savings and additions affect the estimate and why even a small award can matter.",
        "topic": "Pension Credit examples",
        "sections": [
            {"heading": "Examples are more useful than a bare threshold", "paragraphs": ["A single pensioner often wants to know not just the weekly minimum, but what happens if they have a small occupational pension, modest savings or a disability-related addition. Worked examples answer that much better than a single headline figure.", "They also show why a small award can still matter if it opens the door to wider support."]},
            {"heading": "Savings do not automatically rule a single pensioner out", "paragraphs": ["This is one of the most useful example patterns because many single pensioners wrongly assume savings mean the answer is no. Pension Credit is much more forgiving than working-age means-tested support.", "Examples make that clear quickly: savings can reduce the award, but they do not automatically eliminate it."]},
            {"heading": "The award is only part of the value", "paragraphs": ["A worked estimate should usually lead into winter support, council tax help and NHS cost help. The weekly top-up matters, but the connected support can matter just as much.", "That is why the strongest next step after a positive example is to check the linked pension-age support pages as well."]},
        ],
        "related": ["pension-credit-calculator", "winter-fuel-payment-checker", "council-tax-reduction-calculator"],
        "faq": [
            {"q": "Can a single pensioner with savings still get Pension Credit?", "a": "Yes. Savings can reduce the award, but they do not automatically rule it out."},
            {"q": "Why are examples useful here?", "a": "Because many real cases involve a mix of State Pension, a small private pension and some savings rather than a simple zero-income situation."},
        ],
    },
    "pension-credit-examples-for-couple": {
        "title": "Pension Credit examples for a couple",
        "description": "Worked Pension Credit examples for couples, showing how joint income and savings usually change the estimate and why even a modest award can still matter.",
        "topic": "Pension Credit examples",
        "sections": [
            {"heading": "Couples are assessed together", "paragraphs": ["For Pension Credit, the usual position is to assess the couple together rather than as two separate claims. That means joint income and joint capital matter, which is why examples are often easier to understand than a bare rules summary.", "A worked example shows the relationship between the couple guarantee level and the income already coming into the household."]},
            {"heading": "A modest award can still unlock wider help", "paragraphs": ["Couples often assume that if the weekly award looks small there is not much point checking. In reality, even a modest award can unlock council tax help, winter support and other pension-age support.", "That is why the examples on this site focus on the broader outcome, not just the headline weekly figure."]},
            {"heading": "Use examples to understand the shape of the rules", "paragraphs": ["Examples are a way to understand direction rather than predict every detail. State Pension, occupational pensions, savings and additions for caring or disability can all move the final figure.", "The best pattern is to read the example, then run your own numbers through the calculator."]},
        ],
        "related": ["pension-credit-calculator", "cold-weather-payment-checker", "winter-fuel-payment-checker"],
        "faq": [
            {"q": "Is Pension Credit for couples assessed jointly?", "a": "Yes. The usual approach is to assess the couple together rather than as two separate single claims."},
            {"q": "Can a couple still qualify if one person has a small private pension?", "a": "Yes. A small private pension can reduce the award but does not automatically rule it out."},
        ],
    },
    "tax-free-childcare-guide": {
        "title": "Tax-Free Childcare explained",
        "description": "Tax-Free Childcare 2026/27: how the 20% top-up works, who qualifies, maximum savings per child, and how it compares to UC childcare support.",
        "topic": "Childcare support",
        "sections": [
            {"heading": "What Tax-Free Childcare is and how the top-up works", "paragraphs": [
                "Tax-Free Childcare (TFC) is a government-backed savings account scheme where for every £8 you deposit, the government adds £2. That is effectively a 20% top-up on your childcare costs, or to put it another way, you pay 80p in every £1 of eligible childcare.",
                "The scheme works through a government online childcare account. You deposit money into the account, and the top-up is added automatically. Payments are made directly to registered childcare providers — nurseries, childminders, after-school clubs, holiday camps and similar.",
                "For most children, the maximum government top-up is £2,000 per child per year. For a disabled child, the limit doubles to £4,000 per year. If you have two children, the maximum is £4,000 a year. Three children, £6,000 — and so on.",
            ]},
            {"heading": "Who qualifies for Tax-Free Childcare in 2026/27", "paragraphs": [
                "To be eligible, you and your partner (if you have one) both need to be working. There is no minimum hours requirement, but you each need to earn at least the equivalent of 16 hours at the National Minimum Wage per week on average. That is currently around £187 a week for most adults.",
                "There is also an upper earnings limit. If either you or your partner earns over £100,000 a year, neither of you can claim Tax-Free Childcare for that tax year.",
                "The child must be 11 or under at the start of the relevant term (up to 1 September after their 11th birthday). Disabled children can use the scheme until age 16.",
                "You need to use registered childcare. Cash payments to unregistered carers, including family members who are not registered childminders, do not qualify.",
            ]},
            {"heading": "How Tax-Free Childcare compares with Universal Credit childcare support", "paragraphs": [
                "This is the most important comparison for many families. Tax-Free Childcare and Universal Credit childcare support cannot be claimed at the same time. You have to choose one route.",
                "Universal Credit childcare support reimburses up to 85% of eligible registered childcare costs, capped at £1,071.09 a month for one child or £1,836.16 for two or more children. If your childcare bill is high and your income is within UC range, the UC route can be significantly more valuable than the flat 20% TFC top-up.",
                "Tax-Free Childcare tends to be better for higher earners — particularly above the UC earnings threshold — where UC childcare support either does not apply or provides minimal help. A family spending £20,000 a year on childcare for two children gets £4,000 back through TFC rather than the lower percentage they might receive at high earnings through UC.",
                "The comparison always comes down to your specific income, childcare costs and whether you are already on Universal Credit. Running both calculators side by side — the TFC calculator and the Universal Credit calculator — gives the clearest picture.",
            ]},
            {"heading": "Free hours and Tax-Free Childcare — can you combine them?", "paragraphs": [
                "Tax-Free Childcare can generally be used alongside free hours entitlements. The government-funded free hours (15 or 30 hours depending on age and eligibility) are separate from TFC, and TFC can be used to cover costs beyond the free hours.",
                "For example, if your child has 15 free hours and attends nursery for 40 hours a week, you pay for the extra 25 hours privately. Tax-Free Childcare top-up can be applied to those privately paid hours.",
                "From September 2024, 15 hours free childcare was extended to children from 9 months old whose parents meet the working threshold. By September 2025, 30 free hours was extended to children from 9 months. That has significantly reduced the amount families need to pay privately, which in turn affects how much TFC top-up is available and how it stacks against the UC childcare route.",
            ]},
            {"heading": "How to apply and what to watch for", "paragraphs": [
                "You apply through the Government Gateway or Childcare Choices website. DWP and HMRC both need to confirm you meet the eligibility conditions, which typically takes around 24 hours online.",
                "Your eligibility is reconfirmed every three months. If you do not reconfirm, your account is paused and you lose access to the government top-up temporarily. Setting a diary reminder for the reconfirmation date matters.",
                "If you or your partner has a gap in employment — for example during maternity leave or while between jobs — there is a grace period. You can continue using Tax-Free Childcare for a return-to-work period after employment ends, though specific rules apply. Checking the official Childcare Choices site is the most reliable source during a transition.",
            ]},
        ],
        "related": ["tax-free-childcare-calculator", "universal-credit-calculator", "child-benefit-calculator"],
        "faq": [
            {"q": "How much can you save with Tax-Free Childcare per year?", "a": "Up to £2,000 per child per year (up to £4,000 for a disabled child). The government adds £2 for every £8 you pay in, up to the maximum."},
            {"q": "Can you use Tax-Free Childcare and Universal Credit childcare support together?", "a": "No. These two schemes are mutually exclusive. You must choose one or the other in any given period."},
            {"q": "What if one partner is not working?", "a": "Both partners generally need to be working and earning at least the equivalent of 16 hours at the National Minimum Wage. Some exceptions exist for partners on paid or unpaid leave and during return-to-work periods."},
            {"q": "Can I use Tax-Free Childcare with free childcare hours?", "a": "Yes. TFC can be used on top of free hours — covering the costs of hours and days beyond the free entitlement at registered providers."},
            {"q": "Does Tax-Free Childcare apply to after-school clubs and holiday camps?", "a": "Yes, as long as the provider is registered with Ofsted or the equivalent regulator. Many holiday camps, sports clubs and after-school clubs are registered and accept TFC payments."},
        ],
        "related_guides": ["benefits-for-low-income-families", "child-benefit-and-hicbc", "tax-free-childcare-top-up-examples", "universal-credit-explained"],
    },
    "what-counts-as-income-for-benefits": {
        "title": "What counts as income for benefit calculations?",
        "description": "A guide to the kinds of income that commonly affect means-tested benefits and where the rules vary between schemes.",
        "topic": "Income rules",
        "sections": [
            {"heading": "There is no single income rule for every benefit", "paragraphs": ["Means-tested support such as Universal Credit, Housing Benefit and Council Tax Reduction all look at income, but they do not always count exactly the same things in exactly the same way. Contribution-based benefits such as New Style JSA and ESA work differently again.", "That is why a general guide is useful. It helps people understand the categories before they try a calculator."]},
            {"heading": "Earnings, pensions and some benefits can reduce support", "paragraphs": ["Wages usually matter most for working-age means-tested support. Private pensions can matter more on ESA or Pension Credit. Some benefits count as income for other schemes, while disability benefits are often treated more favourably.", "If an estimate looks low, checking the income treatment is often more useful than checking the headline rate."]},
            {"heading": "Adjusted net income is a different concept", "paragraphs": ["Tax-based charges such as HICBC use adjusted net income rather than the same income definition used in most means-tested benefits. That distinction catches people out regularly.", "The site therefore keeps those pages separate rather than mixing the terms."]},
        ],
        "related": ["universal-credit-calculator", "hicbc-calculator", "pension-credit-calculator"],
        "faq": [{"q": "Does Child Benefit count as income for Universal Credit?", "a": "Not in the same way as earnings, but it can still matter through the Benefit Cap."}],
    },
    "universal-credit-rent-increase-explained": {
        "title": "Universal Credit rent increase explained",
        "description": "How a rent increase usually affects Universal Credit, Local Housing Allowance limits, social housing deductions and the Benefit Cap in 2026/27.",
        "topic": "Universal Credit housing",
        "sections": [
            {"heading": "A rent increase does not always mean Universal Credit goes up by the same amount", "paragraphs": ["This is one of the most common points of confusion for renters. Many people assume that if rent rises by £75 a month, their Universal Credit housing support will also rise by £75. In practice, that only happens if the increase still sits within the relevant housing support rules.", "For private renters, the main restriction is usually the Local Housing Allowance. For social tenants, the issue is more often the bedroom rules. For some households, the overall Benefit Cap is the real limit." ]},
            {"heading": "Private renters are usually limited by Local Housing Allowance", "paragraphs": ["If you rent privately, Universal Credit housing costs are usually capped at the Local Housing Allowance for your area and bedroom entitlement. So if your rent rises above the LHA rate, the extra amount usually has to be covered from wages, other benefits or savings rather than by Universal Credit.", "That is why two renters with the same rent increase can see very different results. One may still be below the LHA cap and get most of the increase covered. Another may already be at the cap and see no extra help at all." ]},
            {"heading": "Social renters can still lose out if the bedroom rules apply", "paragraphs": ["For social tenants, the issue is usually not Local Housing Allowance but the eligible rent after any under-occupancy deduction. If the home is treated as having one spare bedroom, the eligible amount is reduced by 14%. With two or more spare bedrooms, it is reduced by 25%.", "That means a higher rent does not always produce a matching increase in support. The rent may go up, but the deduction still applies to the eligible figure." ]},
            {"heading": "The Benefit Cap can cancel out the increase entirely", "paragraphs": ["Some households are already close to the Benefit Cap before rent rises. When that happens, a larger housing element can simply be swallowed up by the cap rather than increasing the amount paid out overall.", "This is especially relevant for larger families, single parents with high rent, and households in high-cost areas outside the cap exemption groups. If your estimate looks lower than expected, the cap is often the missing explanation." ]},
            {"heading": "What to check if there is still a shortfall", "paragraphs": ["If a rent increase leaves a gap, the most practical next step is usually to check Council Tax Reduction, Discretionary Housing Payment and any local hardship support at the same time. A small improvement across several schemes can matter more than a single rent-support check in isolation.", "It is also worth checking whether your bedroom entitlement, council area or household composition has changed, because those details can alter the housing support figure more than the rent rise itself." ]},
        ],
        "related": ["universal-credit-calculator", "housing-benefit-calculator", "benefit-cap-calculator", "council-tax-reduction-calculator"],
        "faq": [
            {"q": "Will Universal Credit always cover a rent increase?", "a": "No. Private renters are usually limited by Local Housing Allowance, and other households can still be restricted by the bedroom rules or the Benefit Cap."},
            {"q": "What if my rent is above Local Housing Allowance?", "a": "Universal Credit usually will not cover the full shortfall above the relevant LHA cap, so the extra amount normally has to be met elsewhere."},
        ],
        "related_guides": ["help-with-rent-and-council-tax", "universal-credit-explained", "how-savings-affect-benefits", "what-benefits-can-i-claim"],
    },
    "tax-free-childcare-top-up-examples": {
        "title": "Tax-Free Childcare top-up examples",
        "description": "Tax-Free Childcare amounts for 1, 2 and 3 children in 2026/27 — worked examples of the 20% top-up and when UC childcare support may be better value.",
        "topic": "Childcare examples",
        "sections": [
            {"heading": "Examples make the Tax-Free Childcare top-up easier to understand", "paragraphs": ["The headline rule sounds simple: for every £8 you pay in, the government adds £2. But families often want to know what that means over a month, a quarter or a full year once they factor in real nursery or childminder bills.", "Worked examples are useful because they show both the benefit of the top-up and the point where the annual or quarterly cap starts to matter." ]},
            {"heading": "One child example: £500 a month of eligible childcare", "paragraphs": ["A family spending £500 a month on one child would normally receive a £125 top-up, because the government adds 20% of the total childcare cost. Over a full year, that is £1,500 of government support if spending stays at that level.", "That sits below the annual cap, so the family gets the full percentage support for the whole year. For many middle-income working households, this is the cleanest example of how the scheme is meant to work." ]},
            {"heading": "Two children example: when the cap becomes more important", "paragraphs": ["If a family spends £1,800 a month across two children, the simple 20% top-up would be £450 a month. But the cap limits how much support can be added per child over the year, so families with high childcare bills need to keep an eye on the annual maximum.", "In practice, high-spending households can still save a lot through Tax-Free Childcare, but they may stop receiving extra top-up once the cap is reached. That is where the Universal Credit childcare route can become much more valuable for lower-income families." ]},
            {"heading": "When Universal Credit childcare support beats Tax-Free Childcare", "paragraphs": ["Tax-Free Childcare is often the cleaner scheme for families outside Universal Credit. But once a household is already on Universal Credit and childcare costs are high, the UC childcare element can be worth far more because it can reimburse up to 85% of eligible childcare costs.", "That is why the strongest comparison is not just to look at the TFC top-up in isolation, but to run both routes side by side if your household is anywhere near Universal Credit entitlement." ]},
            {"heading": "Use examples to understand the shape of the rules, then run your own numbers", "paragraphs": ["Examples are useful because they show the direction of travel: higher childcare bills usually mean a larger top-up until you hit the cap, while lower-income households may still do better through Universal Credit childcare support.", "After reading the examples, the next step should be to use the monthly TFC calculator and then compare it against the Universal Credit calculator if UC might still apply." ]},
        ],
        "related": ["tax-free-childcare-calculator", "tax-free-childcare-monthly-calculator", "universal-credit-calculator"],
        "faq": [
            {"q": "How much does Tax-Free Childcare add each month?", "a": "Usually 20% of the eligible childcare cost, subject to the scheme cap for each child."},
            {"q": "Why compare Tax-Free Childcare with Universal Credit?", "a": "Because households on Universal Credit with high childcare bills often get more support through the UC childcare element than through the flat TFC top-up."},
        ],
        "related_guides": ["tax-free-childcare-guide", "benefits-for-low-income-families", "child-benefit-and-hicbc", "what-benefits-can-i-claim"],
    },
    "what-pension-credit-unlocks": {
        "title": "What Pension Credit unlocks",
        "description": "Why even a small Pension Credit award can open the door to council tax help, winter support, NHS cost help and other pension-age support in 2026/27.",
        "topic": "Pension age support",
        "sections": [
            {"heading": "The weekly Pension Credit figure is often only part of the real value", "paragraphs": ["Many pensioners focus only on the weekly cash top-up and decide it is not worth the effort if the amount looks modest. That can be a costly mistake. The wider support linked to a Pension Credit award is often worth more over a year than the top-up itself.", "That is why Pension Credit is one of the strongest examples of a gateway benefit in the UK system." ]},
            {"heading": "Council tax help is often the first major gain", "paragraphs": ["One of the biggest knock-on benefits is council tax support. Pension-age Council Tax Reduction schemes are usually more generous than working-age ones, and Guarantee Credit can often lead to maximum support depending on the local rules.", "For older households on a tight fixed income, that can make a large difference to the regular monthly budget even if the Pension Credit top-up itself looks small." ]},
            {"heading": "Heating and winter support matter more than many people realise", "paragraphs": ["Pension Credit can also help unlock Winter Fuel Payment routes under the newer income-based approach in England and Wales, as well as Cold Weather Payments where the qualifying conditions are met. These are easy to overlook because they do not always arrive as part of the main weekly award.", "The wider picture is that Pension Credit can improve winter resilience, not just weekly income." ]},
            {"heading": "NHS costs, housing support and other linked help can follow", "paragraphs": ["Depending on circumstances, Pension Credit can also help with NHS costs such as dental treatment, prescriptions and sight tests, and it can interact with Housing Benefit or housing cost help for pension-age households. Some energy-related support schemes and local hardship routes also use Pension Credit as a qualifying route.", "This is why pension-age support is best checked as a package rather than a single weekly payment." ]},
            {"heading": "A small award can still be worth checking", "paragraphs": ["The practical lesson is simple: do not dismiss Pension Credit because the estimated weekly top-up looks small. If it opens access to several other schemes, the total annual value can be much larger than the headline figure suggests.", "That is especially true for pensioners who have modest private pension income or savings and assume they are automatically excluded when they are not." ]},
        ],
        "related": ["pension-credit-calculator", "winter-fuel-payment-checker", "cold-weather-payment-checker", "council-tax-reduction-calculator"],
        "faq": [
            {"q": "Can a small Pension Credit award still matter?", "a": "Yes. Even a modest award can open the door to council tax help, winter support and other linked assistance."},
            {"q": "Is Pension Credit only about the weekly payment?", "a": "No. The linked support can be just as important as the weekly top-up itself."},
        ],
        "related_guides": ["pension-credit-explained", "pension-credit-examples-for-single-pensioner", "pension-credit-examples-for-couple", "what-benefits-can-i-claim"],
    },
    "pip-daily-living-explained": {
        "title": "PIP daily living explained",
        "description": "A plain-English guide to the PIP daily living component, the activities that score points, and what usually makes evidence stronger in 2026/27.",
        "topic": "Disability support",
        "sections": [
            {"heading": "The daily living component is about everyday functional difficulty", "paragraphs": ["The PIP daily living component looks at whether a health condition or disability makes everyday tasks difficult enough to score points. It is not about the diagnosis on its own. The focus is on the real-world impact on preparing food, washing, dressing, medication, communication, social contact and budgeting.", "That is why many claims turn on detailed examples of what happens in ordinary daily routines rather than on a medical label by itself." ]},
            {"heading": "Eight points and twelve points are the important thresholds", "paragraphs": ["If the descriptors that apply to you add up to 8 points in the daily living component, that usually means the standard rate. If they add up to 12 points, that usually means the enhanced rate.", "The practical question is not whether one activity sounds difficult in general terms, but which descriptor best matches what you can do safely, repeatedly and in a reasonable time." ]},
            {"heading": "The strongest evidence usually shows functional impact clearly", "paragraphs": ["Useful evidence for daily living issues often includes care plans, letters explaining help with preparing food or medication, occupational therapy notes, GP records and a clear symptom diary. The best evidence usually explains what help is needed, how often, and what happens when the person tries to do the activity alone.", "That is more persuasive than simply stating that a condition exists." ]},
            {"heading": "Daily living can matter beyond the weekly PIP payment", "paragraphs": ["A daily living award can change other parts of the benefits picture. It may support a carer's claim, help with passported support, and in some households affect whether the Benefit Cap applies.", "That is why a daily living guide is useful even for people who already know the basic weekly rate. The wider knock-on effects matter too." ]},
        ],
        "related": ["pip-eligibility-checker", "benefit-cap-calculator", "esa-calculator"],
        "faq": [
            {"q": "What does PIP daily living look at?", "a": "It looks at how your condition affects ordinary daily tasks such as preparing food, washing, dressing, managing treatments, communication and budgeting."},
            {"q": "How many points do you need for daily living?", "a": "Usually 8 points for standard rate and 12 points for enhanced rate in the daily living component."},
        ],
        "related_guides": ["pip-explained-simply", "pip-points-explained", "pip-mobility-explained", "esa-vs-universal-credit"],
    },
    "pip-mobility-explained": {
        "title": "PIP mobility explained",
        "description": "A plain-English guide to the PIP mobility component, how moving around and planning journeys are assessed, and what the main scoring issues are in 2026/27.",
        "topic": "Disability support",
        "sections": [
            {"heading": "The mobility component is about more than distance alone", "paragraphs": ["People often think the mobility component is only about how far someone can physically walk. That is only part of it. The PIP mobility component also covers planning and following journeys, which is especially relevant where mental health conditions, cognitive impairment or sensory issues affect travel.", "This is why someone can struggle strongly with mobility descriptors even if the issue is not a straightforward physical walking problem." ]},
            {"heading": "Moving around and planning journeys are scored separately", "paragraphs": ["The component uses two activities: planning and following journeys, and moving around. Points are awarded under the descriptor that best reflects what you can do reliably. For some people the stronger score comes from physical difficulty. For others it comes from overwhelming psychological distress, sensory impairment or the need for supervision outdoors.", "The overall mobility score then determines whether the standard or enhanced rate applies." ]},
            {"heading": "Reliability and repeatability still matter", "paragraphs": ["As with the daily living component, the key issue is not whether you can complete a task once on a good day. The test is whether you can do it safely, repeatedly, to an acceptable standard and within a reasonable time on most days.", "Many mobility disputes turn on exactly this point, especially when pain, fatigue, dizziness or distress mean that a distance is technically possible once but not reliably." ]},
            {"heading": "Mobility awards can unlock wider support", "paragraphs": ["A mobility award can matter well beyond the weekly payment. Enhanced mobility can link to the Motability scheme, Blue Badge routes and vehicle tax support. Even standard mobility can be relevant for practical travel help and evidence of need in other systems.", "That makes the mobility component important both financially and practically for day-to-day independence." ]},
        ],
        "related": ["pip-eligibility-checker", "benefit-cap-calculator", "ssp-calculator"],
        "faq": [
            {"q": "Is PIP mobility only about walking distance?", "a": "No. It also covers planning and following journeys, including some mental health and sensory-related barriers to travel."},
            {"q": "Can a mobility award help with other support?", "a": "Yes. Enhanced mobility can help with schemes such as Motability and can matter for wider practical support."},
        ],
        "related_guides": ["pip-explained-simply", "pip-points-explained", "pip-daily-living-explained", "what-benefits-can-i-claim"],
    },
    "universal-credit-capital-disregards": {
        "title": "Universal Credit capital disregards explained",
        "description": "UC capital disregards explained 2026/27: which assets count, what is ignored, and how the £6,000 and £16,000 savings thresholds affect your award.",
        "topic": "Universal Credit",
        "sections": [
            {"heading": "What 'capital' means in Universal Credit", "paragraphs": [
                "In Universal Credit, 'capital' means money and assets that could be converted into cash. That includes savings accounts, current account balances, cash, ISAs, Premium Bonds, investments and shares. It does not include your main home — that is fully disregarded regardless of value.",
                "The DWP adds up everything that counts as capital to produce a total figure. That total then determines whether and how much your UC award is reduced. The rules are the same regardless of whether the capital is held by you or your partner.",
            ]},
            {"heading": "The lower disregard: below £6,000 is ignored entirely", "paragraphs": [
                "If your total capital is below £6,000, Universal Credit ignores it completely. You do not need to declare it on your award or worry about it reducing your payments. This lower threshold is sometimes called the 'lower capital disregard' and it applies in 2026/27 as it has since UC launched.",
                "Assets that are disregarded in full regardless of the amount include: your main home and any property you are taking steps to sell, personal possessions, the surrender value of a life insurance policy, business assets if you are self-employed, and money received as a compensation payment that has been disregarded for 12 months.",
            ]},
            {"heading": "Between £6,000 and £16,000: tariff income reduces your award", "paragraphs": [
                "Once capital goes above £6,000, UC applies a 'tariff income' calculation. For every complete £250 above the £6,000 threshold, the system assumes you receive £4.35 of monthly income. This assumed income reduces your UC award even if the capital earns nothing.",
                "Example: savings of £9,500 means £3,500 above £6,000 — that is fourteen complete £250 bands, producing £60.90 of assumed monthly income. Your UC award is reduced by that £60.90 whether or not the savings actually generate any interest.",
                "This is sometimes called the 'upper capital disregard zone' or 'tariff income zone'. The rate has not changed since UC launched: it remains £4.35 per £250 band.",
            ]},
            {"heading": "At £16,000 and above: no UC entitlement", "paragraphs": [
                "If total capital reaches £16,000 or more, you are not entitled to Universal Credit at all. This is the hard upper capital limit, sometimes called the 'upper capital disregard'. It does not matter how low your income is or how high your rent is — if combined capital exceeds £16,000, a UC claim returns nil.",
                "Capital can fluctuate, so if savings drop below £16,000 again, entitlement can resume. A change of circumstances should be reported to DWP.",
            ]},
            {"heading": "Capital disregards and Pension Credit — a different set of rules", "paragraphs": [
                "Pension Credit uses different capital rules. There is no upper capital limit equivalent to UC's £16,000 stop-point. Savings under £10,000 are fully disregarded. Above £10,000 a similar tariff income approach applies, but the thresholds and rates differ. The UC capital disregard rules described here apply to working-age claimants only.",
            ]},
        ],
        "related": ["universal-credit-calculator", "housing-benefit-calculator"],
        "faq": [
            {"q": "Does my house count as capital for Universal Credit?", "a": "No. Your main home is fully disregarded and does not count as capital for UC purposes, regardless of its value."},
            {"q": "What is the lower capital disregard for Universal Credit in 2026/27?", "a": "Capital below £6,000 is ignored entirely. It has no effect on your UC award."},
            {"q": "How does the tariff income rule work between £6,000 and £16,000?", "a": "For every complete £250 above £6,000, DWP assumes you receive £4.35 of monthly income. This reduces your UC award even if the savings earn nothing."},
            {"q": "What happens to UC if savings go above £16,000?", "a": "You are not entitled to Universal Credit at all if total capital is £16,000 or more. A claim returns nil until capital falls below that level."},
            {"q": "Does a compensation payment count as capital?", "a": "Not immediately. A personal injury compensation payment is disregarded for 12 months from receipt. After that it can be counted as capital."},
        ],
        "related_guides": ["how-savings-affect-benefits", "universal-credit-explained", "what-benefits-can-i-claim"],
    },
    "benefits-for-working-families": {
        "title": "Benefits for working families 2026",
        "description": "Benefits for working families 2026/27: UC work allowance, Child Benefit, childcare support, Free School Meals and council tax help explained.",
        "topic": "Families",
        "sections": [
            {"heading": "Working does not end benefit entitlement for families", "paragraphs": [
                "A common misconception is that taking a job or increasing hours stops all benefit support. For families, that is rarely true. Universal Credit, Child Benefit, childcare support and Council Tax Reduction can all remain in payment as earnings rise — the support tapers gradually rather than switching off sharply.",
                "Understanding the work allowance and taper rate is the key to seeing how much support a working family actually keeps.",
            ]},
            {"heading": "The work allowance: earnings a working family keeps in full", "paragraphs": [
                "If a UC household includes a child or a Limited Capability for Work element, it receives a work allowance — a band of earnings that are completely ignored before the 55p-in-the-pound taper applies. In 2026/27 the work allowance is £673 a month where no housing element is in payment, or £404 a month where rent support is included.",
                "A working single parent earning £800 a month with no housing support keeps that £800 entirely — their work allowance is £673 and their UC is only tapered on the £127 above it, reducing the award by about £70. That is still meaningful UC income on top of their wages.",
            ]},
            {"heading": "Child Benefit for working families — always worth claiming", "paragraphs": [
                "Child Benefit is entirely separate from UC and is not means tested at the point of claim. In 2026/27 it pays £27.05 a week for the first child and £17.90 for each subsequent child. A working family with two children receives around £2,596 a year in Child Benefit regardless of income — unless either parent earns above £60,000, at which point the High Income Child Benefit Charge starts to claw it back.",
                "From April 2026, the two-child limit on UC child elements has been removed, meaning working families with three or more children also qualify for a child element for each child in Universal Credit.",
            ]},
            {"heading": "Childcare costs for working families", "paragraphs": [
                "UC childcare support reimburses up to 85% of registered childcare costs, capped at £1,071.09 a month for one child or £1,836.16 for two or more. This can make a substantial difference to the net cost of working. The childcare element must be claimed within 3 months of paying the costs.",
                "Free childcare hours (15 or 30 depending on the child's age and eligibility) run alongside the UC childcare element and can reduce the total childcare bill further. Working families who are not on UC may prefer Tax-Free Childcare instead, which adds 20p for every 80p spent, up to £2,000 a year per child.",
            ]},
            {"heading": "Free School Meals, council tax help and what else to check", "paragraphs": [
                "Working families on UC can qualify for Free School Meals if annual take-home pay is below £7,400, which is the earnings threshold for the UC household. Families should also check Council Tax Reduction — a working family on a modest income can still receive a substantial council tax reduction from their local council, applied separately from Universal Credit.",
                "Sure Start Maternity Grant (£500 one-off payment for a first child) is available to working families on UC. Healthy Start food and vitamin support is available for pregnant people and those with children under 4 who receive qualifying benefits, including UC.",
            ]},
        ],
        "related": ["universal-credit-calculator", "child-benefit-calculator", "tax-free-childcare-calculator", "free-school-meals-checker"],
        "faq": [
            {"q": "Can a working family still get Universal Credit in 2026?", "a": "Yes. A working family with children receives a work allowance, meaning the first £404 or £673 of monthly earnings are ignored before any taper applies. Many working families continue to receive meaningful UC top-ups."},
            {"q": "What is the work allowance for a working family with children in 2026/27?", "a": "£673 a month if no housing costs are included in the UC award, or £404 a month if the housing element is also in payment."},
            {"q": "Does working affect Child Benefit?", "a": "Working itself does not affect Child Benefit. Only income above £60,000 triggers the High Income Child Benefit Charge, which gradually reduces the benefit between £60,000 and £80,000."},
            {"q": "What childcare support is available for working families in 2026?", "a": "UC childcare support covers up to 85% of registered childcare costs (capped at £1,071.09/month for one child). Free childcare hours can reduce costs further. Tax-Free Childcare is an alternative for those not on UC."},
            {"q": "What benefits do working families miss most?", "a": "Council Tax Reduction, Free School Meals and the UC childcare element are commonly missed by working families who assume they earn too much to qualify. The earnings thresholds are often higher than people expect."},
        ],
        "related_guides": ["benefits-for-low-income-families", "universal-credit-explained", "tax-free-childcare-guide"],
    },
}

SITUATION_PAGES: Dict[str, Dict[str, Any]] = {
    "benefits-for-single-parents": {
        "slug": "benefits-for-single-parents",
        "title": "Benefits for single parents",
        "description": "Single parent benefits 2026/27: Universal Credit work allowance, Child Benefit, childcare support and council tax help — calculator and guide.",
        "intro": "Single parents have access to a number of specific support routes in the UK benefits system. Some are the same as for any low-income household, but the way entitlement is calculated often works differently when there is only one adult. This guide covers the main routes and explains where single parents tend to get the most meaningful support.",
        "sections": [
            {
                "heading": "Universal Credit for single parents",
                "content": "Universal Credit is usually the most important means-tested benefit for a working single parent. Single parents receive a higher standard allowance than a single adult without children, plus a child element for each eligible child (£303.94 per child per month in 2026/27). The work allowance — the amount you can earn before the 55% taper kicks in — is also available to single parents because of the child element. In 2026/27 the work allowance is £673 a month where no housing element is in payment, or £404 where housing support is included. That means a working single parent keeps more of each pound they earn than a childless adult on UC.",
            },
            {
                "heading": "Child Benefit — claim even if income is higher",
                "content": "Child Benefit is not means tested at the point of claim. In 2026/27 it pays £27.05 a week for the first child and £17.90 for each additional child. For a single parent with two children, that is £44.95 a week or around £2,337 a year. Single parents earning above £60,000 may face the High Income Child Benefit Charge, but most single-parent households are well below that threshold. Claiming Child Benefit also protects National Insurance credits during periods when work is limited, which matters for the long-term State Pension position.",
            },
            {
                "heading": "Help with childcare costs",
                "content": "Childcare is often the biggest financial pressure for single parents. Universal Credit can reimburse up to 85% of eligible registered childcare costs, capped at £1,071.09 a month for one child or £1,836.16 for two or more. Tax-Free Childcare is an alternative for those not claiming UC, adding £2 for every £8 spent, up to £2,000 per child per year. Free childcare hours (15 or 30 hours depending on age and eligibility) apply on top of either scheme. Single parents cannot usually use both UC childcare support and Tax-Free Childcare at the same time.",
            },
            {
                "heading": "Council tax, rent and the benefit cap",
                "content": "Single parents should check Council Tax Reduction because the scheme can reduce the bill significantly, especially where income is low. The 25% single-person discount also applies to single-adult households, stacking with means-tested reduction in many local schemes. On rent support, single parents on UC can include a housing costs element, and local housing allowance covers an appropriate bedroom entitlement for the children. The Benefit Cap applies to single parents — the outside-London cap is £1,835 a month for families, which can limit support for households with higher rent or multiple children.",
            },
        ],
        "related_calculators": ["universal-credit-calculator", "child-benefit-calculator", "tax-free-childcare-calculator", "council-tax-reduction-calculator", "benefit-cap-calculator"],
        "related_guides": ["what-benefits-can-i-claim", "benefits-for-low-income-families", "universal-credit-explained", "tax-free-childcare-guide"],
    },
    "benefits-if-you-cannot-work": {
        "slug": "benefits-if-you-cannot-work",
        "title": "Benefits if you cannot work",
        "description": "A guide to UK benefits and support routes for people who are unable to work due to illness, disability or a health condition.",
        "intro": "If a health condition or disability prevents you from working, several separate UK support systems may apply at the same time. Understanding which ones to check — and in what order — is the most practical starting point. This guide covers the main routes for people who are off sick, living with a long-term condition or managing a disability.",
        "sections": [
            {
                "heading": "Statutory Sick Pay and the transition to ESA",
                "content": "If you are an employee, Statutory Sick Pay is normally the first support in the chain. In 2026/27 SSP pays the lower of £123.25 a week or 80% of average weekly earnings, for up to 28 weeks. When SSP ends or is too low, New Style ESA becomes relevant if you have a strong National Insurance record. ESA pays up to £95.55 a week for the work-related activity group or £145.90 for the support group. Private pension income above £85 a week reduces the ESA amount. Universal Credit can also be claimed alongside or instead of ESA for broader household support.",
            },
            {
                "heading": "PIP — the main non-means-tested disability support",
                "content": "Personal Independence Payment (PIP) is the most significant disability benefit for working-age adults. It is entirely non-means-tested — income, savings and employment status have no effect on entitlement. PIP has two components: daily living (up to £114.60 a week at the enhanced rate in 2026/27) and mobility (up to £80.00 a week). The two components can be paid together, giving a maximum of £194.60 a week. PIP is assessed through descriptors and evidence rather than a simple yes/no eligibility test, and many claims benefit significantly from strong supporting evidence such as GP letters, care plans and symptom diaries.",
            },
            {
                "heading": "Universal Credit health element (LCWRA)",
                "content": "Universal Credit includes a Limited Capability for Work-Related Activity (LCWRA) element for people with a health condition that significantly affects their ability to work. In 2026/27 this adds £429.80 a month to the UC award — on top of the standard allowance and any other elements. Receiving PIP does not automatically trigger the LCWRA element, and the work capability assessment is separate. However, PIP exempts a household from the Benefit Cap, which can be important when overall benefit levels are high.",
            },
            {
                "heading": "Council tax, passported support and what to check next",
                "content": "People who cannot work often face wider financial pressure beyond the headline disability payments. Council Tax Reduction may significantly reduce a council tax bill, especially where income is UC-based. Cold Weather Payments are automatic for those on qualifying benefits. Pension Credit recipients who are also disabled may qualify for the Severe Disability Addition. The Warm Home Discount and similar energy-linked support can also apply depending on benefit status. Checking the full picture — not just the disability-linked payments — usually reveals meaningful additional support.",
            },
        ],
        "related_calculators": ["pip-eligibility-checker", "esa-calculator", "ssp-calculator", "universal-credit-calculator", "council-tax-reduction-calculator"],
        "related_guides": ["pip-explained-simply", "esa-vs-universal-credit", "what-benefits-can-i-claim"],
    },
    "benefits-for-renters": {
        "slug": "benefits-for-renters",
        "title": "Benefits for renters",
        "description": "UK rent and housing support: Universal Credit housing costs, Housing Benefit and Council Tax Reduction for private and social renters. 2026/27.",
        "intro": "Renters can access housing support through several different routes depending on their age, employment status, landlord type and income. The main system has shifted significantly since 2013, with most new working-age housing support now going through Universal Credit rather than Housing Benefit. This guide explains how the current system works and which pages to check.",
        "sections": [
            {
                "heading": "Universal Credit housing costs element",
                "content": "For most working-age renters, help with rent now comes through the housing costs element of Universal Credit. For private renters, the amount is capped at the Local Housing Allowance rate for your area — the 30th percentile of local rents for the relevant bedroom size. That can leave a gap between LHA and actual rent, which the claimant must cover from other income. Social renters receive a notional rent figure subject to bedroom rules. If you have more bedrooms than the social size criteria allow, a deduction of 14% (one spare bedroom) or 25% (two or more spare bedrooms) typically applies.",
            },
            {
                "heading": "Housing Benefit — mainly for pension-age cases now",
                "content": "Housing Benefit is still payable in several situations: for pension-age claimants, some supported accommodation cases, and some temporary accommodation situations. For working-age households making a new claim, Universal Credit is the expected route. Housing Benefit and Universal Credit housing costs are not the same system, and you cannot normally claim both. If you are already on Housing Benefit and have not been migrated to UC, you may still be on the legacy route — check whether a managed migration notice has been issued.",
            },
            {
                "heading": "Council Tax Reduction alongside rent support",
                "content": "Rent support and council tax support are separate. Many renters apply for Universal Credit housing costs and do not realise they also need to apply separately for Council Tax Reduction. CTR is run locally, and rules vary by council. On a low income, the reduction can be substantial — sometimes covering the full bill. A single adult also qualifies for the 25% single-person discount, which stacks with CTR rather than replacing it. If you are on a means-tested benefit, CTR can often be awarded at a higher rate.",
            },
            {
                "heading": "Where renters often lose out and what to check",
                "content": "The most common gap for renters is the difference between LHA and actual market rent. Discretionary Housing Payments from the local council can sometimes bridge that gap temporarily. The Benefit Cap can also reduce the effective housing support for households with high rent and multiple other benefits — particularly for larger families in high-rent areas. It is worth checking whether the cap applies before assuming the UC housing figure covers the full rent shortfall.",
            },
        ],
        "related_calculators": ["universal-credit-calculator", "housing-benefit-calculator", "council-tax-reduction-calculator", "benefit-cap-calculator"],
        "related_guides": ["help-with-rent-and-council-tax", "universal-credit-explained", "how-savings-affect-benefits"],
    },
    "benefits-for-pensioners": {
        "slug": "benefits-for-pensioners",
        "title": "Benefits for pensioners",
        "description": "Pensioner benefits 2026/27: Pension Credit, housing benefit, council tax help, Attendance Allowance and winter payments — calculator and guide.",
        "intro": "The UK benefits system works differently once you reach State Pension age. Pension Credit replaces Universal Credit as the main means-tested top-up, and a range of additional support — from council tax reduction to heating help — can be triggered by a Pension Credit award. This guide covers the main pension-age support routes and explains why they are often under-claimed.",
        "sections": [
            {
                "heading": "Pension Credit — the main means-tested top-up",
                "content": "Pension Credit tops up weekly income to a guaranteed minimum — £238.00 a week for a single person and £363.25 for a couple in 2026/27. It has two parts: Guarantee Credit (the main top-up) and Savings Credit (a legacy element for those who reached pension age before April 2016). Around 880,000 eligible households are not claiming it, often because of incorrect assumptions about savings or home ownership. Savings under £10,000 are fully disregarded, and there is no hard upper savings limit equivalent to Universal Credit's £16,000 stop-point.",
            },
            {
                "heading": "What Pension Credit unlocks — the passported support",
                "content": "Even a small Pension Credit award can trigger a wider package of support. This includes maximum Council Tax Reduction, full Housing Benefit where still applicable, Cold Weather Payments, NHS cost help (free prescriptions, dental treatment and sight tests), and the Warm Home Discount. In England and Wales, Pension Credit receipt is also one of the qualifying routes for the Winter Fuel Payment under the current income-based eligibility rules. Together, the passported support can be worth significantly more than the weekly cash top-up alone.",
            },
            {
                "heading": "Winter and heating support",
                "content": "Winter Fuel Payment in England and Wales is now income-related. In 2026/27, the payment is generally £200 or £300 depending on age and circumstances, but it is subject to a £35,000 personal income threshold. Pension Credit is one of the key qualifying routes. Cold Weather Payments of £25 are automatic for each triggered 7-day cold spell during winter. Scotland uses Pension Age Winter Heating Payment instead. The Warm Home Discount — a rebate on electricity bills — is available to some pension-age households through energy suppliers.",
            },
            {
                "heading": "Disability support and council tax at pension age",
                "content": "PIP is for people of working age up to State Pension age. Once you reach State Pension age, you cannot make a new PIP claim — but existing awards can continue. Attendance Allowance is the disability benefit for people over State Pension age. It pays £73.90 (lower rate) or £110.40 (higher rate) a week and is non-means-tested. Council Tax Reduction for pension-age households is often on more generous terms than working-age schemes, and some councils still use the pre-2013 system for pensioners, which can provide fuller protection.",
            },
        ],
        "related_calculators": ["pension-credit-calculator", "winter-fuel-payment-checker", "cold-weather-payment-checker", "council-tax-reduction-calculator"],
        "related_guides": ["pension-credit-explained", "what-benefits-can-i-claim", "how-savings-affect-benefits"],
    },
    "benefits-in-northern-ireland": {
        "slug": "benefits-in-northern-ireland",
        "title": "Benefits calculator for Northern Ireland 2026/27",
        "description": "Benefits calculator for Northern Ireland 2026/27 — Universal Credit, Child Benefit, PIP, Pension Credit and housing support. Managed by DfC with mostly GB-matching rates.",
        "intro": "The benefits system in Northern Ireland is close to Great Britain on core rates, but the administration, domestic rates system and some local schemes are different. Universal Credit in Northern Ireland is run by the Department for Communities (DfC), not DWP. The calculators on this site use the core published rates that also apply to Northern Ireland, while the guidance below flags where Northern Ireland users should expect a different route or official contact point.",
        "sections": [
            {
                "heading": "Universal Credit in Northern Ireland",
                "content": "Universal Credit applies in Northern Ireland and uses the same rates as the rest of the UK. For 2026/27, the standard allowance is £424.90 a month for a single person aged 25 or over, or £666.97 for a couple. Child elements, housing costs, work allowances and the 55% earnings taper all work on identical rules. Claims in Northern Ireland go through the DfC (Department for Communities) rather than DWP, but the rates and calculation method are the same.",
            },
            {
                "heading": "Child Benefit and other non-means-tested support",
                "content": "Child Benefit rates are identical across the UK including Northern Ireland: £27.05 a week for the first child and £17.90 for each subsequent child in 2026/27. PIP rates also apply in Northern Ireland for working-age adults — the daily living and mobility components use the same weekly rates as Great Britain. Attendance Allowance for pension-age adults likewise uses the same rates.",
            },
            {
                "heading": "Housing support and council tax equivalent",
                "content": "Northern Ireland does not have council tax — it uses domestic rates instead. There is no direct equivalent to Council Tax Reduction, though Housing Benefit and UC housing costs elements apply. Rate rebates are available through Housing Benefit for eligible households. For private renters, Local Housing Allowance rules apply in the same way as Great Britain.",
            },
            {
                "heading": "Benefits that differ or do not apply in Northern Ireland",
                "content": "Some England-specific schemes do not apply in Northern Ireland, including some free childcare hour entitlements (NI has a separate scheme) and some devolved top-up payments. The Warm Home Discount operates differently. Winter Fuel Payment for pensioners uses Great Britain eligibility criteria, but Cold Weather Payments operate under the same trigger mechanism. For detailed NI-specific information, the NI Direct website is the official resource alongside DfC.",
            },
        ],
        "related_calculators": ["universal-credit-calculator", "child-benefit-calculator", "pip-eligibility-checker", "housing-benefit-calculator", "pension-credit-calculator"],
        "related_guides": ["universal-credit-explained", "what-benefits-can-i-claim", "benefits-for-single-parents", "benefits-for-pensioners"],
    },
    "benefits-for-low-income-families": {
        "slug": "benefits-for-low-income-families",
        "title": "Benefits for low-income families",
        "description": "A guide to UK support for families on a low income — Universal Credit, Child Benefit, childcare help, Free School Meals, Healthy Start and more.",
        "intro": "Low-income families can access several layers of UK support at the same time. The biggest is usually Universal Credit, but Child Benefit, school support, childcare help and local authority support all sit alongside it. Understanding which pieces stack together — and which are mutually exclusive — gives the clearest picture of what a household can actually receive.",
        "sections": [
            {
                "heading": "Universal Credit for families — what drives the amount",
                "content": "Universal Credit for a family is built from several parts: the standard allowance, a child element of £303.94 per month for each eligible child (from April 2026 with no two-child limit), a housing costs element based on rent, and childcare support for registered childcare costs. The 55% earnings taper reduces the award as income rises, but a work allowance means working families keep a meaningful share of what they earn. The benefit cap can limit the total where rent is high and the family is large.",
            },
            {
                "heading": "Child Benefit — always claim it",
                "content": "Child Benefit sits entirely outside Universal Credit and should be claimed separately. In 2026/27 it pays £27.05 a week for the first child and £17.90 for each subsequent child. For a family with three children, that is £62.85 a week. Child Benefit is not means tested at the point of claim — it is available to all families regardless of income — though the High Income Child Benefit Charge applies where either parent has adjusted net income above £60,000. For most low-income families, there is no charge and the full amount is kept.",
            },
            {
                "heading": "Childcare, school meals and food support",
                "content": "Free School Meals are available in England for children whose parent is on Universal Credit with take-home income below £7,400 a year, or through other qualifying benefits, and universally for reception to year 2 pupils. Healthy Start provides a prepaid card for food and vitamins for eligible pregnant people and those with children under 4. Tax-Free Childcare adds a government top-up of up to £2,000 per child per year on registered childcare costs — but cannot be used at the same time as the UC childcare element.",
            },
            {
                "heading": "Council tax, maternity support and what to check next",
                "content": "Council Tax Reduction can reduce or eliminate a council tax bill for low-income families, and the application is separate from Universal Credit. Families expecting a baby should also check Sure Start Maternity Grant (a one-off £500 payment for eligible households with a first child) and whether Statutory Maternity Pay or Maternity Allowance applies. The maternity pay calculator and the Sure Start checker are designed to make those questions quick to answer.",
            },
        ],
        "related_calculators": ["universal-credit-calculator", "child-benefit-calculator", "free-school-meals-checker", "tax-free-childcare-calculator", "council-tax-reduction-calculator"],
        "related_guides": ["benefits-for-low-income-families", "universal-credit-explained", "tax-free-childcare-guide"],
    },
    "benefits-for-working-families": {
        "slug": "benefits-for-working-families",
        "title": "Benefits for working families 2026/27",
        "description": "Benefits for working families 2026/27: Universal Credit work allowance, Child Benefit rates, childcare support, Free School Meals and council tax help.",
        "intro": "Working does not end benefit entitlement for families. Universal Credit tapers gradually as earnings rise, and several other schemes — Child Benefit, Free School Meals, childcare support and Council Tax Reduction — remain available well into moderate incomes. This guide is built around the search most working parents actually have: what can a working family still claim in the UK in 2026/27, and what changes first as wages rise.",
        "sections": [
            {
                "heading": "The work allowance: earnings a working family keeps in full",
                "content": "If a UC household includes a child or a Limited Capability for Work element, it receives a work allowance — a band of earnings ignored completely before the 55p-in-the-pound taper applies. In 2026/27 the work allowance is £673 a month where no housing element is in payment, or £404 a month where rent support is also included. A working single parent earning £800 a month with no housing element keeps that income fully — UC is only tapered on the £127 above the work allowance, reducing the award by around £70. Meaningful UC income continues on top of their wages.",
            },
            {
                "heading": "Child Benefit — claim regardless of income",
                "content": "Child Benefit is entirely separate from UC and not means tested at the point of claim. In 2026/27 it pays £27.05 a week for the first child and £17.90 for each subsequent child — around £2,596 a year for a family with two children. From April 2026, the two-child limit on UC child elements was removed: all eligible dependent children now generate a child element (£303.94 per month each). The High Income Child Benefit Charge only starts at £60,000 adjusted net income, so most working families keep the full award.",
            },
            {
                "heading": "Childcare and Free School Meals",
                "content": "UC childcare support reimburses up to 85% of registered childcare costs, capped at £1,071.09 a month for one child or £1,836.16 for two or more. Free School Meals are available if annual UC take-home income is below £7,400 — a threshold many part-time or lower-earning working families fall inside. Tax-Free Childcare (20p per 80p spent, up to £2,000 per child per year) is an alternative for families not on UC who work at least 16 hours per week at minimum wage.",
            },
            {
                "heading": "Council Tax Reduction and what else to check",
                "content": "Council Tax Reduction is applied separately from Universal Credit and is commonly missed by working families who assume they earn too much. Local authority CTR schemes can cover a substantial proportion of the bill for households with moderate incomes. Working families should also check Sure Start Maternity Grant (£500 one-off for eligible households expecting a first child) and whether the Benefit Cap applies — the £1,835/month outside-London cap affects larger families with high rent even while working.",
            },
        ],
        "related_calculators": ["universal-credit-calculator", "child-benefit-calculator", "tax-free-childcare-calculator", "free-school-meals-checker", "council-tax-reduction-calculator", "benefit-cap-calculator"],
        "related_guides": ["benefits-for-working-families", "universal-credit-explained", "tax-free-childcare-guide"],
    },
}

SCENARIO_PAGES: Dict[str, Dict[str, Any]] = {
    "what-happens-if-my-savings-increase": {
        "slug": "what-happens-if-my-savings-increase",
        "title": "What happens to Universal Credit if my savings increase?",
        "description": "Understand the £6,000 and £16,000 UC savings thresholds, how tariff income reduces your award, and what happens at the upper limit.",
        "intro": "Savings have two distinct effects on Universal Credit depending on how much you have. Below £6,000 they have no effect at all. Between £6,000 and £16,000 they generate assumed monthly income that reduces your award. At £16,000 or above, you normally cannot claim UC at all. This page explains the mechanism and gives practical examples.",
        "sections": [
            {
                "heading": "Below £6,000 — nothing changes",
                "content": "If your total savings and capital are below £6,000, Universal Credit ignores them entirely. It does not matter whether those savings are in a current account, a savings account, Premium Bonds or an ISA — as long as the total is under £6,000, they do not reduce your award. Your main home is also disregarded and does not count as capital.",
            },
            {
                "heading": "£6,000 to £16,000 — the tariff income rule",
                "content": "Once total capital exceeds £6,000, DWP applies a tariff income calculation. For every complete £250 above £6,000, the system adds £4.35 to your assumed monthly income. So savings of £8,000 generate £8,000 minus £6,000 = £2,000 excess. That is eight complete £250 bands, producing £34.80 a month of assumed income. Your UC award is then reduced by £34.80 — regardless of what the savings actually earn. Savings of £10,000 would produce £16,000 excess, which is sixteen bands at £4.35 = £69.60 a month of reduction.",
            },
            {
                "heading": "At £16,000 — eligibility stops",
                "content": "Once capital reaches £16,000 (or more), you are not normally eligible for a standard Universal Credit award. This applies to combined savings for couples. If savings fluctuate around the threshold — for example if you receive a redundancy payment — it is worth checking the exact position before making or renewing a claim. Some types of capital are disregarded, including certain compensation payments and money set aside for specific care needs.",
            },
            {
                "heading": "Deliberate deprivation — what not to do",
                "content": "DWP can treat you as still holding savings you have deliberately spent or transferred to get below a threshold. Called deprivation of capital, this rule means that spending down savings just before a claim can lead to a notional capital figure being used even after the money is gone. Normal spending on living costs, rent and bills is unlikely to trigger this, but large cash gifts to family members or unusual spending just before a claim can be questioned.",
            },
        ],
        "related_calculators": ["savings-impact-calculator", "universal-credit-calculator"],
        "related_guides": ["how-savings-affect-benefits", "universal-credit-explained"],
    },
    "what-happens-if-i-work-more-hours": {
        "slug": "what-happens-if-i-work-more-hours",
        "title": "What happens to Universal Credit if I work more hours?",
        "description": "Understand the work allowance and 55% earnings taper — and see a real example of how earnings of £1,200 versus £1,400 affect the UC award.",
        "intro": "One of the most common questions about Universal Credit is whether it is worth earning more, given that UC reduces as income rises. The answer is almost always yes — but the mechanics are worth understanding. The 55% taper means you keep 45p from every extra pound earned above your work allowance. This page explains how it works and shows a practical example.",
        "sections": [
            {
                "heading": "The work allowance — earnings that are fully disregarded",
                "content": "If your household includes children or a limited capability for work or work-related activity element, you have a work allowance. In 2026/27 this is £673 a month if no housing costs element is in payment, or £404 a month where housing support is included. Earnings up to the work allowance are fully disregarded — they do not reduce your UC at all. The taper only applies above that threshold.",
            },
            {
                "heading": "The 55% taper — what happens above the work allowance",
                "content": "For every £1 of net earnings above the work allowance, UC is reduced by 55p. This means you keep 45p from each additional pound earned. For households without a work allowance (typically couples without children or a qualifying health condition), the taper starts from the first pound of net earnings. There is no earnings limit at which UC cuts off entirely — the award simply reduces until it reaches zero.",
            },
            {
                "heading": "Example: earnings of £1,200 versus £1,400 a month",
                "content": "Suppose a single parent with a housing element has a work allowance of £404. At £1,200 earnings, the taxable amount is £796. The UC reduction is 55% of £796 = £437.80. At £1,400 earnings, the taxable amount is £996, giving a UC reduction of £547.80 — £110 more. But gross earnings increased by £200, so the net position is £200 earned minus £110 UC reduction = £90 better off in total. Working more always improves the overall financial position — the taper slows the gain but does not eliminate it.",
            },
            {
                "heading": "Reporting changes and the assessment period",
                "content": "Universal Credit is assessed monthly based on your earnings in the preceding assessment period. HMRC payroll data feeds directly into most UC claims for employed workers, so earnings changes are usually picked up automatically. If you are self-employed, you report monthly through your UC journal. Either way, changes in earnings affect the following month's payment rather than the current one.",
            },
        ],
        "related_calculators": ["earnings-impact-calculator", "universal-credit-calculator"],
        "related_guides": ["universal-credit-explained", "what-counts-as-income-for-benefits"],
    },
    "what-happens-if-my-partner-moves-in": {
        "slug": "what-happens-if-my-partner-moves-in",
        "title": "What happens to my benefits if my partner moves in?",
        "description": "Understand how a partner moving in changes Universal Credit, Child Benefit, council tax and other means-tested support — and what to report and when.",
        "intro": "When a partner moves in, you are required to report the change to DWP within one month. The household type change affects Universal Credit significantly — both the standard allowance and the way income is assessed will change. This page explains what happens in practice.",
        "sections": [
            {
                "heading": "Universal Credit moves to a joint claim",
                "content": "When you form a couple, Universal Credit must be claimed jointly. The joint standard allowance for a couple where both are 25 or over is £666.97 a month in 2026/27 — compared to £424.90 for a single person. However, both partners' income and capital are now assessed together. If your partner earns or has significant savings, the combined assessment may reduce or remove the UC award even though the couple allowance is higher. You must report the change within one month of cohabiting.",
            },
            {
                "heading": "Capital and savings become joint",
                "content": "Once in a joint UC claim, savings are assessed jointly. If your partner has £8,000 in savings and you have £3,000, the combined £11,000 puts the household in the tariff income band. The tariff income rule adds £4.35 a month in assumed income for every complete £250 above £6,000 — so £5,000 excess generates around £86.50 a month in assumed income, reducing UC accordingly.",
            },
            {
                "heading": "Council tax — the single person discount ends",
                "content": "If you have been claiming the 25% single person council tax discount, that stops when a second adult moves in. Depending on your income and your council's local scheme, you may still qualify for means-tested Council Tax Reduction — but the 25% discount alone ends on the first day both adults live there. It is worth applying for CTR promptly to avoid a gap.",
            },
            {
                "heading": "Child Benefit and other payments",
                "content": "Child Benefit is paid to the person who claims it and is not affected by a partner moving in directly. However, if your partner has adjusted net income above £60,000, the High Income Child Benefit Charge may start to apply. Check the HICBC calculator if the new partner earns above that threshold. Benefits that are in your name only, like PIP or Carer's Allowance, are also not directly affected by a partner moving in, though they can affect how joint UC is calculated.",
            },
        ],
        "related_calculators": ["universal-credit-calculator", "council-tax-reduction-calculator", "hicbc-calculator", "savings-impact-calculator"],
        "related_guides": ["universal-credit-explained", "child-benefit-and-hicbc"],
    },
    "what-happens-if-my-rent-increases": {
        "slug": "what-happens-if-my-rent-increases",
        "title": "What happens to my benefits if my rent increases?",
        "description": "Understand how a rent increase affects UC housing costs, the LHA cap, and when the benefit cap becomes relevant.",
        "intro": "A rent increase does not automatically mean more Universal Credit housing support. The amount UC pays towards rent is capped in several ways — by the Local Housing Allowance for private renters, by bedroom entitlement rules for social tenants, and by the overall Benefit Cap. This page explains how the caps work and what options exist if the increase leaves a gap.",
        "sections": [
            {
                "heading": "The Local Housing Allowance cap for private renters",
                "content": "If you rent privately and claim Universal Credit, the housing costs element is capped at the Local Housing Allowance for your area and bedroom entitlement. LHA is set at the 30th percentile of private rents in a Broad Rental Market Area and is reviewed periodically. If your rent increases beyond the LHA cap, the extra cost falls on you — UC does not automatically adjust above it. You can appeal LHA decisions or check whether a different bedroom entitlement applies.",
            },
            {
                "heading": "Social housing and bedroom rules",
                "content": "For social renters, the UC housing element is based on the eligible rent for your property, subject to bedroom size criteria. If you have more bedrooms than the criteria allow — typically one per person or couple, with additional rooms for children over certain ages — a deduction of 14% (one spare room) or 25% (two or more spare rooms) applies regardless of the actual rent increase. If your landlord raises the rent, UC will cover the increase up to the eligible rent but the size criteria deduction still applies.",
            },
            {
                "heading": "The Benefit Cap — when total benefits are already high",
                "content": "If your total household benefits are near or above the Benefit Cap, a rent increase may not produce any extra housing support because the cap is applied to the whole award. The cap is £1,835 a month outside London and £2,110 inside London for families. Higher rent means the housing element needs to be higher, but if the cap is already limiting the total, the increase simply reshuffles how the award is divided internally rather than adding to it.",
            },
            {
                "heading": "What to do if there is a shortfall",
                "content": "If a rent increase creates a shortfall that UC cannot cover, there are a few options. Discretionary Housing Payments (DHP) can be applied for at the local council — these are short-term top-ups designed for exactly this type of situation. If the gap is long-term, it may be worth checking whether the property is appropriately sized for your entitlement and whether there are more affordable alternatives. Local welfare assistance schemes can also provide short-term support in some areas.",
            },
        ],
        "related_calculators": ["universal-credit-calculator", "housing-benefit-calculator", "benefit-cap-calculator"],
        "related_guides": ["help-with-rent-and-council-tax", "universal-credit-explained"],
    },
    "carers-allowance-explained": {
        "slug": "carers-allowance-explained",
        "title": "Carer's Allowance explained 2026/27 — rates, eligibility and how it affects other benefits",
        "description": "Carer's Allowance 2026/27: £81.90/week for 35+ hours care. Who qualifies, £151/week earnings limit and how it interacts with Universal Credit.",
        "topic": "Carer support",
        "intro": "Carer's Allowance is the main benefit for people providing substantial unpaid care. In 2026/27 it pays £81.90 a week — but the earnings limit, the interaction with other benefits and the 'underlying entitlement' rule mean it works differently from most other payments. This page explains who qualifies, what the earnings limit means in practice, and how claiming affects your Universal Credit and State Pension.",
        "sections": [
            {
                "heading": "Who qualifies for Carer's Allowance",
                "content": "You can claim Carer's Allowance if you spend at least 35 hours a week caring for someone who receives a qualifying disability benefit — specifically the daily living component of PIP (standard or enhanced), the middle or highest care component of DLA, Attendance Allowance, the daily living component of ADP (Scotland), or Armed Forces Independence Payment. The person you care for does not have to live with you. You must be 16 or over, not in full-time education, and your net earnings after allowable deductions must not exceed £151 a week in 2026/27.",
            },
            {
                "heading": "The £151 weekly earnings limit",
                "content": "The earnings threshold for Carer's Allowance is £151 a week net in 2026/27 — up from £139 in 2025/26. Net earnings means after tax, National Insurance and half of any pension contributions. Certain work expenses for care or disability can also be deducted. If your net earnings go above £151 in any week, you lose the full Carer's Allowance for that week — there is no taper. This makes managing earnings around part-time work particularly important, and it is worth calculating your net figure carefully before assuming you are over or under the limit.",
            },
            {
                "heading": "Carer's Allowance and Universal Credit — the 'underlying entitlement' rule",
                "content": "If you receive Universal Credit, receiving Carer's Allowance at the same time can feel counterintuitive. UC is reduced by £1 for every £1 of Carer's Allowance you receive — so the two payments largely cancel out for the Carer's Allowance element. However, having an 'underlying entitlement' to Carer's Allowance (meaning you meet the criteria even if UC offsets the payment) adds a carer element to your Universal Credit of £198.31 a month in 2026/27. This extra element is worth significantly more than the Carer's Allowance itself, making the interaction work in your favour overall.",
            },
            {
                "heading": "Effect on State Pension and National Insurance credits",
                "content": "Carer's Allowance comes with Carer's Credits if you are not already paying National Insurance. These protect your State Pension record during periods when caring prevents paid work. If you have reached State Pension age, you cannot receive Carer's Allowance — but you may still qualify for a carer addition within Pension Credit (worth £48.15 a week in 2026/27 if you qualify). Importantly, Carer's Allowance is taxable, which can affect your income tax position if you also have part-time earnings or a private pension.",
            },
            {
                "heading": "What happens if the person you care for loses their benefit",
                "content": "Carer's Allowance is tied to the disability benefit of the person you care for. If their PIP, DLA or Attendance Allowance is reduced or stopped — for example after a reassessment — and they no longer receive a qualifying benefit, your Carer's Allowance must stop too. You must report changes to DWP promptly. Continuing to claim after eligibility ends creates an overpayment, which DWP will seek to recover. If you believe the decision on the person you care for is wrong, supporting their appeal is worth doing — it could restore both benefits.",
            },
        ],
        "faq": [
            {"q": "How much is Carer's Allowance in 2026/27?", "a": "Carer's Allowance is £81.90 per week in 2026/27, paid every four weeks. This is subject to income tax if your total income exceeds the personal allowance."},
            {"q": "Can I claim Carer's Allowance and Universal Credit at the same time?", "a": "Yes. Carer's Allowance reduces UC pound for pound, but having underlying entitlement to Carer's Allowance adds a carer element of £198.31 a month to your UC award — more than Carer's Allowance itself."},
            {"q": "What is the earnings limit for Carer's Allowance?", "a": "In 2026/27 the limit is £151 per week net earnings (after tax, NI and half of pension contributions). Exceeding this even by £1 means you lose Carer's Allowance for that week entirely."},
            {"q": "Does the person I care for have to receive PIP?", "a": "They must receive a qualifying disability benefit: the daily living component of PIP (standard or enhanced), middle or highest rate DLA care component, Attendance Allowance, or equivalent Scottish benefits."},
        ],
        "related_calculators": ["universal-credit-calculator", "pension-credit-calculator"],
        "related_guides": ["what-benefits-can-i-claim", "benefits-if-you-cannot-work", "universal-credit-explained"],
    },
    "pip-explained": {
        "slug": "pip-explained",
        "title": "PIP explained 2026/27 — rates, points, eligibility and how the assessment works",
        "description": "PIP 2026/27: daily living up to £114.60/week, mobility up to £80.00/week, max £194.60/week. How the points system works and how PIP interacts with Universal Credit.",
        "topic": "Disability support",
        "intro": "Personal Independence Payment (PIP) is the main disability benefit for working-age adults in England, Wales and Northern Ireland. It is based on how your condition affects you — not on your diagnosis or whether you are in work. In 2026/27 it pays up to £194.60 a week if you qualify for both components at the enhanced rate. This guide explains how the points system works, what each activity and descriptor means in practice, and how PIP interacts with Universal Credit and other benefits.",
        "sections": [
            {
                "heading": "PIP rates for 2026/27",
                "content": "PIP has two components: daily living and mobility. Each is awarded at either standard or enhanced rate depending on the points scored in the assessment. Daily living standard rate: £76.70 a week. Daily living enhanced rate: £114.60 a week. Mobility standard rate: £30.30 a week. Mobility enhanced rate: £80.00 a week. If you qualify for both components at the enhanced rate, the combined weekly amount is £194.60 — over £10,000 a year. PIP is not means-tested, is not taxable and is not affected by savings. You can receive it whether you are working or not.",
            },
            {
                "heading": "How the PIP points system works",
                "content": "PIP is assessed against ten daily living activities and two mobility activities. For each activity, descriptors describe different levels of ability. The descriptor that best matches what you can do — safely, repeatedly, to an acceptable standard, and in a reasonable time — determines your points score. You need at least 8 points in the daily living component to receive the standard daily living rate, and at least 12 points for the enhanced rate. The same thresholds (8 points for standard, 12 for enhanced) apply to the mobility component separately. Points from different activities in the same component are added together — you do not need to score heavily on a single activity.",
            },
            {
                "heading": "The PIP assessment: what DWP considers",
                "content": "A healthcare professional commissioned by DWP will assess how your condition affects you across the activities. The assessment is based on your application form (PIP2), any supporting evidence you provide, and the face-to-face or telephone consultation. Key evidence sources include GP letters, specialist reports, care plans, occupational therapy assessments, prescription histories and personal diaries documenting good and bad days. DWP considers your typical day, not your best day. Many people under-report their difficulties — be specific about how often symptoms affect you and whether you can complete activities reliably and safely.",
            },
            {
                "heading": "PIP and Universal Credit — how they interact",
                "content": "PIP and Universal Credit are separate benefits paid by different parts of the DWP and assessed independently. Receiving PIP does not reduce your Universal Credit. In fact, it can increase UC in two ways. First, the standard daily living or enhanced daily living rate of PIP triggers the UC limited capability for work-related activity element (£416.19 a month in 2026/27 if you also have a UC health element). Second, if someone in your household receives PIP daily living, a carer who spends 35 hours a week caring for them may qualify for Carer's Allowance — which carries an underlying entitlement that adds the UC carer element of £198.31 a month.",
            },
            {
                "heading": "If your PIP claim is refused or reduced",
                "content": "A significant proportion of PIP claims are overturned on appeal. If your initial claim is refused or you receive a lower rate than expected, request mandatory reconsideration within one month of the decision. If the reconsideration does not change the outcome, you have the right to appeal to an independent tribunal. Success rates at tribunal are substantially higher than at mandatory reconsideration. Gathering additional evidence — particularly from consultants, care professionals or a detailed diary — strengthens the case. Citizens Advice and welfare rights organisations can help with the appeal process.",
            },
        ],
        "faq": [
            {"q": "How much is PIP in 2026/27?", "a": "PIP pays £76.70 (standard) or £114.60 (enhanced) a week for daily living, and £30.30 (standard) or £80.00 (enhanced) a week for mobility. The maximum combined weekly amount is £194.60."},
            {"q": "Does working affect PIP?", "a": "No. PIP is not means-tested and is not affected by earnings, savings or whether you are working. You can receive PIP in or out of work."},
            {"q": "How many points do you need for PIP?", "a": "You need at least 8 points in a component for the standard rate and at least 12 points for the enhanced rate. Daily living and mobility are scored separately."},
            {"q": "Does PIP affect Universal Credit?", "a": "PIP does not reduce UC. Receiving the daily living component of PIP can trigger the limited capability for work-related activity addition (£416.19/month) to your UC award if you also meet health criteria."},
        ],
        "related_calculators": ["universal-credit-calculator", "pip-checker"],
        "related_guides": ["benefits-if-you-cannot-work", "disability-support", "carers-allowance-explained"],
    },
    "child-benefit-guide": {
        "slug": "child-benefit-guide",
        "title": "Child Benefit 2026/27 — rates, High Income Charge and how to claim",
        "description": "Child Benefit 2026/27: £27.05/week first child, £17.90 each additional. High Income Child Benefit Charge starts at £60,000 and withdraws fully at £80,000.",
        "topic": "Family support",
        "intro": "Child Benefit is a universal payment for families with children under 16 (or under 20 in approved education or training). In 2026/27 it pays £27.05 a week for the first child and £17.90 for each additional child. It is not means-tested at point of claim — but households where one person earns above £60,000 face the High Income Child Benefit Charge, which withdraws the benefit between £60,000 and £80,000 adjusted net income. This guide explains the rates, the HICBC calculation, and what to do if you are near the threshold.",
        "sections": [
            {
                "heading": "Child Benefit rates for 2026/27",
                "content": "Child Benefit rates from April 2026 are: £27.05 per week for the eldest or only child (£1,406.60 per year), and £17.90 per week for each additional child (£930.80 per year each). A family with two children receives £44.95 a week (£2,337.40 per year). The benefit is paid every four weeks. Child Benefit is not taxable and is not means-tested at the point of claim — but the High Income Child Benefit Charge claws it back through self-assessment for higher earners.",
            },
            {
                "heading": "The High Income Child Benefit Charge explained",
                "content": "If either you or your partner has adjusted net income above £60,000 in a tax year, the higher earner must pay the High Income Child Benefit Charge (HICBC) via self-assessment. The charge is 1% of the Child Benefit received for every £200 of income above £60,000. At £70,000 — £10,000 over the threshold — 50% of Child Benefit is clawed back. At £80,000 the charge equals 100% of Child Benefit and you are no better off claiming. Above £80,000, you lose more than you gain unless you have a particular reason to continue (such as maintaining NI credits). The key point is that adjusted net income — not gross salary — is what matters. Pension contributions reduce adjusted net income, which can bring the charge down or eliminate it.",
            },
            {
                "heading": "Using pension contributions to reduce the HICBC",
                "content": "Adjusted net income for HICBC purposes is gross income minus pension contributions (including salary sacrifice), trading losses and Gift Aid payments. If your gross income is £70,000 and you make £10,001 in pension contributions, your adjusted net income falls to £59,999 — just below the threshold — and the HICBC disappears entirely. This makes pension contributions particularly valuable at incomes between £60,000 and £80,000, especially for families with multiple children. For a family with two children where the higher earner is at £70,000, a pension contribution of £10,001 saves approximately £1,169 in Child Benefit (50% of £2,337.40) while also saving 42% income tax and NI on the contribution.",
            },
            {
                "heading": "Claiming Child Benefit even if you face the charge",
                "content": "Many families with income above £80,000 still choose to claim Child Benefit and pay back the full amount via the HICBC. There are two reasons. First, the claim protects the main carer's National Insurance record — non-claiming parents can miss NI credits that count toward State Pension. Second, claiming gives the child an automatic National Insurance number at age 16. If you choose not to claim, you can still register via HMRC to receive the NI credits without receiving the payment itself. Check this option carefully with HMRC if the higher earner is above £80,000.",
            },
            {
                "heading": "Child Benefit and Universal Credit",
                "content": "Child Benefit does not count as income for Universal Credit. It is paid on top of any UC child elements. If you are on Universal Credit, you should still claim Child Benefit separately — they do not offset each other. However, if you are receiving Tax Credits (not UC), Child Benefit is included in the income assessment for some older Tax Credit calculations. Families on UC should focus on the UC child element (£303.94 per child per month in 2026/27 from April 2026) and Child Benefit separately.",
            },
        ],
        "faq": [
            {"q": "How much is Child Benefit in 2026/27?", "a": "£27.05 per week for the first child (£1,406.60/year) and £17.90 per week for each additional child (£930.80/year). Two children: £44.95/week (£2,337.40/year)."},
            {"q": "When does the High Income Child Benefit Charge start?", "a": "The HICBC applies when either partner's adjusted net income exceeds £60,000. It withdraws Child Benefit at 1% per £200 over this threshold, reaching 100% at £80,000."},
            {"q": "Can pension contributions reduce the HICBC?", "a": "Yes. Pension contributions reduce adjusted net income for HICBC purposes. If contributions bring adjusted net income below £60,000, the charge disappears entirely."},
            {"q": "Should I claim Child Benefit if I earn over £80,000?", "a": "Consider claiming to protect NI credits for the main carer and secure the child's NI number. You can elect not to receive the payment but still register to receive NI credits."},
        ],
        "related_calculators": ["child-benefit-calculator", "hicbc-calculator"],
        "related_guides": ["benefits-for-low-income-families", "family-support", "what-counts-as-income-for-benefits"],
    },
}

TOPIC_HUBS: Dict[str, Dict[str, Any]] = {
    "universal-credit": {
        "slug": "universal-credit",
        "title": "Universal Credit hub",
        "description": "Universal Credit hub 2026/27: how it works, what drives the award, how earnings and savings affect it, and which calculators and guides to use.",
        "intro": "Universal Credit is the main working-age means-tested benefit in the UK, combining housing support, child elements, childcare support, health elements and basic living costs into a single monthly payment. This hub brings together the main calculators and guides so you can move from a quick estimate to a detailed understanding.",
        "key_facts": [
            "Standard allowance: £424.90/month (single, 25+) or £666.97/month (couple, both 25+)",
            "Child element: £303.94 per child per month from April 2026 (no two-child limit)",
            "Earnings taper: 55% — you keep 45p of every £1 earned above the work allowance",
            "Work allowance: £404 or £673/month where children or a health element apply",
            "Savings threshold: £6,000 lower (tariff income applies above this), £16,000 upper (UC stops)",
            "Benefit Cap: £1,835/month outside London, £2,110 inside London (families)",
        ],
        "related_calculators": ["universal-credit-calculator", "benefit-cap-calculator", "savings-impact-calculator", "earnings-impact-calculator", "council-tax-reduction-calculator"],
        "related_guides": ["universal-credit-explained", "how-savings-affect-benefits", "what-counts-as-income-for-benefits"],
        "related_situations": ["benefits-for-single-parents", "benefits-for-low-income-families", "benefits-for-renters"],
        "related_scenarios": ["what-happens-if-my-savings-increase", "what-happens-if-i-work-more-hours", "what-happens-if-my-partner-moves-in", "what-happens-if-my-rent-increases"],
    },
    "family-support": {
        "slug": "family-support",
        "title": "Family and childcare support hub",
        "description": "Child Benefit, Tax-Free Childcare, Free School Meals, Healthy Start, Sure Start and maternity support — all the UK family benefit tools in one place.",
        "intro": "UK family support comes through several separate schemes that do not always talk to each other. This hub brings together the most useful calculators and guides so families can check Child Benefit, childcare top-ups, school meal eligibility and maternity support in a single session.",
        "key_facts": [
            "Child Benefit: £27.05/week (first child), £17.90 (additional children) — 2026/27 rates",
            "HICBC taper: 1% per £200 over £60,000 adjusted net income, 100% at £80,000",
            "Tax-Free Childcare: £2 top-up per £8 spent, max £2,000/child/year",
            "UC childcare support: up to 85% of registered childcare costs, capped monthly",
            "Free School Meals income test: UC household earnings below £7,400/year (England)",
            "SMP: 90% of weekly pay for 6 weeks, then £184.03/week for up to 33 more weeks",
        ],
        "related_calculators": ["child-benefit-calculator", "hicbc-calculator", "tax-free-childcare-calculator", "tax-free-childcare-monthly-calculator", "free-school-meals-checker", "maternity-pay-calculator", "sure-start-maternity-grant-checker", "healthy-start-checker"],
        "related_guides": ["benefits-for-low-income-families", "child-benefit-and-hicbc", "tax-free-childcare-guide", "tax-free-childcare-top-up-examples", "how-much-child-benefit-for-1-2-3-children"],
        "related_situations": ["benefits-for-single-parents", "benefits-for-low-income-families"],
        "related_scenarios": [],
    },
    "rent-and-council-tax": {
        "slug": "rent-and-council-tax",
        "title": "Rent and council tax support hub",
        "description": "UC housing costs, Housing Benefit, Council Tax Reduction and the Benefit Cap — all the tools for understanding housing support in one place.",
        "intro": "Help with rent and council tax comes from different parts of the UK system and often requires separate applications. This hub covers the main housing support routes, from Universal Credit housing costs and Housing Benefit through to Council Tax Reduction and the Benefit Cap.",
        "key_facts": [
            "UC housing element: capped at Local Housing Allowance for private renters",
            "Social housing: bedroom rule deductions of 14% (one spare) or 25% (two or more spare)",
            "Housing Benefit: mainly for pension-age claimants and specialist accommodation",
            "Council Tax Reduction: run locally — rules vary by council",
            "Single person discount: 25% off council tax for single-adult households",
            "Benefit Cap: £1,835/month outside London, £2,110 inside London (families)",
        ],
        "related_calculators": ["universal-credit-calculator", "housing-benefit-calculator", "council-tax-reduction-calculator", "benefit-cap-calculator"],
        "related_guides": ["help-with-rent-and-council-tax", "universal-credit-explained"],
        "related_situations": ["benefits-for-renters", "benefits-for-single-parents"],
        "related_scenarios": ["what-happens-if-my-rent-increases", "what-happens-if-my-partner-moves-in"],
    },
    "disability-support": {
        "slug": "disability-support",
        "title": "Disability and health support hub",
        "description": "PIP, ESA, SSP, the UC health element and the Benefit Cap disability exemption — all the disability-related benefit tools in one place.",
        "intro": "Disability and health-related support in the UK comes through several different systems. PIP, ESA, SSP and the Universal Credit health element each work differently and can sometimes be claimed at the same time. This hub brings together the main tools and explains how they connect.",
        "key_facts": [
            "PIP: not means tested — income and savings have no effect on eligibility",
            "PIP daily living: £76.70/week (standard) or £114.60/week (enhanced) — 2026/27",
            "PIP mobility: £30.30/week (standard) or £80.00/week (enhanced) — 2026/27",
            "ESA support group: up to £145.90/week; work-related activity: up to £95.55/week",
            "UC LCWRA element: £429.80/month added to UC award",
            "SSP: lower of £123.25/week or 80% of average weekly earnings, for up to 28 weeks",
        ],
        "related_calculators": ["pip-eligibility-checker", "esa-calculator", "ssp-calculator", "universal-credit-calculator"],
        "related_guides": ["pip-explained-simply", "pip-points-explained", "pip-daily-living-explained", "pip-mobility-explained", "esa-vs-universal-credit"],
        "related_situations": ["benefits-if-you-cannot-work"],
        "related_scenarios": [],
    },
    "pension-age-support": {
        "slug": "pension-age-support",
        "title": "Pension-age support hub",
        "description": "Pension Credit, council tax help, winter payments and worked examples for pension-age households in one place.",
        "intro": "Pension-age support works differently from working-age benefits. Pension Credit, winter support, council tax help and pension-age examples are closely linked, so this hub is designed to help older households move through them as one joined-up journey.",
        "key_facts": [
            "Guarantee Credit standard minimum: £238.00/week single, £363.25/week couple",
            "Savings under £10,000 are ignored for Pension Credit",
            "Savings above £10,000 create £1/week assumed income for each £500",
            "Even a small Pension Credit award can unlock wider support",
            "Winter support and council tax help often matter as much as the weekly top-up",
            "Home ownership does not automatically rule out Pension Credit",
        ],
        "related_calculators": ["pension-credit-calculator", "winter-fuel-payment-checker", "cold-weather-payment-checker", "council-tax-reduction-calculator", "housing-benefit-calculator"],
        "related_guides": ["pension-credit-explained", "what-pension-credit-unlocks", "pension-credit-examples-for-single-pensioner", "pension-credit-examples-for-couple", "how-savings-affect-benefits"],
        "related_situations": ["benefits-for-pensioners"],
        "related_scenarios": [],
    },
}

STATIC_PAGES = {
    "methodology": {
        "title": "Methodology",
        "content": [
            "UK Benefits Calculator is an independent estimator site. We use published GOV.UK rates and guidance where practical, then apply simplified logic for public-facing calculators where the official rules are too detailed for a short tool.",
            "Our calculators are designed to help users estimate entitlement, compare support routes and identify what to check next. They are not official decisions and should not be treated as guaranteed awards.",
            "We review assumptions regularly and update the site when key published rates or eligibility rules change.",
        ],
        "links": [("Universal Credit", "https://www.gov.uk/universal-credit"), ("Pension Credit", "https://www.gov.uk/pensioncredit"), ("Child Benefit and tax credits rates", "https://www.gov.uk/government/publications/rates-and-allowances-tax-credits-child-benefit-and-guardians-allowance/tax-credits-child-benefit-and-guardians-allowance")],
    },
    "sources": {
        "title": "Sources",
        "content": [
            "Core assumptions on this site are reviewed against GOV.UK and other official UK public-sector guidance.",
            "For the current build we reviewed official pages covering Universal Credit, Child Benefit, the High Income Child Benefit Charge, Pension Credit, PIP, Housing Benefit, Council Tax Reduction, SSP, maternity payments, ESA, JSA, Tax-Free Childcare, Sure Start Maternity Grant, Healthy Start, Free School Meals, Winter Fuel Payment and Cold Weather Payments.",
            "Where a calculation is simplified, that is stated on the page itself.",
        ],
        "links": [("Universal Credit", "https://www.gov.uk/universal-credit/what-youll-get"), ("PIP", "https://www.gov.uk/pip/how-much-youll-get"), ("Winter Fuel Payment", "https://www.gov.uk/winter-fuel-payment")],
    },
    "privacy": {
        "title": "Privacy",
        "content": [
            "We do not ask users to create an account to use UK Benefits Calculator. If analytics or advertising are enabled, third-party services may process limited technical data such as page views, approximate device information or ad interactions.",
            "Calculator inputs stay in your browser unless they form part of the page URL as query parameters. We do not ask for National Insurance numbers, DWP credentials or claim logins through the public calculator pages.",
            "If you contact us directly, we use your message only to reply, manage editorial corrections and operate the site responsibly.",
        ],
        "links": [],
    },
    "cookie-policy": {
        "title": "Cookie policy",
        "content": [
            "UK Benefits Calculator uses only a small number of technical cookies and browser storage features needed for normal site operation, analytics configuration and ad loading where enabled.",
            "If analytics is enabled through a GA measurement ID, Google Analytics may set cookies or similar identifiers to help us understand page usage. If advertising is enabled, Google AdSense or related ad technology may also use cookies in line with their own policies.",
            "You can block or delete cookies through your browser settings, although some site features or ad behaviour may then work differently.",
        ],
        "links": [("Google Privacy & Terms", "https://policies.google.com/privacy"), ("Google AdSense policies", "https://support.google.com/adsense/answer/48182")],
    },
    "terms": {
        "title": "Terms",
        "content": [
            "UK Benefits Calculator provides independent information and estimation tools for UK benefits and support. Content is for general guidance only and does not replace official advice, regulated financial advice or welfare-rights casework.",
            "No calculator on this site creates a claim, guarantees entitlement or confirms a final award. Use official services and professional advice where decisions are important.",
            "We may update or remove pages as rules and rates change.",
        ],
        "links": [],
    },
    "about": {
        "title": "About UK Benefits Calculator",
        "content": [
            "UK Benefits Calculator is a UK-focused support and entitlement estimation site built to help people understand what help they may qualify for across benefits, childcare support, disability support and pension-age help.",
            "The site is intentionally independent and non-governmental. Our aim is to explain complicated support routes in plain English while keeping calculators fast, readable and search-friendly.",
            "We publish practical estimator pages, support guides and connected topical clusters so users can move from one question to the next without starting from scratch each time.",
            "Content is produced by UK Benefits Calculator Editorial, an in-house publishing team focused on UK household finance, benefits, low-income support and plain-English search-first guidance.",
        ],
        "links": [],
    },
    "editorial-standards": {
        "title": "Editorial standards",
        "content": [
            "UK Benefits Calculator Editorial aims to publish pages that are clear, useful and honest about assumptions. We avoid presenting simplified estimates as official decisions or government-endorsed outcomes.",
            "Pages are written in plain British English, structured for search intent and reviewed when official rates, qualifying rules or core policy changes materially affect a page.",
            "When a topic is too complex for a definitive public calculator, we frame the page as a checker or guide, explain the limitation directly and link users to the most relevant official sources.",
        ],
        "links": [],
    },
    "contact": {
        "title": "Contact",
        "content": [
            "For editorial corrections or general site queries, contact hello@ukbenefitscalculator.co.uk.",
            "We cannot manage benefit claims or provide case-specific welfare rights advice, but we can review factual issues on the site.",
            "If you need urgent claim help, use the relevant GOV.UK service or a specialist adviser such as Citizens Advice.",
        ],
        "links": [("Citizens Advice", "https://www.citizensadvice.org.uk/"), ("Find your local council", "https://www.gov.uk/find-local-council")],
    },
}

CALCULATOR_ORDER = list(CALCULATORS.keys())
GUIDE_ORDER = list(GUIDES.keys())
CALCULATOR_ALIASES = {alias: slug for slug, page in CALCULATORS.items() for alias in page["aliases"]}
STATIC_ROUTES = set(STATIC_PAGES.keys())


def related_calculators(slugs: List[str]) -> List[Dict[str, Any]]:
    return [CALCULATORS[slug] for slug in slugs if slug in CALCULATORS]


def related_guides_for_calculator(slug: str) -> List[Dict[str, Any]]:
    matches = []
    for guide_slug, guide in GUIDES.items():
        if slug in guide.get("related", []):
            item = dict(guide)
            item["slug"] = guide_slug
            matches.append(item)
    return matches[:4]


def breadcrumbs(*items: Dict[str, str]) -> List[Dict[str, str]]:
    return [{"name": "Home", "url": SITE_URL + "/"}] + list(items)


OFFICIAL_SOURCE_SETS: Dict[str, List[Dict[str, str]]] = {
    "universal-credit": [
        {"label": "Universal Credit: what you'll get", "url": "https://www.gov.uk/universal-credit/what-youll-get"},
        {"label": "Universal Credit and childcare costs", "url": "https://www.gov.uk/universal-credit/what-youll-get"},
        {"label": "Benefit Cap overview", "url": "https://www.gov.uk/benefit-cap"},
    ],
    "child-benefit": [
        {"label": "Child Benefit rates and allowances", "url": "https://www.gov.uk/government/publications/rates-and-allowances-tax-credits-child-benefit-and-guardians-allowance/tax-credits-child-benefit-and-guardians-allowance"},
        {"label": "High Income Child Benefit Charge", "url": "https://www.gov.uk/child-benefit-tax-charge"},
        {"label": "Tax-Free Childcare", "url": "https://www.gov.uk/tax-free-childcare"},
    ],
    "pension-support": [
        {"label": "Pension Credit", "url": "https://www.gov.uk/pension-credit"},
        {"label": "Winter Fuel Payment", "url": "https://www.gov.uk/winter-fuel-payment"},
        {"label": "Cold Weather Payment", "url": "https://www.gov.uk/cold-weather-payment"},
    ],
    "disability-health": [
        {"label": "Personal Independence Payment (PIP)", "url": "https://www.gov.uk/pip"},
        {"label": "Employment and Support Allowance (ESA)", "url": "https://www.gov.uk/employment-support-allowance"},
        {"label": "Statutory Sick Pay", "url": "https://www.gov.uk/statutory-sick-pay"},
    ],
    "housing-council-tax": [
        {"label": "Housing Benefit", "url": "https://www.gov.uk/housing-benefit"},
        {"label": "Local Housing Allowance", "url": "https://www.gov.uk/government/collections/local-housing-allowance-lha-rates-applicable-from-april-2025-to-march-2026"},
        {"label": "Find your local council", "url": "https://www.gov.uk/find-local-council"},
    ],
}


def cluster_for_slug(slug: str) -> str:
    if slug.startswith("universal-credit") or slug in {"savings-impact-calculator", "earnings-impact-calculator", "benefit-cap-calculator"}:
        return "universal-credit"
    if any(token in slug for token in ("child-benefit", "hicbc", "childcare", "free-school-meals", "healthy-start", "sure-start", "maternity")):
        return "child-benefit"
    if any(token in slug for token in ("pension-credit", "winter-fuel", "cold-weather")):
        return "pension-support"
    if any(token in slug for token in ("pip", "esa", "ssp", "jsa")):
        return "disability-health"
    if any(token in slug for token in ("housing-benefit", "council-tax")):
        return "housing-council-tax"
    return "universal-credit"


def page_sources(slug: str) -> List[Dict[str, str]]:
    return OFFICIAL_SOURCE_SETS.get(cluster_for_slug(slug), OFFICIAL_SOURCE_SETS["universal-credit"])


def build_estimate_visual(estimate: Dict[str, Any]) -> Dict[str, Any]:
    palette = ["var(--c-uc)", "var(--c-child)", "var(--c-housing)", "var(--c-other)"]
    positive_rows = []
    for label, value in estimate.get("breakdown", []):
        if "percentage" in label.lower():
            continue
        if isinstance(value, (int, float)) and value > 0:
            positive_rows.append((label, float(value)))
    if not positive_rows:
        amount = max(estimate.get("primary_amount", 0.0), 0.0)
        positive_rows = [(estimate.get("primary_label", "Estimated amount"), amount or 1.0)]

    total = sum(value for _, value in positive_rows) or 1.0
    top_rows = positive_rows[:3]
    if len(positive_rows) > 3:
        other_total = sum(value for _, value in positive_rows[3:])
        top_rows.append(("Other included support", other_total))

    legend = []
    segments = []
    current = 0.0
    for idx, (label, value) in enumerate(top_rows):
        share = max(3.0, round((value / total) * 100, 1))
        color = palette[idx % len(palette)]
        legend.append({"label": label, "value": round_money(value), "share": share, "color": color})
        next_stop = min(100.0, current + share)
        segments.append(f"{color} {current:.1f}% {next_stop:.1f}%")
        current = next_stop
    if current < 100:
        segments.append(f"var(--surface-alt) {current:.1f}% 100%")

    return {
        "legend": legend,
        "conic": ", ".join(segments),
        "explainer": "Visual split of the main amounts included in this estimate.",
    }


def _breakdown_value(estimate: Dict[str, Any], label: str) -> float:
    for row_label, value in estimate.get("breakdown", []):
        if row_label == label and isinstance(value, (int, float)):
            return float(value)
    return 0.0


def _fmt_money(amount: float) -> str:
    return f"£{amount:,.2f}"


def _fmt_integer(amount: float) -> str:
    return f"{int(round(amount)):,}"


def calculator_ui_config(slug: str, page: Dict[str, Any]) -> Dict[str, Any]:
    cluster = cluster_for_slug(slug)
    base = {
        "cluster": cluster,
        "calculator_title": page["title"],
        "calculator_subcopy": "Adjust the inputs and review the answer cards, chart and breakdown together.",
        "hero_notes": [
            "Fast answer first",
            "Designed for mobile and desktop",
            "Updated to current published rates",
        ],
        "geo_note": "UK-wide estimator using current published rules, with local or case-specific limitations explained below.",
        "priority_fields": [],
        "result_mode": page["formula"],
        "chart_unit_label": "estimate",
        "chart_secondary_prefix": "",
        "chart_secondary_suffix": "/yr",
        "input_brief_title": "Key rules",
        "input_brief_points": [],
        "related_intro": "Use the linked calculators and guides below to test the next question people usually have after this estimate.",
    }
    per_slug = {
        "universal-credit-calculator": {
            "calculator_subcopy": "Check the monthly Universal Credit estimate first, with savings, the £16,000 capital limit and tariff income effects visible early.",
            "hero_notes": [
                "Capital over £6,000 changes the award",
                "£16,000 usually stops entitlement",
                "Rent, earnings and childcare included",
            ],
            "geo_note": "UK-wide Universal Credit rules with simplified housing-cost treatment. Local rent limits, service charges and special-case rules can still change the final award.",
            "priority_fields": ["household", "earnings", "savings", "housing_cost", "children", "age_band", "childcare_cost", "health"],
            "chart_unit_label": "per month",
            "input_brief_title": "Capital rules to know",
            "input_brief_points": ["£6,000 ignored", "£4.35 per £250 over £6,000", "£16,000 usually stops standard UC"],
            "related_intro": "These next pages are the usual follow-up checks for people comparing UC, capital limits, childcare help and capped awards.",
        },
        "child-benefit-calculator": {
            "calculator_subcopy": "Get the weekly Child Benefit figure first, then the monthly equivalent and annual amount for your child count in 2026/27.",
            "hero_notes": [
                "Weekly rate first",
                "Monthly and annual equivalents included",
                "Built for current child-count queries",
            ],
            "geo_note": "UK-wide Child Benefit rates are fixed nationally. The follow-up issue for many families is the High Income Child Benefit Charge.",
            "priority_fields": ["children"],
            "chart_unit_label": "per week",
            "input_brief_title": "2026/27 rates used",
            "input_brief_points": ["First child £27.05/wk", "Each extra child £17.90/wk", "Usually paid every 4 weeks"],
            "related_intro": "These are the pages most families need next when checking Child Benefit, HICBC and childcare support together.",
        },
        "hicbc-calculator": {
            "chart_unit_label": "per year",
            "chart_secondary_prefix": "keeps ",
            "chart_secondary_suffix": "",
            "input_brief_title": "HICBC threshold",
            "input_brief_points": ["Starts above £60,000 ANI", "1% per £200 over the threshold", "Full charge at £80,000"],
        },
        "pension-credit-calculator": {
            "calculator_subcopy": "See the likely weekly Pension Credit top-up first, with savings treatment and key additions kept visible from the start.",
            "hero_notes": [
                "Savings do not automatically rule it out",
                "Weekly top-up first",
                "Passported help matters too",
            ],
            "geo_note": "Pension Credit uses UK-wide core rates, but housing costs, Savings Credit and mixed-age couple rules can still change the final position.",
            "priority_fields": ["household", "weekly_income", "savings"],
            "chart_unit_label": "per week",
            "input_brief_title": "Savings rules",
            "input_brief_points": ["First £10,000 ignored", "No UC-style £16,000 stop point", "Even small awards can unlock extra help"],
            "related_intro": "Most Pension Credit searches lead into council tax, winter support and worked examples rather than ending at the weekly cash figure alone.",
        },
        "pip-eligibility-checker": {
            "calculator_subcopy": "Turn likely daily living and mobility points into the PIP rate bands and the weekly, monthly and annual amounts people actually search for.",
            "hero_notes": [
                "Daily living and mobility shown separately",
                "Weekly, monthly and annual equivalents",
                "Not means tested",
            ],
            "geo_note": "PIP rules are UK-wide in core structure, but this remains an indicative points checker rather than a DWP decision tool.",
            "priority_fields": ["daily_living_points", "mobility_points"],
            "chart_unit_label": "per week",
            "input_brief_title": "PIP point thresholds",
            "input_brief_points": ["8 points = standard rate", "12 points = enhanced rate", "Not affected by earnings or savings"],
            "related_intro": "People usually use these follow-up pages when they are comparing PIP with ESA, UC health routes or other disability-related support.",
        },
        "council-tax-reduction-calculator": {
            "calculator_subcopy": "Check likely monthly council tax help quickly, with income, savings and single-adult effects visible near the top.",
            "hero_notes": [
                "Savings can stop entitlement",
                "Monthly bill and help shown together",
                "Local scheme warning kept visible",
            ],
            "geo_note": "Council Tax Reduction is local, not one national scheme. This page is built as a UK directional estimator, not a council-specific decision tool.",
            "priority_fields": ["monthly_council_tax", "monthly_income", "savings"],
            "chart_unit_label": "per month",
            "input_brief_title": "CTR reminders",
            "input_brief_points": ["Local scheme, not one UK formula", "Savings can reduce help", "Single-person discount is separate"],
            "related_intro": "Council tax support searches usually connect to rent help, Pension Credit and wider affordability support, so the follow-up links stay tightly focused.",
        },
        "housing-benefit-calculator": {
            "calculator_subcopy": "Useful for legacy and pension-age Housing Benefit cases where weekly rent, weekly income and savings are the key starting checks.",
            "hero_notes": [
                "Legacy and pension-age focus",
                "Weekly support first",
                "Savings kept visible early",
            ],
            "geo_note": "Housing Benefit is mainly a legacy or specialist route now. This page is meant to answer that search intent while steering most new cases back to Universal Credit housing costs.",
            "priority_fields": ["weekly_rent", "weekly_income", "savings"],
            "chart_unit_label": "per week",
            "input_brief_title": "Before you rely on it",
            "input_brief_points": ["Mainly legacy or pension-age cases", "Working-age savings can still stop entitlement", "Bedroom and rent caps can reduce support"],
            "related_intro": "Housing Benefit searches usually need a second check on Universal Credit, council tax help or the Benefit Cap once the legacy-versus-new-claim question is clear.",
        },
        "benefit-cap-calculator": {
            "calculator_subcopy": "Check the cap amount for your household first, then see whether your entered monthly total looks above it and whether an exemption is likely worth checking next.",
            "hero_notes": [
                "London versus outside London made explicit",
                "Monthly cap amount shown clearly",
                "Useful after UC, rent or Child Benefit checks",
            ],
            "geo_note": "The Benefit Cap uses national cap levels, but exemptions and earnings rules still matter. This page is designed as a quick first cap check rather than a full exemption checker.",
            "priority_fields": ["monthly_benefits", "household", "inside_london"],
            "chart_unit_label": "over cap",
            "chart_secondary_prefix": "cap ",
            "chart_secondary_suffix": "",
            "input_brief_title": "Cap levels to compare",
            "input_brief_points": ["Outside London family cap £1,835/mo", "Inside London family cap £2,110/mo", "Many disability awards exempt the household"],
            "related_intro": "Benefit Cap searches often come after a lower-than-expected UC result, so the related links stay centred on rent, family support and cap exemptions.",
        },
        "tax-free-childcare-calculator": {
            "chart_unit_label": "per year",
            "chart_secondary_suffix": "/mo equiv",
            "input_brief_title": "How the top-up works",
            "input_brief_points": ["Government adds £2 for every £8 paid in", "Up to £2,000 a year per child", "Cannot usually be used with UC childcare support"],
        },
        "free-school-meals-checker": {
            "chart_unit_label": "school year",
            "chart_secondary_suffix": " family value",
            "input_brief_title": "England rules used here",
            "input_brief_points": ["UC earnings test usually £7,400 net", "Reception to year 2 often get universal infant meals", "Other UK nations use different rules"],
        },
        "savings-impact-calculator": {
            "chart_unit_label": "per month",
            "input_brief_title": "UC savings thresholds",
            "input_brief_points": ["Below £6,000 ignored", "£4.35 a month per £250 band", "£16,000 or more usually means no standard UC"],
        },
    }
    merged = dict(base)
    merged.update(per_slug.get(slug, {}))
    return merged


def ordered_fields_for_page(slug: str, page: Dict[str, Any]) -> List[Dict[str, Any]]:
    priority = calculator_ui_config(slug, page).get("priority_fields", [])
    order_index = {name: idx for idx, name in enumerate(priority)}
    return sorted(
        page["fields"],
        key=lambda field: (order_index.get(field["name"], len(priority) + page["fields"].index(field)), page["fields"].index(field)),
    )


def calculator_result_highlights(slug: str, page: Dict[str, Any], estimate: Dict[str, Any], inputs: Dict[str, Any]) -> List[Dict[str, str]]:
    formula = page["formula"]
    if formula == "universal_credit":
        savings_deduction = abs(_breakdown_value(estimate, "Savings deduction"))
        capital_status = "Over £16,000 entered" if inputs.get("savings", 0) >= 16000 else "Below £16,000 limit"
        return [
            {"label": "Monthly award", "value": _fmt_money(estimate["primary_amount"]), "tone": "primary"},
            {"label": "Annual view", "value": _fmt_money(estimate["secondary_amount"]), "tone": "standard"},
            {"label": "Savings entered", "value": _fmt_money(float(inputs.get("savings", 0))), "tone": "standard"},
            {"label": "Tariff income/month", "value": _fmt_money(savings_deduction), "tone": "standard"},
            {"label": "Capital status", "value": capital_status, "tone": "muted"},
        ]
    if formula == "child_benefit":
        weekly = float(estimate["primary_amount"])
        monthly = round_money(weekly * 52 / 12)
        annual = float(estimate["secondary_amount"])
        return [
            {"label": "Weekly amount", "value": _fmt_money(weekly), "tone": "primary"},
            {"label": "Monthly equivalent", "value": _fmt_money(monthly), "tone": "standard"},
            {"label": "Annual amount", "value": _fmt_money(annual), "tone": "standard"},
            {"label": "Children used", "value": _fmt_integer(float(inputs.get("children", 0))), "tone": "muted"},
        ]
    if formula == "pip":
        weekly = float(estimate["primary_amount"])
        monthly = round_money(weekly * 52 / 12)
        daily = _breakdown_value(estimate, "Daily living component")
        mobility = _breakdown_value(estimate, "Mobility component")
        daily_label = "No daily living award" if daily <= 0 else f"Daily living {_fmt_money(daily)}/wk"
        mobility_label = "No mobility award" if mobility <= 0 else f"Mobility {_fmt_money(mobility)}/wk"
        return [
            {"label": "Daily living award", "value": daily_label, "tone": "standard"},
            {"label": "Mobility award", "value": mobility_label, "tone": "standard"},
            {"label": "Weekly amount", "value": _fmt_money(weekly), "tone": "primary"},
            {"label": "Monthly equivalent", "value": _fmt_money(monthly), "tone": "standard"},
            {"label": "Annual equivalent", "value": _fmt_money(float(estimate["secondary_amount"])), "tone": "standard"},
        ]
    if formula == "benefit_cap":
        cap_used = _breakdown_value(estimate, "Monthly cap used")
        household_options = {option["value"]: option["label"] for option in next((field["options"] for field in page["fields"] if field["name"] == "household"), [])}
        return [
            {"label": "Amount over cap", "value": _fmt_money(float(estimate["primary_amount"])), "tone": "primary"},
            {"label": "Capped total", "value": _fmt_money(float(estimate["secondary_amount"])), "tone": "standard"},
            {"label": "Cap used", "value": _fmt_money(cap_used), "tone": "standard"},
            {"label": "Household used", "value": household_options.get(inputs.get("household", ""), str(inputs.get("household", ""))), "tone": "muted"},
        ]
    if formula == "council_tax_reduction":
        reduction_pct = _breakdown_value(estimate, "Reduction percentage used")
        return [
            {"label": "Monthly help", "value": _fmt_money(float(estimate["primary_amount"])), "tone": "primary"},
            {"label": "Annual help", "value": _fmt_money(float(estimate["secondary_amount"])), "tone": "standard"},
            {"label": "Monthly bill used", "value": _fmt_money(float(inputs.get("monthly_council_tax", 0))), "tone": "standard"},
            {"label": "Reduction rate", "value": f"{reduction_pct:,.0f}%", "tone": "standard"},
            {"label": "Savings entered", "value": _fmt_money(float(inputs.get("savings", 0))), "tone": "muted"},
        ]
    if formula == "housing_benefit":
        weekly = float(estimate["primary_amount"])
        monthly = round_money(weekly * 52 / 12)
        return [
            {"label": "Weekly support", "value": _fmt_money(weekly), "tone": "primary"},
            {"label": "Monthly equivalent", "value": _fmt_money(monthly), "tone": "standard"},
            {"label": "Annual equivalent", "value": _fmt_money(float(estimate["secondary_amount"])), "tone": "standard"},
            {"label": "Weekly rent used", "value": _fmt_money(float(inputs.get("weekly_rent", 0))), "tone": "standard"},
            {"label": "Savings entered", "value": _fmt_money(float(inputs.get("savings", 0))), "tone": "muted"},
        ]
    if formula == "pension_credit":
        weekly = float(estimate["primary_amount"])
        monthly = round_money(weekly * 52 / 12)
        household_options = {option["value"]: option["label"] for option in next((field["options"] for field in page["fields"] if field["name"] == "household"), [])}
        return [
            {"label": "Weekly amount", "value": _fmt_money(weekly), "tone": "primary"},
            {"label": "Monthly equivalent", "value": _fmt_money(monthly), "tone": "standard"},
            {"label": "Annual amount", "value": _fmt_money(float(estimate["secondary_amount"])), "tone": "standard"},
            {"label": "Savings entered", "value": _fmt_money(float(inputs.get("savings", 0))), "tone": "standard"},
            {"label": "Household used", "value": household_options.get(inputs.get("household", ""), str(inputs.get("household", ""))), "tone": "muted"},
        ]
    return [
        {"label": estimate.get("primary_label", "Main estimate"), "value": _fmt_money(float(estimate.get("primary_amount", 0))), "tone": "primary"},
        {"label": estimate.get("secondary_label", "Secondary estimate"), "value": _fmt_money(float(estimate.get("secondary_amount", 0))), "tone": "standard"},
    ]


def next_steps_for_slug(slug: str) -> List[Dict[str, str]]:
    mapping = {
        "universal-credit": [
            {"label": "Check the full Universal Credit calculator", "url": "/universal-credit-calculator"},
            {"label": "See how savings change the award", "url": "/savings-impact-calculator"},
            {"label": "Read the earnings taper guide", "url": "/guides/universal-credit-if-my-wages-go-up"},
        ],
        "child-benefit": [
            {"label": "Compare Child Benefit with HICBC", "url": "/hicbc-calculator"},
            {"label": "Check Tax-Free Childcare", "url": "/tax-free-childcare-calculator"},
            {"label": "See child-count examples", "url": "/guides/how-much-child-benefit-for-1-2-3-children"},
        ],
        "pension-support": [
            {"label": "Run the Pension Credit calculator", "url": "/pension-credit-calculator"},
            {"label": "Check winter support", "url": "/winter-fuel-payment-checker"},
            {"label": "Read pensioner worked examples", "url": "/guides/pension-credit-examples-for-single-pensioner"},
        ],
        "disability-health": [
            {"label": "Use the PIP checker", "url": "/pip-eligibility-checker"},
            {"label": "Compare ESA and UC health routes", "url": "/guides/esa-vs-universal-credit"},
            {"label": "Read the PIP points explainer", "url": "/guides/pip-points-explained"},
        ],
        "housing-council-tax": [
            {"label": "Check council tax support", "url": "/council-tax-reduction-calculator"},
            {"label": "Check Housing Benefit", "url": "/housing-benefit-calculator"},
            {"label": "Read rent and council tax guidance", "url": "/guides/help-with-rent-and-council-tax"},
        ],
    }
    return mapping.get(cluster_for_slug(slug), mapping["universal-credit"])


def render_page(template: str, *, title: str, description: str, canonical_path: str, breadcrumbs_data: Optional[List[Dict[str, str]]] = None, **context):
    canonical_url = f"{SITE_URL}{canonical_path}"
    return render_template(
        template,
        title=title,
        meta_description=description,
        canonical_url=canonical_url,
        site_url=SITE_URL,
        now=now_utc(),
        adsense_client=ADSENSE_CLIENT,
        adsense_enabled=ENABLE_ADS,
        adsense_slot_content=ADSENSE_SLOT_CONTENT,
        adsense_slot_calculator=ADSENSE_SLOT_CALCULATOR,
        ga_measurement_id=GA_MEASUREMENT_ID,
        tax_year="2026/27",
        breadcrumbs=breadcrumbs_data or [],
        show_cross_links=False,
        **context,
    )


@app.route("/")
def home():
    featured = [CALCULATORS[slug] for slug in CALCULATOR_ORDER[1:7]]
    guide_cards = []
    for slug in GUIDE_ORDER[:6]:
        item = dict(GUIDES[slug])
        item["slug"] = slug
        guide_cards.append(item)
    home_calc_page = CALCULATORS["universal-credit-calculator"]
    home_form_state = parse_inputs(home_calc_page)
    home_estimate = CALCULATION_FUNCTIONS[home_calc_page["formula"]](home_form_state)
    scenario_guides = []
    for slug in [
        "universal-credit-if-my-wages-go-up",
        "universal-credit-if-partner-moves-in",
        "how-much-child-benefit-for-1-2-3-children",
        "pension-credit-examples-for-single-pensioner",
        "pip-points-explained",
        "child-benefit-tax-charge-examples",
    ]:
        if slug in GUIDES:
            item = dict(GUIDES[slug])
            item["slug"] = slug
            scenario_guides.append(item)
    situation_guides = []
    for slug in [
        "benefits-for-low-income-families",
        "help-with-rent-and-council-tax",
        "pension-credit-explained",
        "pip-explained-simply",
    ]:
        if slug in GUIDES:
            item = dict(GUIDES[slug])
            item["slug"] = slug
            situation_guides.append(item)
    return render_page(
        "landing.html",
        title="UK Benefits Calculator 2026 | Working Families, Universal Credit & Entitlement Check",
        description="Free UK benefits calculator 2026. Working families, single parents and pensioners: estimate Universal Credit, Child Benefit, Pension Credit, PIP, housing and childcare support using the latest 2026/27 rates.",
        canonical_path="/",
        breadcrumbs_data=[],
        home_calc_page=home_calc_page,
        home_form_state=home_form_state,
        home_estimate=home_estimate,
        home_estimate_visual=build_estimate_visual(home_estimate),
        featured_calculators=featured,
        all_calculators=[CALCULATORS[slug] for slug in CALCULATOR_ORDER],
        guide_cards=guide_cards,
        scenario_guides=scenario_guides,
        situation_guides=situation_guides,
        topic_hubs=[TOPIC_HUBS[slug] for slug in ["universal-credit", "family-support", "rent-and-council-tax", "disability-support", "pension-age-support"] if slug in TOPIC_HUBS],
        scenario_pages=[SCENARIO_PAGES[slug] for slug in ["what-happens-if-my-savings-increase", "what-happens-if-i-work-more-hours", "what-happens-if-my-partner-moves-in", "what-happens-if-my-rent-increases"] if slug in SCENARIO_PAGES],
        situation_pages=[SITUATION_PAGES[slug] for slug in ["benefits-for-working-families", "benefits-for-single-parents", "benefits-for-renters", "benefits-for-pensioners", "benefits-if-you-cannot-work", "benefits-in-northern-ireland"] if slug in SITUATION_PAGES],
        home_sources=page_sources("universal-credit-calculator"),
    )


@app.route("/calculators")
def calculators_index():
    return render_page(
        "calculators_index.html",
        title="UK benefits calculators and eligibility checkers",
        description="Browse calculators and checkers for Universal Credit, Child Benefit, HICBC, Pension Credit, PIP, council tax help, childcare support and seasonal payments.",
        canonical_path="/calculators",
        breadcrumbs_data=breadcrumbs({"name": "Calculators", "url": f"{SITE_URL}/calculators"}),
        tools=[CALCULATORS[slug] for slug in CALCULATOR_ORDER],
        topic_hubs=[TOPIC_HUBS[slug] for slug in ["universal-credit", "family-support", "rent-and-council-tax", "disability-support", "pension-age-support"] if slug in TOPIC_HUBS],
        scenario_pages=[SCENARIO_PAGES[slug] for slug in ["what-happens-if-my-savings-increase", "what-happens-if-i-work-more-hours", "what-happens-if-my-partner-moves-in", "what-happens-if-my-rent-increases"] if slug in SCENARIO_PAGES],
    )


@app.route("/guides")
def guides_index():
    return render_page(
        "guides_index.html",
        title="UK benefits guides",
        description="Plain-English guides covering Universal Credit, PIP, Pension Credit, family support, rent help and how UK benefit calculations work.",
        canonical_path="/guides",
        breadcrumbs_data=breadcrumbs({"name": "Guides", "url": f"{SITE_URL}/guides"}),
        guide_items=GUIDES,
        topic_hubs=[TOPIC_HUBS[slug] for slug in ["universal-credit", "family-support", "rent-and-council-tax", "disability-support", "pension-age-support"] if slug in TOPIC_HUBS],
        situation_pages=[SITUATION_PAGES[slug] for slug in ["benefits-for-working-families", "benefits-for-single-parents", "benefits-for-renters", "benefits-for-pensioners", "benefits-if-you-cannot-work", "benefits-in-northern-ireland"] if slug in SITUATION_PAGES],
        scenario_pages=[SCENARIO_PAGES[slug] for slug in ["what-happens-if-my-savings-increase", "what-happens-if-i-work-more-hours", "what-happens-if-my-partner-moves-in", "what-happens-if-my-rent-increases"] if slug in SCENARIO_PAGES],
    )


@app.route("/situations/<slug>")
def situation_page(slug: str):
    page = SITUATION_PAGES.get(slug)
    if not page:
        abort(404)
    calcs = [CALCULATORS[s] for s in page["related_calculators"] if s in CALCULATORS]
    guides = []
    for g_slug in page.get("related_guides", []):
        if g_slug in GUIDES:
            item = dict(GUIDES[g_slug])
            item["slug"] = g_slug
            guides.append(item)
    return render_page(
        "situation_page.html",
        title=f"{page['title']} | UK Benefits Calculator",
        description=page["description"],
        canonical_path=f"/situations/{slug}",
        breadcrumbs_data=breadcrumbs({"name": "Situations", "url": f"{SITE_URL}/situations"}, {"name": page["title"], "url": f"{SITE_URL}/situations/{slug}"}),
        page=page,
        related_calculators=calcs,
        related_guides=guides,
    )


@app.route("/what-if/<slug>")
def scenario_page(slug: str):
    page = SCENARIO_PAGES.get(slug)
    if not page:
        abort(404)
    calcs = [CALCULATORS[s] for s in page["related_calculators"] if s in CALCULATORS]
    guides = []
    for g_slug in page.get("related_guides", []):
        if g_slug in GUIDES:
            item = dict(GUIDES[g_slug])
            item["slug"] = g_slug
            guides.append(item)
    return render_page(
        "scenario_page.html",
        title=f"{page['title']} | UK Benefits Calculator",
        description=page["description"],
        canonical_path=f"/what-if/{slug}",
        breadcrumbs_data=breadcrumbs({"name": "What if", "url": f"{SITE_URL}/what-if"}, {"name": page["title"], "url": f"{SITE_URL}/what-if/{slug}"}),
        page=page,
        related_calculators=calcs,
        related_guides=guides,
    )


@app.route("/hub/<slug>")
def hub_page(slug: str):
    page = TOPIC_HUBS.get(slug)
    if not page:
        abort(404)
    calcs = [CALCULATORS[s] for s in page["related_calculators"] if s in CALCULATORS]
    guides = []
    for g_slug in page.get("related_guides", []):
        if g_slug in GUIDES:
            item = dict(GUIDES[g_slug])
            item["slug"] = g_slug
            guides.append(item)
    situations = [SITUATION_PAGES[s] for s in page.get("related_situations", []) if s in SITUATION_PAGES]
    scenarios = [SCENARIO_PAGES[s] for s in page.get("related_scenarios", []) if s in SCENARIO_PAGES]
    return render_page(
        "hub_page.html",
        title=f"{page['title']} | UK Benefits Calculator",
        description=page["description"],
        canonical_path=f"/hub/{slug}",
        breadcrumbs_data=breadcrumbs({"name": "Hubs", "url": f"{SITE_URL}/hub"}, {"name": page["title"], "url": f"{SITE_URL}/hub/{slug}"}),
        page=page,
        related_calculators=calcs,
        related_guides=guides,
        related_situations=situations,
        related_scenarios=scenarios,
    )


@app.route("/guides/<slug>")
def guide_page(slug: str):
    if slug == "pension-credit-who-can-claim":
        return redirect("/guides/pension-credit-explained", code=301)
    guide = GUIDES.get(slug)
    if not guide:
        abort(404)
    related_calc = related_calculators(guide.get("related", []))
    related_guides = []
    seen_related = set()
    for related_slug in guide.get("related_guides", []):
        if related_slug in GUIDES and related_slug != slug and related_slug not in seen_related:
            copy = dict(GUIDES[related_slug])
            copy["slug"] = related_slug
            related_guides.append(copy)
            seen_related.add(related_slug)
    for other_slug, item in GUIDES.items():
        if other_slug != slug and other_slug not in seen_related:
            copy = dict(item)
            copy["slug"] = other_slug
            related_guides.append(copy)
            seen_related.add(other_slug)
    return render_page(
        "guide_page.html",
        title=f"{guide['title']} | UK Benefits Calculator",
        description=guide["description"],
        canonical_path=f"/guides/{slug}",
        breadcrumbs_data=breadcrumbs({"name": "Guides", "url": f"{SITE_URL}/guides"}, {"name": guide["title"], "url": f"{SITE_URL}/guides/{slug}"}),
        guide=guide,
        slug=slug,
        faq_items=guide.get("faq", []),
        related_guides=related_guides[:6],
        related_calculators=related_calc,
        page_sources=page_sources(slug),
        next_steps=next_steps_for_slug(slug),
    )


@app.route("/<slug>")
def calculator_or_static(slug: str):
    if slug in CALCULATORS:
        page = CALCULATORS[slug]
        inputs = parse_inputs(page)
        estimate = CALCULATION_FUNCTIONS[page["formula"]](inputs)
        ordered_fields = ordered_fields_for_page(slug, page)
        ui_config = calculator_ui_config(slug, page)
        return render_page(
            "calculator.html",
            title=f"{page['title']} | UK Benefits Calculator",
            description=page["description"],
            canonical_path=f"/{slug}",
            breadcrumbs_data=breadcrumbs({"name": "Calculators", "url": f"{SITE_URL}/calculators"}, {"name": page["title"], "url": f"{SITE_URL}/{slug}"}),
            page=page,
            faq_items=page["faq"],
            form_state=inputs,
            estimate=estimate,
            estimate_visual=build_estimate_visual(estimate),
            ordered_fields=ordered_fields,
            ui_config=ui_config,
            result_highlights=calculator_result_highlights(slug, page, estimate, inputs),
            related_calculators=related_calculators(page["related"]),
            related_guides=related_guides_for_calculator(slug),
            page_sources=page_sources(slug),
            next_steps=next_steps_for_slug(slug),
        )
    if slug in CALCULATOR_ALIASES:
        return redirect(url_for("calculator_or_static", slug=CALCULATOR_ALIASES[slug]), code=301)
    if slug in STATIC_ROUTES:
        page = STATIC_PAGES[slug]
        return render_page(
            "static_page.html",
            title=f"{page['title']} | UK Benefits Calculator",
            description=page["content"][0],
            canonical_path=f"/{slug}",
            breadcrumbs_data=breadcrumbs({"name": page["title"], "url": f"{SITE_URL}/{slug}"}),
            page=page,
        )
    if slug in GUIDES:
        return redirect(f"/guides/{slug}", code=301)
    if slug in {"benefits-calculator", "benefits-calculator-uk"}:
        return redirect("/", code=301)
    abort(404)


@app.route("/html-sitemap")
@app.route("/sitemap")
@app.route("/sitemap.html")
def html_sitemap():
    return render_page(
        "html_sitemap.html",
        title="HTML sitemap | UK Benefits Calculator",
        description="HTML sitemap for UK Benefits Calculator.",
        canonical_path="/html-sitemap",
        breadcrumbs_data=breadcrumbs({"name": "HTML sitemap", "url": f"{SITE_URL}/html-sitemap"}),
        calculators=[CALCULATORS[slug] for slug in CALCULATOR_ORDER],
        guides=GUIDES,
        static_pages=STATIC_PAGES,
        situation_pages=SITUATION_PAGES,
        scenario_pages=SCENARIO_PAGES,
        topic_hubs=TOPIC_HUBS,
    )


@app.route("/trap")
def honeypot_trap():
    ip_str = _get_real_ip()
    if ip_str:
        _HONEYPOT_BLOCKED.add(ip_str)
    abort(403)


@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Allow: /\n"
        "Allow: /universal-credit-calculator\n"
        "Allow: /child-benefit-calculator\n"
        "Allow: /guides/what-benefits-can-i-claim\n"
        f"Sitemap: {SITE_URL}/sitemap.xml\n"
    )
    resp = make_response(body)
    resp.mimetype = "text/plain"
    return resp


@app.route("/ads.txt")
def ads_txt():
    pub_id = ADSENSE_CLIENT.replace("ca-pub-", "").strip()
    body = f"google.com, pub-{pub_id}, DIRECT, f08c47fec0942fa0\n" if pub_id else ""
    resp = make_response(body)
    resp.mimetype = "text/plain"
    return resp


@app.route("/favicon.ico")
def favicon():
    return send_from_directory("static", "favicon.ico")


@app.route("/site.webmanifest")
def site_webmanifest():
    return send_from_directory("static", "site.webmanifest")


@app.route("/apple-touch-icon.png")
def apple_touch_icon():
    return send_from_directory("static", "apple-touch-icon.png")


@app.route("/favicon-32x32.png")
def favicon_32():
    return send_from_directory("static", "favicon-32x32.png")


@app.route("/favicon-16x16.png")
def favicon_16():
    return send_from_directory("static", "favicon-16x16.png")


@app.route("/llms.txt")
def llms_txt():
    lines = [
        "UK Benefits Calculator",
        "",
        f"Home: {SITE_URL}/",
        f"Calculators: {SITE_URL}/calculators",
        f"Guides: {SITE_URL}/guides",
        "",
        "Popular calculators:",
        f"- Universal Credit calculator: {SITE_URL}/universal-credit-calculator",
        f"- Child Benefit calculator: {SITE_URL}/child-benefit-calculator",
        f"- Pension Credit calculator: {SITE_URL}/pension-credit-calculator",
        f"- PIP eligibility checker: {SITE_URL}/pip-eligibility-checker",
        f"- Council Tax Reduction estimator: {SITE_URL}/council-tax-reduction-calculator",
    ]
    resp = make_response("\n".join(lines))
    resp.mimetype = "text/plain"
    return resp


@app.route("/sitemap.xml")
def sitemap_xml():
    now = now_utc().date().isoformat()
    entries = [("/", "1.0", "weekly"), ("/calculators", "0.9", "weekly"), ("/guides", "0.9", "weekly"), ("/html-sitemap", "0.3", "monthly")]
    for slug in CALCULATOR_ORDER:
        entries.append((f"/{slug}", "0.8", "weekly"))
    for slug in GUIDE_ORDER:
        entries.append((f"/guides/{slug}", "0.7", "monthly"))
    for slug in STATIC_PAGES.keys():
        entries.append((f"/{slug}", "0.4", "monthly"))
    for slug in SITUATION_PAGES.keys():
        entries.append((f"/situations/{slug}", "0.7", "monthly"))
    for slug in SCENARIO_PAGES.keys():
        entries.append((f"/what-if/{slug}", "0.7", "monthly"))
    for slug in TOPIC_HUBS.keys():
        entries.append((f"/hub/{slug}", "0.7", "monthly"))
    xml = render_template("sitemap.xml", url_entries=[{"loc": f"{SITE_URL}{path}", "lastmod": now, "priority": priority, "changefreq": freq} for path, priority, freq in entries], now=now)
    resp = make_response(xml)
    resp.mimetype = "application/xml"
    return resp


@app.route("/api/calculate/<slug>")
def api_calculate(slug: str):
    if slug not in CALCULATORS:
        from flask import abort as _abort
        _abort(404)
    page = CALCULATORS[slug]
    inputs = parse_inputs(page)
    estimate = CALCULATION_FUNCTIONS[page["formula"]](inputs)
    visual = build_estimate_visual(estimate)
    from flask import jsonify as _jsonify
    return _jsonify({
        "primary_amount": estimate["primary_amount"],
        "primary_label": estimate["primary_label"],
        "secondary_amount": estimate["secondary_amount"],
        "secondary_label": estimate["secondary_label"],
        "summary": estimate.get("summary", ""),
        "breakdown": estimate.get("breakdown", []),
        "notes": estimate.get("notes", []),
        "visual": visual,
    })


@app.route("/health")
@app.route("/healthz")
def health_check():
    return {"status": "ok", "site": "ukbenefitscalculator", "updated": "2026-04-20"}


@app.errorhandler(404)
def not_found(_err):
    return (
        render_page(
            "404.html",
            title="Page not found | UK Benefits Calculator",
            description="The page could not be found.",
            canonical_path=request.path,
            breadcrumbs_data=[],
        ),
        404,
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
