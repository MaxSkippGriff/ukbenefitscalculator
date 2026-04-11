"""EmployerCalculator.co.uk Flask application."""

from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime
from typing import Dict, List

from dotenv import load_dotenv
from flask import Flask, abort, make_response, redirect, render_template, request, send_from_directory, url_for
from flask_limiter import Limiter

from calculator import (
    active_tax_year,
    EMPLOYMENT_ALLOWANCE_2024,
    EMPLOYMENT_ALLOWANCE_2025,
    MIN_EMPLOYER_PENSION_RATE,
    MIN_TOTAL_PENSION_RATE,
    SECONDARY_THRESHOLD_2024,
    SECONDARY_THRESHOLD_2025,
    TAX_YEAR,
    UPPER_SECONDARY_THRESHOLD,
    calculate_employer_cost,
    change_2025_vs_2024,
    employer_ni_2024,
    employer_ni_2025,
    monthly,
    salary_neighbours,
    weekly,
)

load_dotenv()

app = Flask(__name__)

CANONICAL_HOST = os.getenv("CANONICAL_HOST", "employercalculator.co.uk").replace("https://", "").replace("http://", "")
CANONICAL_HOST = CANONICAL_HOST[4:] if CANONICAL_HOST.startswith("www.") else CANONICAL_HOST
SITE_URL = f"https://{CANONICAL_HOST}"
GA_MEASUREMENT_ID = os.getenv("GA_MEASUREMENT_ID", "").strip()
ADSENSE_CLIENT = os.getenv("ADSENSE_CLIENT", "ca-pub-3932111812673824").strip()


limiter = Limiter(
    app=app,
    key_func=lambda: (request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or ""),
    default_limits=["100 per minute"],
    storage_uri="memory://",
    strategy="fixed-window",
)

_BLOCKED_SUBNETS = [
    # ── Singapore cloud / hosting (scraper source) ───────────────────────────
    ipaddress.ip_network("43.173.0.0/16"),     # Wangsu/CDNetworks
    ipaddress.ip_network("47.82.0.0/16"),      # Alibaba Cloud SG
    ipaddress.ip_network("47.128.0.0/16"),     # Alibaba Cloud SG (broader)
    ipaddress.ip_network("8.222.0.0/16"),      # Alibaba Cloud SG
    ipaddress.ip_network("47.245.0.0/16"),     # Alibaba Cloud SG
    ipaddress.ip_network("43.129.0.0/16"),     # Tencent Cloud SG
    ipaddress.ip_network("43.134.0.0/16"),     # Tencent Cloud SG
    ipaddress.ip_network("43.156.0.0/16"),     # Tencent Cloud SG
    ipaddress.ip_network("103.253.40.0/22"),   # Tencent Cloud SG
    ipaddress.ip_network("13.212.0.0/15"),     # AWS ap-southeast-1 (SG)
    ipaddress.ip_network("18.136.0.0/15"),     # AWS ap-southeast-1 (SG)
    ipaddress.ip_network("18.138.0.0/15"),     # AWS ap-southeast-1 (SG)
    ipaddress.ip_network("52.76.0.0/15"),      # AWS ap-southeast-1 (SG)
    ipaddress.ip_network("54.169.0.0/16"),     # AWS ap-southeast-1 (SG)
    ipaddress.ip_network("54.254.0.0/16"),     # AWS ap-southeast-1 (SG)
    ipaddress.ip_network("175.41.128.0/17"),   # AWS ap-southeast-1 (SG)
    ipaddress.ip_network("34.87.0.0/18"),      # GCP asia-southeast1 (SG)
    ipaddress.ip_network("34.126.64.0/18"),    # GCP asia-southeast1 (SG)
    ipaddress.ip_network("35.185.176.0/20"),   # GCP asia-southeast1 (SG)
    ipaddress.ip_network("35.240.176.0/20"),   # GCP asia-southeast1 (SG)
    ipaddress.ip_network("128.199.192.0/19"),  # DigitalOcean SG
    ipaddress.ip_network("68.183.160.0/19"),   # DigitalOcean SG
    ipaddress.ip_network("139.59.192.0/18"),   # DigitalOcean SG
    ipaddress.ip_network("104.238.160.0/20"),  # Vultr SG
    ipaddress.ip_network("172.104.160.0/20"),  # Akamai/Linode SG
    # ── Bytespider / ByteDance ───────────────────────────────────────────────
    ipaddress.ip_network("47.128.32.0/20"),    # Bytespider / ByteDance
    ipaddress.ip_network("110.249.200.0/22"),  # Bytespider alternate
]
_BLOCKED_UAS = ("bytespider", "petalbot", "ccbot", "omgili", "dataforseo", "scrapy", "python-httpx", "go-http-client")
# Known legitimate crawlers — exempt from browser fingerprint check
_GOOD_BOTS = (
    "googlebot", "google-inspectiontool", "adsbot-google", "mediapartners-google",
    "bingbot", "slurp", "duckduckbot", "baiduspider", "yandexbot",
    "applebot", "facebot", "linkedinbot", "twitterbot", "whatsapp",
    "telegrambot", "ia_archiver", "ahrefsbot", "semrushbot",
    # LLM crawlers
    "gptbot", "chatgpt-user", "claudebot", "anthropic-ai",
    "google-extended", "gemini", "perplexitybot", "youbot",
    "meta-externalagent", "amazonbot", "cohere-ai", "diffbot",
)
_HONEYPOT_BLOCKED: set = set()


def _get_real_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote_addr or "")


@app.before_request
def block_scrapers():
    ip_str = _get_real_ip()
    if ip_str in _HONEYPOT_BLOCKED:
        abort(403)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for subnet in _BLOCKED_SUBNETS:
            if ip_obj in subnet:
                abort(403)
    except ValueError:
        pass

    ua = request.headers.get("User-Agent", "").lower()

    # Hard-block known bad bots
    if any(b in ua for b in _BLOCKED_UAS):
        abort(403)

    # Allow known good crawlers through without further checks
    if any(g in ua for g in _GOOD_BOTS):
        return

    # Browser fingerprint check — real browsers always send Accept-Language.
    # Scrapers using requests/httpx/curl rarely do unless explicitly configured.
    # Only applies to HTML page requests (not assets, API calls, etc.)
    accept = request.headers.get("Accept", "")
    if "text/html" in accept:
        if not request.headers.get("Accept-Language"):
            abort(403)


@app.before_request
def enforce_canonical_host():
    host = (request.host or "").split(":")[0].lower()
    if not host:
        return None
    if host == f"www.{CANONICAL_HOST}":
        target = f"{SITE_URL}{request.full_path if request.query_string else request.path}"
        if target.endswith("?"):
            target = target[:-1]
        return redirect(target, code=301)
    return None


@app.after_request
def apply_cache_headers(response):
    path = request.path or ""
    if path.startswith("/static/"):
        # Avoid long-lived stale assets while UI is being iterated quickly.
        response.headers["Cache-Control"] = "public, max-age=300"
    elif path in ("/favicon.ico", "/site.webmanifest", "/apple-touch-icon.png", "/favicon-32x32.png", "/favicon-16x16.png"):
        response.headers["Cache-Control"] = "public, max-age=86400"
    elif path == "/robots.txt":
        # Keep robots TTL short so search-console live tests refresh quickly.
        response.headers["Cache-Control"] = "public, max-age=60"
    elif response.mimetype == "text/html":
        # Ensure browsers always fetch latest templates/styles.
        response.headers["Cache-Control"] = "private, no-store, max-age=0, must-revalidate"
    return response

SALARY_AMOUNTS = [
    18000, 19000, 20000, 21000, 22000, 23000, 24000, 25000, 26000, 27000,
    28000, 29000, 30000, 31000, 32000, 33000, 34000, 35000, 36000, 37000,
    38000, 39000, 40000, 41000, 42000, 43000, 44000, 45000, 46000, 47000,
    48000, 49000, 50000, 51000, 52000, 53000, 54000, 55000, 56000, 57000,
    58000, 59000, 60000, 61000, 62000, 63000, 64000, 65000, 66000, 67000,
    68000, 69000, 70000, 71000, 72000, 73000, 74000, 75000, 80000, 85000,
    90000, 95000, 100000, 110000, 120000, 130000, 140000, 150000, 175000, 200000,
]

TOOL_CARDS = [
    {"slug": "team-cost-planner", "title": "Team Payroll Cost Planner", "url": "/team-cost-planner", "description": "Model your entire team. Multiple employees, individual salaries, pension rates and overheads. Employment Allowance offset included.", "tag": "New"},
    {"slug": "employer-ni-calculator", "title": "Employer NI &amp; Total Cost", "url": "/calculator", "description": "Salary + NI at 15% + pension + overheads. Full employer cost with band breakdown for 2025/26.", "tag": "Live"},
    {"slug": "holiday-entitlement-calculator", "title": "Holiday Entitlement", "url": "/holiday-entitlement", "description": "Statutory and contractual holiday for full-time, part-time and mid-year starters.", "tag": "Live"},
    {"slug": "redundancy-pay-calculator", "title": "Redundancy Pay", "url": "/redundancy-pay", "description": "Statutory redundancy by age, service years and weekly pay. Includes PILON.", "tag": "Live"},
    {"slug": "maternity-pay-calculator", "title": "Statutory Maternity Pay", "url": "/maternity-pay", "description": "6-week higher rate + 33-week lower rate. Employer cost and SMP recovery.", "tag": "Live"},
    {"slug": "notice-period-calculator", "title": "Notice Period", "url": "/notice-period", "description": "Statutory vs contractual notice, exact end dates, and payment in lieu of notice.", "tag": "Live"},
    {"slug": "settlement-agreement-calculator", "title": "Settlement Agreement", "url": "/settlement-agreement", "description": "Estimate settlement value: notice, redundancy, compensatory amounts and tax treatment.", "tag": "Live"},
    {"slug": "pro-rata-salary-calculator", "title": "Pro Rata Salary", "url": "/pro-rata-salary", "description": "Convert full-time salary to part-time equivalent by days or hours per week.", "tag": "Live"},
    {"slug": "sick-pay-calculator", "title": "Statutory Sick Pay", "url": "/sick-pay", "description": "SSP eligibility, waiting days, weekly amounts and duration for 2025/26.", "tag": "Live"},
    {"slug": "pension-cost-calculator", "title": "Employer Pension Cost", "url": "/pension-cost", "description": "Auto-enrolment costs on qualifying earnings. Employer minimum, total minimum and opt-out rates.", "tag": "Live"},
    {"slug": "bradford-factor-calculator", "title": "Bradford Factor", "url": "/bradford-factor", "description": "Absence scoring for HR teams. Input episodes and days to calculate Bradford Factor score.", "tag": "Live"},
    {"slug": "unfair-dismissal-calculator", "title": "Unfair Dismissal Compensation", "url": "/unfair-dismissal", "description": "Basic award + compensatory award estimates. Updated for Employment Rights Act 2025 changes.", "tag": "Live"},
    {"slug": "apprenticeship-levy-calculator", "title": "Apprenticeship Levy Calculator", "url": "/apprenticeship-levy-calculator", "description": "Calculate apprenticeship levy liability for any payroll size. 0.5% above £3m wage bill with £15,000 annual allowance.", "tag": "New"},
]

GUIDES: Dict[str, Dict] = {
    "employer-ni-changes-2025": {
        "title": "Employer NI Changes April 2025 — Rate Up to 15%, Threshold Down to £5,000",
        "description": "From April 2025, employer NI rises from 13.8% to 15% and the secondary threshold drops from £9,100 to £5,000/year. See what this means for your payroll costs.",
        "topic": "Employer NI",
        "sections": [
            {
                "heading": "Employer NI 2025/26: the exact rule changes from 6 April 2025",
                "paragraphs": [
                    "If you searched for an NI rise calculator, these are the two numbers that matter for 2025/26: employer Class 1 NI is now 15% (up from 13.8%), and the secondary threshold is now £5,000 (down from £9,100). Both changes started on 6 April 2025 and apply to standard employer NI calculations.",
                    "Those two changes compound each other. A higher rate means each NIable pound costs more, and a lower threshold means more salary is NIable in the first place. This is why many employers saw a larger payroll cost increase than expected, even before pension, benefits, or recruitment overheads were added.",
                    "The policy package also increased Employment Allowance from £5,000 to £10,500 and removed the previous £100,000 eligibility cap. That relief is meaningful for eligible employers, but it does not reverse the structural NI rise for every business. Your net outcome depends on payroll size and whether allowance can be fully used.",
                ],
            },
            {
                "heading": "What the NI rise costs by salary: practical worked examples",
                "paragraphs": [
                    "At £30,000 salary, 2025/26 employer NI is approximately £3,750. Under 2024/25 rules, the equivalent NI was about £2,884. That is a rise of roughly £866 per employee per year. At £35,000, NI rises from about £3,575 to £4,500, adding around £915. At £40,000, NI moves from around £4,264 to £5,250, adding around £986.",
                    "At £50,000 salary, 2025/26 employer NI is around £6,750 compared with about £5,644 under 2024/25 assumptions, a rise near £1,106. At £75,000 salary, NI is around £10,500 versus about £9,094, adding around £1,406. At £100,000 salary, NI is around £14,250 versus about £12,544, adding around £1,706.",
                    "The pattern is simple: NI rise per employee generally grows with salary, but lower and mid salaries still face material absolute increases because the threshold fell sharply. For budgeting, run your actual salary mix instead of a single midpoint. A team with many £28k–£38k roles can see significant aggregate impact.",
                ],
            },
            {
                "heading": "From NI-only to true employer cost: what to include in decisions",
                "paragraphs": [
                    "NI is only one layer of recurring cost. For realistic hiring decisions, combine salary, employer NI, minimum pension, and your operational overhead assumptions. A £35,000 role can move from a headline salary to a total employer cost in the low-£40k range once statutory and operational components are included.",
                    "Auto-enrolment pension is usually modelled at a minimum employer contribution of 3% on qualifying earnings between £6,240 and £50,270. Above £50,270, pension qualifying earnings stop increasing for statutory minimum purposes, but employer NI continues with no upper cap. That shifts the cost mix as salaries rise.",
                    "Use monthly-first outputs for approvals and cashflow planning. Managers, finance teams, and founders usually decide faster with a clear monthly number plus annual total. If your process is still gross-salary-first, payroll pressure tends to appear late in the quarter when commitments are already made.",
                ],
            },
            {
                "heading": "How to use this as an NI rise calculator in practice",
                "paragraphs": [
                    "Step 1: model the role at current 2025/26 settings (15% above £5,000). Step 2: compare against 2024/25 baseline logic (13.8% above £9,100). Step 3: add pension and overhead assumptions. This gives a clean year-on-year variance you can use in budget notes, board packs, and offer sign-off.",
                    "Step 4: run the same salary with and without Employment Allowance where relevant. For eligible small employers, allowance can materially reduce net NI payable in-year. For larger payrolls, allowance may only offset an early part of annual liability, so do not assume the relief eliminates NI rise impact.",
                    "Step 5: document assumptions in plain English: tax year, threshold, NI rate, pension basis, allowance treatment, and overhead rule. Most reporting disputes come from assumption mismatch rather than calculation errors. A documented assumptions line makes finance, HR, and payroll conversations materially faster.",
                ],
            },
            {
                "heading": "Common mistakes to avoid in 2025/26 employer NI planning",
                "paragraphs": [
                    "Mistake one is using old thresholds in spreadsheets or offer calculators. A model still using £9,100 as secondary threshold will understate NI in 2025/26. Mistake two is quoting NI-only cost to hiring managers without pension and overheads, which causes recurring under-budgeting across multiple hires.",
                    "Mistake three is treating Employment Allowance as automatic. Eligibility still matters, and some company structures are excluded. Mistake four is assuming NI behaves like employee NI with an upper-rate reduction. Employer NI does not taper at higher salaries; 15% continues above threshold with no upper limit.",
                    "Mistake five is not refreshing planning pages in search and internal docs. If your team searches terms like “employer ni calculator 2025/26” or “ni rise calculator”, make sure they land on updated, assumption-led pages. Good decisions come from current-year inputs, consistent assumptions, and clear monthly outputs.",
                ],
            },
        ],
    },
    "true-cost-of-hiring": {
        "title": "The true cost of hiring an employee in the UK (2025/26)",
        "description": "A practical framework for calculating the full employer cost of hiring in 2025/26.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Salary is only the first line item",
                "paragraphs": [
                    "Employer cost starts with salary but quickly expands into NI, pension, onboarding, equipment, software and line-manager time. Most budgeting errors happen when salary is treated as the total cost baseline.",
                    "In 2025/26, employer NI is 15% above the £5,000 threshold. Auto-enrolment pension adds at least 3% of qualifying earnings. Combined, these statutory items can add a sizeable uplift before any operational overheads.",
                    "A robust model shows annual and monthly totals and reports cost above salary as a percentage. That percentage is useful for hiring managers who need a quick way to compare role options and timing.",
                ],
            },
            {
                "heading": "A repeatable cost model",
                "paragraphs": [
                    "Start with gross salary, then calculate employer NI on current-year rates and thresholds. Next add minimum employer pension on qualifying earnings. Finally include overhead assumptions that are specific to your organisation.",
                    "Overheads normally include laptop and peripherals, SaaS licences, security tooling, desk space, and training. For many office-based teams, £2,000 to £5,000 per employee per year is a common planning range.",
                    "Use one model template across finance and people teams so approval conversations are consistent. This reduces disputes created by conflicting spreadsheets.",
                ],
            },
            {
                "heading": "Using the model for decisions",
                "paragraphs": [
                    "Use monthly-first outputs for cash planning and annual outputs for headcount plans. Managers usually understand monthly burn faster, while finance needs annual totals for forecasting.",
                    "When comparing candidates or grades, evaluate the full cost delta, not salary delta. The NI and pension increments can materially change affordability near budget limits.",
                    "Treat the calculator as a decision aid, not legal advice. Employment law and contractual terms can introduce additional obligations beyond baseline statutory cost estimates.",
                ],
            },
        ],
    },
    "employment-allowance-guide": {
        "title": "Employment Allowance 2025/26: eligibility, claiming and examples",
        "description": "Eligibility rules, payroll claiming process and worked examples for Employment Allowance in 2025/26.",
        "topic": "Tax relief",
        "sections": [
            {
                "heading": "What Employment Allowance does",
                "paragraphs": [
                    "Employment Allowance reduces an eligible employer's annual Class 1 NI bill. For 2025/26 the maximum relief is £10,500, up from £5,000 in 2024/25.",
                    "The allowance is applied against employer NI liabilities through payroll reporting. It does not reduce employee NI and does not alter gross salary calculations.",
                    "For eligible small and medium employers, this can remove a large share of NI cost for one or more employees.",
                ],
            },
            {
                "heading": "Eligibility and exclusions",
                "paragraphs": [
                    "Businesses and charities can usually claim, subject to standard HMRC conditions. One key exclusion remains companies where the only paid employee is a director.",
                    "The previous £100,000 NI cap has been removed, so more employers can qualify in 2025/26 than in prior years.",
                    "Where group structures exist, payroll teams should confirm allowance treatment is applied correctly across connected entities.",
                ],
            },
            {
                "heading": "How to claim and monitor",
                "paragraphs": [
                    "Claiming is completed in payroll software using the Employment Allowance indicator in your Employer Payment Summary process.",
                    "Track allowance utilisation monthly. Once fully used, NI liabilities return at the standard rate for subsequent pay periods.",
                    "Keep internal documentation for audit and handover. The most common issue is not eligibility but inconsistent operational setup.",
                ],
            },
        ],
    },
    "auto-enrolment-pension-costs": {
        "title": "Auto-enrolment pension costs 2025/26: 3% minimum, qualifying earnings £6,240–£50,270",
        "description": "Employer auto-enrolment costs explained: minimum 3% on qualifying earnings £6,240–£50,270. A £30k salary costs ~£716/yr; a £50k salary costs ~£1,321/yr. Full breakdown with enrolment rules.",
        "topic": "Pensions",
        "sections": [
            {
                "heading": "Minimum contribution framework",
                "paragraphs": [
                    "For workplace pensions, the minimum total contribution is 8% of qualifying earnings, with at least 3% paid by the employer. The remaining 5% comes from the employee's own pay plus tax relief. Qualifying earnings are bounded by lower and upper limits set each April.",
                    "The employer element is not a simple percentage of full gross salary. It is calculated on the slice of salary that falls within the qualifying earnings band, unless the pension scheme uses a more generous certification basis. That means a £20,000 salary and a £50,000 salary do not attract proportionally equal pension costs.",
                    "In budgeting, pension should always be modelled alongside employer NI because both scale with pay and together move total employer cost materially above the headline salary figure.",
                ],
            },
            {
                "heading": "Qualifying earnings in practice",
                "paragraphs": [
                    "For 2025/26, qualifying earnings run from £6,240 to £50,270 per year. Earnings below the lower threshold are excluded from minimum contribution calculations — so a worker on £12,000 per year has pension calculated on £5,760 (£12,000 minus £6,240), not on the full £12,000.",
                    "For higher earners above £50,270, only earnings up to the upper limit are included for statutory minimum modelling. An employer contributing the legal minimum on a £70,000 salary pays 3% of £44,030 (£50,270 minus £6,240) — roughly £1,321 per year — not 3% of £70,000. Employers can choose to contribute on full salary as a company policy, but that is a voluntary enhancement above the statutory floor.",
                    "Understanding the qualifying earnings band logic matters because it avoids over-estimating pension cost for lower salaries and under-estimating it for mid-range ones. The full employer calculator models this band correctly for any salary you enter.",
                ],
            },
            {
                "heading": "Enrolment eligibility and timing",
                "paragraphs": [
                    "Eligible workers are those aged 22 to State Pension Age earning above £10,000 per year from a single employer. They must be enrolled automatically within six weeks of their start date. Workers aged 16–21 or above State Pension Age, or earning between £6,240 and £10,000, have the right to opt into a pension scheme but cannot be enrolled without requesting it.",
                    "Employees can opt out within one calendar month of being enrolled. If they do, their contributions are refunded and yours stop. Crucially, employers must re-enrol eligible workers every three years regardless of previous opt-outs — this is a legal duty, not a choice.",
                    "Keep records of enrolment dates, opt-out requests and re-enrolment cycles. The Pensions Regulator carries out compliance checks and the fine for failure to re-enrol can run into thousands of pounds per day for larger employers.",
                ],
            },
            {
                "heading": "Budgeting and communication",
                "paragraphs": [
                    "Set a standard pension assumption in all hiring plans and make exceptions explicit. Using different pension bases across departments — some on qualifying earnings, some on full salary — makes role cost comparisons misleading. Standardise the basis and note it alongside salary when presenting headcount budgets.",
                    "Where you offer above-minimum employer contributions — common at 5% or 10% — publish the policy clearly so managers can explain total package value accurately in job offers. Higher pension contributions are a genuine differentiator in hiring but only when candidates understand them.",
                    "Reconcile pension cost forecasts to payroll monthly, especially where salary changes, new starters, opt-outs or opt-ins happen during the year. Pension cost is easy to under-budget mid-year if it is only modelled at the point of hire.",
                ],
            },
        ],
    },
    "redundancy-process-guide": {
        "title": "Redundancy Process UK 2025/26: Step-by-Step Employer Guide With Costs",
        "description": "A practical employer guide to redundancy process, statutory pay, notice and risk control in 2025.",
        "topic": "Redundancy",
        "sections": [
            {
                "heading": "Statutory redundancy pay: how the calculation works",
                "paragraphs": [
                    "Statutory redundancy pay is calculated using three variables: age, complete years of service (up to 20), and weekly pay (capped at £643 per week from April 2024). The multiplier is 0.5 weeks for each year worked under age 22, 1 week for each year aged 22–40, and 1.5 weeks for each year aged 41 and above.",
                    "As a worked example: an employee aged 38 with 8 years of service on a £35,000 salary (weekly pay £673, capped at £643) would receive 8 × 1 × £643 = £5,144 in statutory redundancy pay. The first £30,000 of redundancy payments is generally free from income tax.",
                    "Many employers offer enhanced redundancy terms beyond the statutory minimum, particularly for longer-serving employees. Where enhanced terms exist, document them clearly in employment contracts or a standalone redundancy policy so they are enforceable and consistently applied.",
                ],
            },
            {
                "heading": "Notice pay and payment in lieu of notice",
                "paragraphs": [
                    "Statutory minimum notice is one week for each complete year of service, up to a maximum of 12 weeks. Contracts often specify longer notice periods, in which case the contractual period applies. Notice must be served or bought out — whichever is the right approach depends on the circumstances and contract terms.",
                    "Payment in lieu of notice (PILON) is taxed as earnings where there is a contractual PILON clause. Where there is no contractual right, tax treatment is more complex; take payroll or legal advice before paying PILON without a clause. Accrued but untaken holiday must also be paid out on termination.",
                    "Include notice and holiday pay in your redundancy cost model from the outset. Both are legal obligations and are easily missed when the focus is on the headline redundancy payment. For a £35,000 employee with 3 months notice, PILON represents approximately £8,750, which can dwarf the statutory redundancy amount.",
                ],
            },
            {
                "heading": "Process steps and consultation obligations",
                "paragraphs": [
                    "For individual redundancies, employers must follow a fair process: establish a genuine redundancy situation, apply fair selection criteria, consult meaningfully with the affected employee, and consider suitable alternative roles. For 20 or more redundancies in 90 days, collective consultation rules apply and minimum 45-day consultation periods are required.",
                    "Documentation is as important as the arithmetic. Keep consultation records, scoring evidence, meeting notes and all written communications. Employment tribunals frequently find in employees' favour not because the redundancy was commercially unjustified but because the process was flawed or inconsistently applied.",
                    "If using a scoring matrix for selection, apply it consistently and document rationale for each decision. Avoid criteria that could be directly or indirectly discriminatory, such as selecting solely on absence records where protected characteristics are linked to the absences.",
                ],
            },
            {
                "heading": "Total cost modelling for redundancy decisions",
                "paragraphs": [
                    "A complete redundancy cost model should include: statutory redundancy pay, contractual notice or PILON, accrued holiday pay, any enhanced terms, settlement agreement value where applicable, and professional support costs. It should also include the ongoing salary saving used to justify the decision.",
                    "Calculate the payback period: total redundancy cost divided by monthly salary saving gives the number of months before the business breaks even. For a £35,000 role costing £18,000 to exit, with a monthly saving of £2,916, payback is approximately 6.2 months. Decisions made without this figure tend to be harder to defend at senior review.",
                    "Where settlement is likely, model a realistic settlement scenario alongside the statutory baseline. Settlement agreements typically exceed the statutory minimum in exchange for a waiver of employment tribunal claims. Legal costs, both employer-side and the contribution to employee advice, should be included in the settlement total.",
                ],
            },
            {
                "heading": "Reducing operational and legal risk",
                "paragraphs": [
                    "The most common redundancy legal risks are: failure to consult meaningfully, inconsistent selection criteria, failure to consider alternative roles, and procedural irregularities (wrong notice, wrong pay). Addressing these before the process starts is cheaper than resolving them after an employment tribunal claim.",
                    "Brief line managers before any employee-facing meetings. Inconsistent messages between HR and line management, or promises made informally by managers, can undermine process integrity. Use a script or talking points for difficult conversations.",
                    "Where legal risk is elevated — for example where the employee has or may claim a protected characteristic, or where unfair dismissal risk is real — take employment law advice before serving notice. The cost of early legal advice is almost always less than tribunal defence costs.",
                ],
            },
        ],
    },
    "employment-rights-act-2025": {
        "title": "Employment Rights Act 2025: what employers need to know",
        "description": "Operational implications of Employment Rights Act 2025 reforms for UK employers, including unfair dismissal day one rights, flexible working and zero-hours changes.",
        "topic": "Legislation",
        "sections": [
            {
                "heading": "The key changes employers need to prepare for",
                "paragraphs": [
                    "The Employment Rights Act 2025 introduces the most significant expansion of employee rights in a generation. The headline change is the removal of the two-year qualifying period for unfair dismissal claims, making unfair dismissal protection a day-one right for most employees. The practical implication is that probation periods will need to be better managed and more consistently applied.",
                    "Other significant changes include: flexible working becoming a default right from day one; zero-hours workers gaining the right to guaranteed hours contracts based on their regularly worked pattern; third-party harassment rules being strengthened; and trade union access rights being expanded.",
                    "Not all reforms have confirmed implementation dates. Leadership teams should separate confirmed commencement orders from proposals still in consultation. Planning against unconfirmed assumptions creates effort that may need to be re-done when dates slip.",
                ],
            },
            {
                "heading": "Day-one unfair dismissal: practical implications",
                "paragraphs": [
                    "Once day-one unfair dismissal protection is in force, employers cannot simply dismiss employees during a probation period without following a fair process. The government has indicated that probation periods of up to nine months will be the relevant framework, with a statutory procedure expected to apply during that window.",
                    "In practice, this means probation management needs to become more structured. Clear performance objectives at the start of employment, documented mid-probation reviews, and formal probation failure conversations with evidence all become more important. The risk of an informal 'this isn't working' conversation followed by immediate dismissal is materially higher than under the current two-year qualifying period.",
                    "Review your probation policy and manager training before implementation. Line managers are often the weakest link in probation management because they are not trained to give honest performance feedback early enough for it to be documented and acted on within the probation window.",
                ],
            },
            {
                "heading": "Flexible working and zero-hours changes",
                "paragraphs": [
                    "Flexible working is already a day-one right to request since April 2024, but the Employment Rights Act extends this by limiting the grounds on which employers can refuse. Where flexible working is refused, the reasons must be demonstrably reasonable and documented. This raises the bar above the current eight statutory grounds for refusal.",
                    "Zero-hours and minimum-hours workers who work a regular pattern over a reference period will be entitled to a guaranteed-hours contract reflecting that pattern. Employers who rely on zero-hours arrangements for operational flexibility will need to either accept that pattern becoming contractual or restructure rotas to avoid regularity. Both approaches carry cost and administrative implications.",
                    "Review your workforce composition before implementation. Zero-hours usage is not uniformly problematic — some workers genuinely prefer flexibility — but where it is being used to avoid employment cost and legal risk, that model will need to change.",
                ],
            },
            {
                "heading": "Workforce planning and cost implications",
                "paragraphs": [
                    "The combined effect of these reforms is to increase the average cost and legal risk of employing people, particularly for lower-paid and variable-hours workers. Employers should update their hiring cost models to include a higher provision for probation management, performance process time, and potential settlement costs for early-stage dismissals.",
                    "Structured onboarding and probation programmes — which are good practice regardless of legislation — become more valuable as legal protection for day-one rights. Employers who already run well-documented probation processes will see less disruption than those who rely on informality.",
                    "Use the next six months before implementation to complete the gap review: contracts, handbooks, probation policies, manager training, flexible working procedure and zero-hours audit. Set one deployment date for updated documentation so that all managers are working from the same version.",
                ],
            },
            {
                "heading": "Building a compliant cost model",
                "paragraphs": [
                    "Every significant employment law change creates a corresponding administration cost that rarely appears in headcount budgets. Estimate the time cost of better probation management, more flexible working requests, guaranteed-hours reviews and any workforce consultation requirements. That time has a real payroll value.",
                    "Where the legal risk of day-one dismissal is real (for example, a hire into a business-critical role that does not work out within a few months), model a potential settlement scenario alongside the direct employment cost. Having that number visible in advance makes the decision to hire — or to take legal advice — faster.",
                    "Track compliance ownership clearly across HR, payroll and line management. When policy changes interact with payroll rules, out-of-date processes create avoidable errors. Assign named owners for each area of the reform and review compliance quarterly for the first year.",
                ],
            },
        ],
    },
    "hiring-costs-london": {
        "title": "Cost of hiring in London (2025/26): employer NI, pension and salary benchmarks",
        "description": "Employer cost of hiring in London for 2025/26. Typical salary bands, employer NI at 15%, pension and total monthly cost at common London pay levels.",
        "topic": "London hiring",
        "sections": [
            {
                "heading": "Typical London salary bands and employer NI cost",
                "paragraphs": [
                    "London salary levels are significantly higher than the UK average across most sectors. For 2025/26, employer NI is 15% on earnings above the £5,000 secondary threshold. At a £40,000 London salary (common for early-to-mid career roles), employer NI is £5,250 per year (£437.50 per month). At £50,000, NI is £6,750 per year (£562.50 per month). At £60,000, it rises to £8,250 per year (£687.50 per month).",
                    "Adding minimum employer pension on qualifying earnings increases these figures. At £40,000, pension is approximately £1,013 per year; at £50,000 it is approximately £1,321 per year (capped at the qualifying earnings upper limit of £50,270). Total employer cost above salary at £40,000 is therefore around £6,263 per year, or £522 per month.",
                    "For London roles offering salary sacrifice pension, the pension cost comes from pre-tax salary, which reduces the employer NI base slightly. At £50,000 with 5% salary sacrifice, the NIable pay falls to £47,500, reducing employer NI to approximately £6,375 per year compared with £6,750 on the full salary.",
                ],
            },
            {
                "heading": "London vs national hiring cost comparison",
                "paragraphs": [
                    "London employers face a dual cost premium: higher gross salaries and proportionally higher employer NI on those salaries. A role that benchmarks at £30,000 in a northern city might benchmark at £40,000 in London — adding £1,500 more in employer NI alone (£4,500 London vs £3,750 on a £30,000 salary).",
                    "The employment allowance (up to £10,500 per year) can partially offset this for eligible employers with annual NI below that threshold. A small London business with three employees averaging £35,000 in salary generates approximately £13,500 in annual employer NI — still above the allowance ceiling, so the offset is partial.",
                    "Remote work has changed London hiring dynamics. Many employers now hire at London salary rates for roles that can be performed from anywhere, while others use regional salary banding to pay market rates by location. Either approach has employer NI implications because NI follows the employee's salary, not their location.",
                ],
            },
            {
                "heading": "Practical London hiring cost checklist",
                "paragraphs": [
                    "Before committing to a London hire, model: gross salary, employer NI (15% above £5,000), minimum pension, and your operational overhead assumption. For London, equipment, software licences and any desk or office space allocation should be priced explicitly. A common range for operational overhead is £3,000–£6,000 per employee per year for an office-based role.",
                    "For London senior roles above £100,000, note that employer NI continues at 15% with no upper cap. A £120,000 salary generates £17,250 in employer NI annually (£1,437.50 per month). Pension for that salary caps at the qualifying earnings upper limit — the employer minimum contribution is approximately £1,321 per year regardless of how far above £50,270 the salary sits.",
                    "Use the employer cost calculator to model the exact NI and pension for any London salary. Input the salary, set pension rate and overhead assumption, and record both monthly and annual totals as your hiring baseline. This output is the number to use in headcount approval, not gross salary alone.",
                ],
            },
        ],
    },
    "hiring-costs-manchester": {
        "title": "Cost of hiring in Manchester (2025/26): employer NI and total hiring costs",
        "description": "Employer cost of hiring in Manchester for 2025/26. Common salary ranges, employer NI at 15% and total cost above salary at typical Manchester pay levels.",
        "topic": "Manchester hiring",
        "sections": [
            {
                "heading": "Manchester salary benchmarks and employer NI",
                "paragraphs": [
                    "Manchester is one of the UK's strongest regional hiring markets, with salary levels ranging from £24,000–£30,000 for entry roles to £45,000–£65,000 for senior individual contributors and team leads in tech, finance and professional services. For 2025/26, employer NI is 15% on earnings above the £5,000 secondary threshold.",
                    "At a £30,000 Manchester salary, employer NI is £3,750 per year (£312.50 per month). At £35,000, NI is £4,500 per year (£375 per month). At £45,000, it is £6,000 per year (£500 per month). Adding minimum employer pension at 3% of qualifying earnings: at £35,000 the pension cost is approximately £863 per year, giving a total above-salary cost of £5,363 per year (£447 per month).",
                    "Manchester's growing tech sector includes significant demand for roles in the £35,000–£55,000 band. At £50,000, total employer cost above salary is approximately £8,071 per year (NI £6,750 plus pension £1,321), making the total annual cost around £58,071 for that hire.",
                ],
            },
            {
                "heading": "Manchester cost of hiring versus London",
                "paragraphs": [
                    "Manchester salary benchmarks are typically 15–25% below London for comparable roles, though the gap is narrowing in tech and financial services. The employer NI difference compounds this: at £35,000 (a common Manchester mid-career benchmark) versus £45,000 (a more common London equivalent), the annual NI difference is £1,500 per employee.",
                    "For employers with operations in both cities, this means Manchester-based headcount carries lower NI per employee, even before accounting for lower salary. Employment Allowance — which can offset up to £10,500 of employer NI for eligible businesses — may be fully usable by a Manchester team where it only partially offsets London NI bills.",
                    "Operational overhead assumptions also differ. Manchester office space and equipment costs are lower than London equivalents, though the gap has narrowed as demand for Manchester office space has grown. Use local market rates for workspace and benchmark salary data for your sector before finalising a hiring cost model.",
                ],
            },
            {
                "heading": "Using this for Manchester headcount approval",
                "paragraphs": [
                    "For a headcount approval presentation, the most useful format is: role title, gross salary, monthly employer NI, monthly pension, monthly overhead, and total monthly cost. This is more useful to finance and founders than annual gross salary because it shows recurring cashflow impact.",
                    "Use the employer cost calculator to generate the NI and pension components, then add your overhead assumption. Document the pension basis (qualifying earnings minimum, or full salary) and overhead rule (per-employee figure or shared cost allocation). Consistent documentation means re-approvals later in the year use the same framework.",
                    "For growing Manchester teams, model a hiring plan across the next 12 months with monthly NI running totals. This helps identify whether Employment Allowance will be fully absorbed during the year and shows when NI liability starts compounding materially.",
                ],
            },
        ],
    },
    "hiring-costs-birmingham": {
        "title": "Cost of hiring in Birmingham (2025/26): employer NI and salary benchmarks",
        "description": "Employer hiring costs in Birmingham for 2025/26. Salary ranges, employer NI at 15%, pension and total cost at common Birmingham pay levels.",
        "topic": "Birmingham hiring",
        "sections": [
            {
                "heading": "Birmingham salary levels and employer NI",
                "paragraphs": [
                    "Birmingham is the UK's second largest city economy with a diverse hiring market spanning financial services, professional services, manufacturing, public sector and a growing tech sector. Salary ranges vary significantly by sector: £22,000–£30,000 for entry roles, £30,000–£50,000 for experienced hires, and £50,000–£75,000 for senior management and technical specialists.",
                    "At a £30,000 Birmingham salary, employer NI for 2025/26 is £3,750 per year (£312.50 per month). At £35,000, NI is £4,500 per year (£375 per month). At £40,000, NI is £5,250 per year (£437.50 per month). Adding 3% employer pension at £35,000: approximately £863 per year, making total above-salary cost around £5,363 per year (£447 per month).",
                    "Birmingham HMRC processing and financial services roles, and the growing professional services cluster, often benchmark between £28,000 and £45,000. HS2 and infrastructure projects have created additional demand in engineering and project management at higher salary bands.",
                ],
            },
            {
                "heading": "Employment Allowance impact for Birmingham employers",
                "paragraphs": [
                    "Employment Allowance (up to £10,500 for eligible employers in 2025/26) can be particularly valuable for growing Birmingham businesses. A team of four employees averaging £32,000 in salary generates approximately £16,200 in annual employer NI — allowance offsets the first £10,500, leaving a net NI liability of approximately £5,700 for the year.",
                    "For Birmingham small and medium employers, the removal of the previous £100,000 NI bill eligibility cap in 2025/26 means more businesses can now claim. Previously, businesses with NI bills above £100,000 were excluded; that restriction has now been lifted. Check eligibility (solo-director companies remain excluded) and claim through your payroll software.",
                    "For Birmingham employers near the Employment Allowance ceiling, model the full-year position monthly. The allowance offsets cumulative employer NI in-year; once used, standard rates apply from that point forward. This affects cashflow particularly in the second half of the tax year.",
                ],
            },
            {
                "heading": "Building a Birmingham hiring cost model",
                "paragraphs": [
                    "For a repeatable Birmingham hiring cost model, use: gross salary, 15% NI on earnings above £5,000, 3% pension on qualifying earnings, and an overhead assumption specific to your operational setup. Birmingham office and equipment costs are broadly similar to Manchester and lower than London equivalents.",
                    "For mixed Birmingham headcount (some office-based, some remote), use a consistent overhead assumption or document different rates by work type. Finance teams reviewing headcount approval find inconsistent overhead assumptions confusing and may apply their own, potentially incorrect, figures.",
                    "Use the employer cost calculator to produce the NI and pension baseline for any Birmingham salary. Combine that with your overhead assumption to create the complete monthly hiring cost number. Review quarterly, particularly around budget reviews or when salary bands are adjusted.",
                ],
            },
        ],
    },
    "hiring-costs-edinburgh-scotland": {
        "title": "Cost of hiring in Scotland (2025/26): employer NI and Scottish payroll considerations",
        "description": "Employer cost of hiring in Scotland for 2025/26. Employer NI at 15%, Scottish income tax context, pension and total hiring costs at common Scottish salary levels.",
        "topic": "Scotland hiring",
        "sections": [
            {
                "heading": "Employer NI in Scotland: what is and is not different",
                "paragraphs": [
                    "Employer National Insurance is UK-wide. Scottish employers pay the same 15% employer NI on earnings above £5,000 as employers anywhere else in the UK. Scottish income tax (which uses five bands with rates from 19% to 48%) is deducted from employees' wages and does not affect employer NI or pension contributions.",
                    "At a £35,000 salary in Edinburgh or Glasgow, employer NI is £4,500 per year (£375 per month) — exactly the same as in Manchester or Birmingham at the same salary. Pension cost at 3% minimum is approximately £863 per year. Total employer cost above salary is around £5,363 per year.",
                    "For employers comparing Scottish and rUK headcount, the employer cost model is identical for the same salary. The difference appears on the employee's payslip — Scottish income tax reduces take-home pay at mid and higher salaries compared with rUK — which can affect recruitment, retention and salary negotiation dynamics.",
                ],
            },
            {
                "heading": "Scottish salary benchmarks and hiring context",
                "paragraphs": [
                    "Edinburgh and Glasgow are the two major Scottish hiring centres. Edinburgh has a strong financial services cluster (Standard Life, Baillie Gifford, fund administration) alongside legal, technology and public sector employers. Glasgow has broader private sector diversity including financial services, retail, logistics and growing tech.",
                    "Scottish salary benchmarks are generally 5–15% below London for equivalent roles, and broadly comparable with other major UK regional cities. Edinburgh financial services roles and technology roles in both cities have seen upward salary pressure, with some roles now benchmarking close to London levels for specialist skills.",
                    "Aberdeen salary levels in energy and engineering can vary significantly with commodity cycles. During peak periods, offshore and subsea roles commanded significant premia that are less common now. Model Aberdeen salaries against current market benchmarks rather than historical peaks.",
                ],
            },
            {
                "heading": "Employee awareness of Scottish income tax in hiring",
                "paragraphs": [
                    "Scottish income tax affects take-home pay at mid and higher salary levels. A £45,000 salary produces a slightly lower net monthly take-home under Scottish rules than under rUK — approximately £60–£90 per month less depending on deduction settings. For employers hiring from outside Scotland, this is sometimes a surprise to candidates during offer negotiation.",
                    "Being transparent about Scottish income tax in offer discussions — and pointing candidates to reliable net pay comparison tools — reduces late-stage negotiation friction. Candidates who understand the tax position early are less likely to request last-minute salary uplifts.",
                    "For relocating employees, the change in income tax region happens when they become Scottish resident (main home in Scotland). This is handled via payroll and HMRC; employers should notify payroll when a relocation takes effect so the correct tax code is applied.",
                ],
            },
        ],
    },
    "hiring-costs-leeds": {
        "title": "Cost of Hiring in Leeds (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Leeds for 2025/26. Salary benchmarks across NHS, finance and tech, employer NI at 15%, pension and total above-salary cost at common Leeds pay levels.",
        "topic": "Leeds hiring",
        "sections": [
            {
                "heading": "Leeds salary benchmarks and employer NI",
                "paragraphs": [
                    "Leeds is one of the UK's largest regional economies, with major employment clusters in financial services, legal, NHS and public sector, digital technology and professional services. Entry-level roles typically range from £22,000–£28,000; experienced hires from £30,000–£50,000; senior and specialist roles from £50,000–£80,000.",
                    "At a £30,000 Leeds salary, employer NI for 2025/26 is £3,750 per year (£312.50 per month). At £35,000, NI is £4,500 per year (£375 per month). Adding 3% employer pension at £35,000 adds approximately £863 per year, making total above-salary cost around £5,363 per year (£447 per month).",
                    "Leeds Teaching Hospitals NHS Trust is one of Europe's largest, alongside West Yorkshire ICB and Leeds City Council — making public sector a significant part of the Leeds hiring market. NHS Agenda for Change pay bands drive many hiring decisions at Bands 2–8.",
                ],
            },
            {
                "heading": "Employment Allowance for Leeds employers",
                "paragraphs": [
                    "Employment Allowance (up to £10,500 for eligible employers in 2025/26) is available to most Leeds SMEs and reduces the employer NI bill directly. A team of four employees averaging £32,000 generates approximately £16,200 in annual employer NI — allowance covers the first £10,500, leaving a net NI liability of £5,700.",
                    "Single-director limited companies cannot claim Employment Allowance if the director is the only employee paid above the secondary threshold. Confirm eligibility with your payroll provider or accountant before applying.",
                ],
            },
            {
                "heading": "Total cost of a Leeds hire: worked example",
                "paragraphs": [
                    "For a £35,000 salary: employer NI £4,500 + pension £863 + typical overheads (recruitment, equipment, workspace) of £3,000 = total employer cost approximately £43,363 per year. Monthly equivalent: £3,614.",
                    "Use the calculator to model any Leeds salary with custom pension percentage and overhead assumptions. The cost-of-employing hub shows pre-calculated totals for common salary levels.",
                ],
            },
        ],
    },
    "hiring-costs-liverpool": {
        "title": "Cost of Hiring in Liverpool (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Liverpool for 2025/26. Salary benchmarks, employer NI at 15%, pension and total above-salary cost at common Liverpool pay levels.",
        "topic": "Liverpool hiring",
        "sections": [
            {
                "heading": "Liverpool salary benchmarks and employer NI",
                "paragraphs": [
                    "Liverpool's economy spans logistics and maritime, healthcare, financial services, digital and creative industries, and higher education (University of Liverpool, Liverpool John Moores, Hope). Salaries typically range from £22,000–£28,000 for entry roles to £35,000–£55,000 for experienced professionals.",
                    "At £30,000, employer NI for 2025/26 is £3,750 per year. At £35,000, NI is £4,500 per year (£375 per month). Adding 3% pension at £35,000 costs approximately £863 per year. Total above-salary cost at £35,000: around £5,363 per year.",
                    "Liverpool City Region's healthcare and logistics sectors generate consistent PAYE hiring demand. The port and distribution economy sustains significant numbers of roles at £22,000–£30,000, while financial services and professional services anchor mid-market hiring.",
                ],
            },
            {
                "heading": "Total cost of a Liverpool hire: worked example",
                "paragraphs": [
                    "For a £32,000 salary: employer NI £4,050 + pension £776 + overheads £2,500 = total employer cost approximately £39,326 per year. Monthly: £3,277.",
                    "Model any Liverpool salary in the calculator. Employment Allowance of up to £10,500 can significantly reduce the NI component for eligible employers.",
                ],
            },
        ],
    },
    "hiring-costs-bristol": {
        "title": "Cost of Hiring in Bristol (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Bristol for 2025/26. Salary benchmarks in tech, aerospace and financial services, employer NI at 15%, pension and total cost.",
        "topic": "Bristol hiring",
        "sections": [
            {
                "heading": "Bristol salary benchmarks and employer NI",
                "paragraphs": [
                    "Bristol has one of the UK's strongest regional economies, with high-productivity clusters in aerospace and defence (Airbus, Rolls-Royce), financial services (Lloyds Banking Group), digital technology and creative industries. Salary levels are above most UK regional cities — technology and engineering roles frequently benchmark at £40,000–£70,000.",
                    "At £40,000, employer NI for 2025/26 is £5,250 per year (£437.50 per month). At £50,000, NI is £6,750 per year (£562.50 per month). Adding 3% pension at £40,000 adds approximately £1,013 per year. Total above-salary cost at £40,000: approximately £6,263 per year (£522 per month).",
                    "Bristol's tech and aerospace premium means employers often need to budget for above-average salaries. Use the calculator to model accurate employer NI at Bristol's typical pay levels.",
                ],
            },
            {
                "heading": "Total cost of a Bristol hire: worked example",
                "paragraphs": [
                    "For a £45,000 salary in Bristol: employer NI £6,000 + pension £1,150 + overheads £3,000 = total employer cost approximately £55,150 per year. Monthly: £4,596.",
                    "Bristol's higher-than-average salaries mean employer NI and pension costs are proportionally higher. Model your specific role in the calculator for an accurate breakdown.",
                ],
            },
        ],
    },
    "hiring-costs-edinburgh": {
        "title": "Cost of Hiring in Edinburgh (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Edinburgh for 2025/26. Scottish salary benchmarks, employer NI at 15%, pension and total above-salary cost. Note: employer NI is a UK-wide rate — Scottish income tax does not affect employer payroll costs.",
        "topic": "Edinburgh hiring",
        "sections": [
            {
                "heading": "Edinburgh salary benchmarks and employer NI",
                "paragraphs": [
                    "Edinburgh is Scotland's financial and professional services capital, with strong demand for finance, legal, technology, public sector and tourism roles. Salary levels are broadly comparable with Manchester and Leeds, though financial services and tech roles can benchmark close to London rates. Entry-level roles typically start at £24,000–£28,000; experienced professionals in financial services and law often earn £45,000–£80,000.",
                    "Employer NI in Edinburgh is the same as anywhere in the UK: 15% on earnings above the £5,000 secondary threshold for 2025/26. At £35,000, employer NI is £4,500 per year (£375 per month). At £45,000, it is £6,000 per year (£500 per month). Adding 3% pension at £45,000 adds £1,163 per year. Total above-salary cost at £45,000: approximately £7,163 per year.",
                    "Edinburgh's major employers include Standard Life Aberdeen, Baillie Gifford, Lloyds Banking Group (Halifax/Bank of Scotland), NHS Lothian and the Scottish Government. The financial services sector benchmarks strongly against UK peers, and recruitment competition with London firms is a factor for senior hires.",
                ],
            },
            {
                "heading": "Total cost of an Edinburgh hire: worked example",
                "paragraphs": [
                    "For a £40,000 salary in Edinburgh: employer NI £5,250 + pension £1,013 + overheads £3,000 = total employer cost approximately £49,263 per year. Monthly: £4,105. Note that the employee's Scottish income tax is not an employer liability — it is deducted from the employee's pay via PAYE.",
                    "Employment Allowance of up to £10,500 can offset NI costs for eligible Edinburgh employers. Use the calculator to model your specific salary and headcount.",
                ],
            },
        ],
    },
    "hiring-costs-cardiff": {
        "title": "Cost of Hiring in Cardiff (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Cardiff for 2025/26. Welsh salary benchmarks, employer NI at 15%, pension and total above-salary cost. Wales uses the same employer NI rates as England.",
        "topic": "Cardiff hiring",
        "sections": [
            {
                "heading": "Cardiff salary benchmarks and employer NI",
                "paragraphs": [
                    "Cardiff is the largest city in Wales and its economic centre, with significant public sector employment (Welsh Government, NHS Wales, Cardiff Council), financial services, professional services, media and higher education. Salary levels are broadly in line with other regional UK cities, typically 15–20% below London. Entry-level roles generally start at £22,000–£26,000; senior professional roles in finance, law and tech reach £40,000–£65,000.",
                    "Employer NI in Cardiff uses the same UK-wide rate: 15% on earnings above the £5,000 secondary threshold for 2025/26. At £30,000, employer NI is £3,750 per year (£312.50 per month). At £40,000, it is £5,250 per year (£437.50 per month). Adding 3% pension at £35,000 adds £863 per year. Total above-salary cost at £35,000: approximately £5,363 per year.",
                    "Major Cardiff employers include NHS Wales, Welsh Government, Admiral Group, Legal & General, Cardiff University and Cardiff Metropolitan University. The Admiral Group and Legal & General maintain large operations in Cardiff, making financial services and insurance significant sectors for recruitment.",
                ],
            },
            {
                "heading": "Total cost of a Cardiff hire: worked example",
                "paragraphs": [
                    "For a £32,000 salary in Cardiff: employer NI £4,050 + pension £788 + overheads £2,500 = total employer cost approximately £39,338 per year. Monthly: £3,278. Wales uses the same income tax rates as England, so PAYE deductions work identically for Cardiff employees.",
                    "Employment Allowance of up to £10,500 can reduce NI costs significantly for eligible Cardiff employers. Model your specific salary in the calculator.",
                ],
            },
        ],
    },
    "employer-on-costs-explained": {
        "title": "Employer On-Costs Explained (2025/26): NI, Pension, Holiday & Overheads",
        "description": "What are employer on-costs? This guide explains all the costs above salary — employer NI at 15%, pension, holiday pay accrual and overheads — with worked examples for 2025/26.",
        "topic": "Employer on-costs",
        "sections": [
            {
                "heading": "What are employer on-costs?",
                "paragraphs": [
                    "Employer on-costs are all the costs that sit above an employee's gross salary — the amounts the employer pays on top of, or in addition to, the salary itself. The main components are employer National Insurance (NI), employer pension contributions, and overhead costs such as office space, equipment and management time.",
                    "Understanding on-costs is critical for workforce planning, budgeting and evaluating the true return on a hire. A £35,000 salary does not cost £35,000 — it typically costs £38,000–£42,000 depending on pension rate and overhead assumptions.",
                ],
            },
            {
                "heading": "Employer NI — the largest on-cost for most employers",
                "paragraphs": [
                    "From April 2025, employer NI is charged at 15% on all earnings above the secondary threshold of £5,000 per year (£416.67 per month). This is the largest mandatory on-cost for most employers.",
                    "At a £35,000 salary: employer NI = (35,000 − 5,000) × 15% = £4,500 per year (£375 per month). At £50,000: employer NI = (50,000 − 5,000) × 15% = £6,750 per year (£562.50 per month). These figures represent employer liability only — employee NI is separate and deducted from the employee's pay.",
                    "Employment Allowance can reduce employer NI by up to £10,500 per year for eligible employers. Eligibility requires that total employer NI liabilities were below £100,000 in the prior tax year and the employer does not employ any single person who is a director of a limited company with no other employees.",
                ],
            },
            {
                "heading": "Pension contributions and other on-costs",
                "paragraphs": [
                    "Auto-enrolment requires employers to contribute a minimum of 3% of qualifying earnings (£6,240–£50,270 for 2025/26). At £35,000, the qualifying earnings band gives £28,760 in pensionable pay, and 3% employer contribution = £862.80 per year (£71.90 per month).",
                    "Other on-costs vary by employer but typically include: employer liability insurance, recruitment costs (job board fees and agency fees of 10–20% of salary for permanent hires), IT equipment (£500–£2,000 per employee), office space, and management overhead. A common rule of thumb is to add 10–15% of salary as a blended overhead allowance. This gives a total cost-to-company at £35,000 of approximately £38,000–£42,000 per year.",
                ],
            },
        ],
    },
    "hiring-costs-newcastle": {
        "title": "Cost of Hiring in Newcastle (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Newcastle for 2025/26. Salary benchmarks, employer NI at 15%, pension and total above-salary cost at common Newcastle pay levels.",
        "topic": "Newcastle hiring",
        "sections": [
            {
                "heading": "Newcastle salary benchmarks and employer NI",
                "paragraphs": [
                    "Newcastle upon Tyne is the economic centre of the North East, with strong public sector employment (NHS, councils, HMRC), financial services, digital technology and offshore energy. Salary levels are generally 10–20% below London, with entry roles at £22,000–£27,000 and experienced professionals at £28,000–£50,000.",
                    "At £28,000, employer NI for 2025/26 is £3,450 per year (£287.50 per month). At £35,000, NI is £4,500 per year (£375 per month). Adding 3% pension at £35,000 adds £863 per year. Total above-salary cost at £35,000: around £5,363 per year.",
                    "Newcastle's public sector is substantial — NHS trusts, Northumberland County Council, Newcastle City Council and HMRC's regional operations are major employers. Agenda for Change banding drives NHS hiring at Bands 2–7 in the region.",
                ],
            },
            {
                "heading": "Total cost of a Newcastle hire: worked example",
                "paragraphs": [
                    "For a £30,000 salary in Newcastle: employer NI £3,750 + pension £713 + overheads £2,500 = total employer cost approximately £36,963 per year. Monthly: £3,080.",
                    "Employment Allowance of up to £10,500 can reduce the NI component significantly for eligible Newcastle employers. Model your specific salary in the calculator.",
                ],
            },
        ],
    },
    "hiring-costs-sheffield": {
        "title": "Cost of Hiring in Sheffield (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Sheffield for 2025/26. Salary benchmarks in manufacturing, logistics and digital sectors, employer NI at 15%, pension at 3% and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Sheffield: what it costs employers in 2025/26",
                "paragraphs": [
                    "Sheffield's employer cost structure follows UK-wide rules: employer NI at 15% on earnings above £5,000 and a minimum 3% pension contribution on qualifying earnings under auto-enrolment. What varies is the salary range. Sheffield salaries tend to sit below London levels but are broadly comparable with other major northern cities such as Leeds and Manchester.",
                    "In manufacturing, engineering and logistics — three of Sheffield's strongest employment sectors — typical salaries range from £26,000 for operational and warehouse roles to £55,000 for experienced engineers and supply chain managers. At the upper end of that range, employer NI and pension add approximately £8,250 per year before overheads. At the lower end, the April 2025 NI threshold change has increased cost more proportionally because more of a lower salary now falls into the NIable band.",
                    "Sheffield's growing digital and creative sector produces a different cost profile. Entry-level digital roles commonly start around £24,000–£28,000. Mid-level developer or UX salaries tend to sit in the £35,000–£45,000 range. At £40,000, the total employer cost before overheads is approximately £45,813 per year — salary, NI and pension combined.",
                ],
            },
            {
                "heading": "Sheffield salary benchmarks and employer cost worked examples",
                "paragraphs": [
                    "At a £25,000 salary — common for entry-level and administrative roles — employer NI is £3,000 per year (15% above £5,000) and minimum pension is approximately £563 per year, giving a total employer cost of approximately £28,563 before overheads. At £30,000, total employer cost is approximately £34,464 — £3,750 NI and £714 pension on top of salary.",
                    "For a £40,000 role in engineering or digital, employer NI is £5,250 per year and pension is approximately £1,013, giving a baseline cost of approximately £46,263 with a standard £3,000 overhead assumption. For senior or specialist hires at £55,000, employer NI rises to £7,500 per year, pension to £1,322 (capped at £50,270 for qualifying earnings), bringing total cost before overheads to approximately £63,822.",
                    "These figures use 2025/26 rates. For roles budgeted under 2024/25 NI assumptions, costs will be understated — particularly on salaries below £40,000 where the threshold change from £9,100 to £5,000 creates the largest proportional uplift.",
                ],
            },
            {
                "heading": "Employment Allowance and Sheffield SME employers",
                "paragraphs": [
                    "Sheffield has a high density of SMEs and family businesses, particularly in manufacturing and professional services. For smaller employers, Employment Allowance remains one of the most significant levers available. In 2025/26, eligible employers can offset up to £10,500 of employer NI — up from £5,000 in 2024/25 — which for a small Sheffield business with total NI below that threshold means NI is effectively zero.",
                    "The previous £100,000 NI cap on eligibility has been removed, meaning more Sheffield employers now qualify. If you are unsure whether you qualify, the standard rule is that limited companies with at least one employee who is not a sole director are usually eligible. Check with HMRC or your accountant before claiming.",
                    "Use the employer cost calculator to model Sheffield hire costs with and without Employment Allowance applied. For budget presentations and headcount sign-off, presenting both scenarios is common practice.",
                ],
            },
        ],
    },
    "hiring-costs-nottingham": {
        "title": "Cost of Hiring in Nottingham (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Nottingham for 2025/26. Salary benchmarks across retail, healthcare and professional services, employer NI at 15%, pension and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Nottingham: employer cost overview for 2025/26",
                "paragraphs": [
                    "Nottingham's employment mix spans healthcare, retail, financial services and a growing digital sector, with the University of Nottingham and Nottingham Trent University producing a consistent graduate pipeline. Employer costs follow national rules — 15% NI above £5,000, minimum 3% pension — applied to salary levels that sit broadly in line with other East Midlands cities.",
                    "For office-based and professional service roles, salaries commonly range from £24,000 for graduate and administrative positions to £50,000 for experienced managers and specialists. At £35,000 — a common Nottingham mid-market salary — total employer cost before overheads is approximately £39,501 per year: £35,000 salary plus £4,500 employer NI plus approximately £863 employer pension.",
                    "Healthcare roles, whether NHS or private, add a further consideration: many NHS contracts have fixed salary scales, so the employer cost variable is primarily NI and pension rather than negotiated salary. At the NHS Band 5 starting point of approximately £28,407, employer NI is approximately £3,511 per year and pension (at minimum 3%) is approximately £667 per year.",
                ],
            },
            {
                "heading": "Nottingham hiring cost worked examples",
                "paragraphs": [
                    "At £25,000 — a common salary for graduate and entry-level roles — total employer cost before overheads is approximately £28,563 (£3,000 NI + £563 pension). At £30,000, total reaches approximately £34,464. At £40,000, the figure is approximately £46,263 with a standard overhead assumption.",
                    "For retailers and hospitality operators hiring at or near minimum wage, the NI change matters more proportionally than for higher-salary employers. A full-time employee on the 2025/26 minimum wage earns approximately £24,785 per year. Employer NI on that salary is approximately £2,968 per year — up from approximately £2,031 under 2024/25 rules, a rise of £790 per employee per year from NI alone.",
                    "For financial services and insurance roles — present in Nottingham through several major employers — typical salaries of £40,000–£65,000 produce employer costs of £46,263 to approximately £74,573 before overheads. Employment Allowance can absorb a meaningful portion of NI for smaller Nottingham firms under the threshold.",
                ],
            },
            {
                "heading": "Planning and budgeting Nottingham hires",
                "paragraphs": [
                    "When budgeting Nottingham hires for 2025/26, the most common error is carrying forward 2024/25 NI assumptions. The threshold change from £9,100 to £5,000 hits proportionally harder at lower salary levels, which affects sectors like retail, care and hospitality more than professional services.",
                    "Use the employer cost calculator to build a consistent per-role cost model before offer stage. For budget presentations, the monthly number tends to resonate more than annual totals — a £34,464/year cost for a £30,000 Nottingham hire is £2,872 per month, which is the figure most finance teams want to see on a headcount request.",
                    "For Employment Allowance, Nottingham SMEs with total employer NI below £10,500 can use the allowance to eliminate NI entirely. For employers above that level, it reduces the first £10,500 of liability — still significant for teams with three to eight employees in typical Nottingham salary ranges.",
                ],
            },
        ],
    },
    "hiring-costs-manchester": {
        "title": "Cost of Hiring in Manchester (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Manchester for 2025/26. Salary benchmarks across finance, tech, media and professional services, with employer NI at 15%, pension and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Manchester: what it costs employers in 2025/26",
                "paragraphs": [
                    "Manchester is one of the UK's most significant employment markets outside London, with strong sectors in financial services, technology, media (anchored by MediaCityUK), professional services and logistics. Employer costs follow national rules — 15% employer NI on earnings above £5,000, minimum 3% pension — applied to a salary market that sits above average for the North West but below London levels.",
                    "In financial services, salaries in Manchester typically range from £28,000 for graduate and analyst roles to £65,000 for experienced managers and specialists. At £35,000 — a common mid-market salary across several Manchester sectors — total employer cost is approximately £40,363 per year: £35,000 salary, £4,500 employer NI, £863 minimum pension. Media and tech roles at MediaCityUK and the growing Northern Quarter tech cluster tend to sit in the £30,000–£55,000 range.",
                    "The April 2025 NI threshold reduction from £9,100 to £5,000 has increased costs particularly for roles below £30,000. For logistics and distribution roles — common in Greater Manchester — earning £24,000–£28,000, per-employee NI has risen by approximately £790–£870 per year versus 2024/25 assumptions. Any headcount plan using pre-April 2025 NI assumptions will understate employer cost.",
                ],
            },
            {
                "heading": "Manchester salary benchmarks and employer cost worked examples",
                "paragraphs": [
                    "At £25,000 — typical for entry-level, graduate and administrative roles — employer NI is £3,000 per year and minimum pension is approximately £563, giving a total employer cost of approximately £28,563 before overheads. At £30,000 (common across sales, marketing coordination and junior finance roles), total cost reaches approximately £34,464 per year.",
                    "For mid-level professionals in financial services or tech earning £45,000, employer NI is £6,000 per year and pension is approximately £1,163, placing total employer cost at approximately £52,163 before overheads. Senior managers and specialists at £60,000 generate employer NI of £8,250 and pension of £1,322 (qualifying earnings capped at £50,270), giving total employer cost of approximately £69,572.",
                    "Manchester's media sector, particularly at MediaCityUK, produces a wide salary spread: production assistants may earn £22,000–£26,000, while senior producers and executives can reach £50,000–£70,000. Production companies and broadcasters with high NI bills can benefit significantly from Employment Allowance if eligible.",
                ],
            },
            {
                "heading": "Employment Allowance and Manchester SME employers",
                "paragraphs": [
                    "Manchester has a dense SME ecosystem, particularly in digital, creative and professional services. For eligible employers, Employment Allowance in 2025/26 offsets up to £10,500 of annual employer NI — a material saving for small Manchester businesses. The previous £100,000 NI eligibility cap has been removed, broadening access.",
                    "For a Manchester tech startup employing five people with an average salary of £38,000, total employer NI is approximately £24,750 per year. Employment Allowance reduces this by £10,500, leaving net NI payable of approximately £14,250 — a saving of approximately £875 per month. This is a significant consideration for scaling teams in Manchester's competitive hiring market.",
                    "Use the employer cost calculator to model Manchester hire scenarios with and without Employment Allowance. For offer approvals and headcount plans, presenting both net and gross NI scenarios is standard practice and helps finance teams plan cashflow accurately.",
                ],
            },
        ],
    },
    "hiring-costs-birmingham": {
        "title": "Cost of Hiring in Birmingham (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Birmingham for 2025/26. Salary benchmarks across manufacturing, automotive, professional services and public sector, with employer NI, pension and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Birmingham: what it costs employers in 2025/26",
                "paragraphs": [
                    "Birmingham is the UK's second city and a major employment hub for manufacturing, automotive (with Jaguar Land Rover operations in the West Midlands), financial and professional services, retail and public sector employment. Employer costs are governed by the same 2025/26 rules — 15% NI above £5,000, minimum 3% pension — applied to salaries that broadly sit at the Midlands average.",
                    "For manufacturing and production roles, common in the wider West Midlands area, salaries typically range from £24,000 for operatives to £45,000–£60,000 for engineers and senior technical staff. At £30,000 — a typical mid-range salary for Birmingham's diverse employer base — total employer cost is approximately £34,464 per year. At £40,000, total employer cost before overheads is approximately £46,263.",
                    "Birmingham's professional services sector has grown significantly, with accountancy, legal and consulting firms expanding their West Midlands presence. Graduate and junior professional roles commonly start at £24,000–£28,000, rising to £40,000–£60,000 at the manager level. The April 2025 NI threshold change adds approximately £790 per employee per year at entry-level salaries compared with 2024/25.",
                ],
            },
            {
                "heading": "Birmingham salary benchmarks and employer cost worked examples",
                "paragraphs": [
                    "At £25,000 — common for administrative, retail and entry-level professional roles across Birmingham — employer NI is £3,000 per year and minimum pension is approximately £563, placing total employer cost before overheads at approximately £28,563. At £28,000, total employer cost reaches approximately £31,863 (NI £3,450 + pension £651).",
                    "For engineering and technical roles in the automotive and manufacturing supply chain, salaries of £35,000–£50,000 are typical. At £35,000, employer NI is £4,500 and pension is £863, giving total cost of approximately £40,363. At £50,000, NI is £6,750 and pension £1,322, total £58,072 before overheads.",
                    "Birmingham's public sector employers — including the NHS, local authorities and universities — tend to follow national pay scales, making salary benchmarking more predictable than private sector roles. NHS Band 5 starting salary of approximately £28,407 generates employer NI of approximately £3,511 and pension of approximately £667, placing total employer cost at approximately £32,585 before trust-specific overhead.",
                ],
            },
            {
                "heading": "Employment Allowance and Birmingham SME employers",
                "paragraphs": [
                    "Birmingham has a large SME sector spanning manufacturing, retail, property, and professional services. For eligible employers, Employment Allowance offsets up to £10,500 of annual employer NI in 2025/26 — a substantial relief for small businesses with two to eight employees in typical Birmingham salary ranges.",
                    "A small Birmingham professional services firm with five staff at an average salary of £32,000 generates approximately £20,250 in employer NI per year. Employment Allowance of £10,500 reduces net NI payable to approximately £9,750 — saving approximately £875 per month. This is particularly meaningful for Birmingham's growing creative, legal and accountancy SME sector.",
                    "Sole directors of Birmingham-based limited companies without other employees cannot claim Employment Allowance. As soon as a second person is employed through PAYE, eligibility typically opens. Use the employer cost calculator to model Birmingham hire costs with Employment Allowance applied before sign-off.",
                ],
            },
        ],
    },
    "hiring-costs-leeds": {
        "title": "Cost of Hiring in Leeds (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Leeds for 2025/26. Salary benchmarks in financial services, legal, digital and healthcare, with employer NI at 15%, pension and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Leeds: what it costs employers in 2025/26",
                "paragraphs": [
                    "Leeds is one of the UK's strongest financial services centres outside London, with major banks, insurance companies and building societies maintaining large operations in the city. It also has a strong legal sector, growing tech and digital economy, and significant NHS employment. Employer NI (15% above £5,000) and minimum pension (3% on qualifying earnings) apply at the same rates as everywhere in the UK — Leeds-specific factors are salary levels and sector mix.",
                    "In financial services, Leeds salaries commonly range from £26,000 for graduate analyst roles to £65,000 for experienced managers. Legal professionals range from £28,000 for newly qualified solicitors in Leeds firms to £60,000+ for partners and senior associates. At £40,000 — common across both sectors at the mid level — total employer cost is approximately £46,263 per year before overheads.",
                    "Leeds' digital and tech sector has grown rapidly around areas like the South Bank regeneration zone. Developer and data science roles typically sit between £35,000 and £70,000. At £55,000, employer NI is £7,500 and pension £1,322 per year, placing total employer cost at approximately £63,822 before any per-employee overhead assumptions.",
                ],
            },
            {
                "heading": "Leeds salary benchmarks and employer cost worked examples",
                "paragraphs": [
                    "At £25,000 — common for graduate, administrative and junior service roles — total Leeds employer cost before overheads is approximately £28,563 (NI £3,000 + pension £563). At £30,000 total employer cost is approximately £34,464. Both figures are based on 2025/26 NI rates; under 2024/25 rates, the same roles would have generated lower NI bills by approximately £790–£870 per employee.",
                    "NHS roles in Leeds — employing thousands through Leeds Teaching Hospitals Trust and other trusts — follow national pay scales. Band 5 roles starting around £28,407 generate approximately £3,511 employer NI and £667 pension per year, totalling approximately £32,585. Band 6 roles (approximately £35,000–£42,618) generate NI of £4,500–£5,643 per year.",
                    "For legal firms billing at solicitor and partner level, salaries of £45,000–£80,000 are typical for experienced hires. At £65,000, employer NI is £9,000 per year and pension £1,322, placing total employer cost at approximately £75,322. At £80,000, NI is £11,250 and total employer cost approximately £92,572.",
                ],
            },
            {
                "heading": "Employment Allowance and Leeds SME employers",
                "paragraphs": [
                    "Leeds has a vibrant SME economy — independent law firms, accountancy practices, digital agencies and healthcare providers all benefit from Employment Allowance where eligible. In 2025/26, the allowance offsets up to £10,500 of annual employer NI for qualifying businesses, up from £5,000 in 2024/25.",
                    "A Leeds digital agency with six employees earning an average of £35,000 generates approximately £27,000 in total employer NI per year (6 × £4,500). Employment Allowance of £10,500 reduces net NI payable to approximately £16,500 — a reduction of nearly 40%. For smaller teams where total NI falls below £10,500, the entire bill can be eliminated.",
                    "The Employment Allowance increase from £5,000 to £10,500 is especially relevant in Leeds where many firms operate as small professional practices. Previously, companies with two or three employees could only offset part of their NI bill; now, many can offset it entirely. Model this in the employer cost calculator to see the Leeds-specific impact on your headcount budget.",
                ],
            },
        ],
    },
    "hiring-costs-bristol": {
        "title": "Cost of Hiring in Bristol (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Bristol for 2025/26. Salary benchmarks in aerospace, tech, financial services and creative sectors, with employer NI at 15%, pension and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Bristol: what it costs employers in 2025/26",
                "paragraphs": [
                    "Bristol has one of the highest average salaries outside London, driven by a strong aerospace and defence cluster (Airbus, Rolls-Royce, BAE Systems), a growing technology sector, established financial services businesses and a thriving creative economy. Employer NI at 15% and minimum pension at 3% apply nationally, but Bristol's higher average salaries mean per-employee NI costs tend to be above the UK average.",
                    "Aerospace and engineering roles command a premium. Graduate aerospace engineers typically start at £28,000–£35,000, rising to £50,000–£75,000 for experienced engineers and programme managers. At £50,000, employer NI is £6,750 per year and pension £1,322, giving total employer cost of approximately £58,072 before overheads. At £65,000, total employer cost rises to approximately £75,322.",
                    "Bristol's tech sector — particularly SaaS, cybersecurity and fintech — produces salaries of £40,000–£80,000 for experienced engineers. The city also has a strong creative economy with agencies, studios and broadcast employers. Entry-level creative roles typically start at £24,000–£28,000, while senior creatives and directors can earn £45,000–£60,000.",
                ],
            },
            {
                "heading": "Bristol salary benchmarks and employer cost worked examples",
                "paragraphs": [
                    "At £28,000 — common for entry-level professional and creative roles in Bristol — employer NI is £3,450 and minimum pension is approximately £651, totalling approximately £32,101 before overheads. At £35,000 (common mid-level across multiple Bristol sectors), total employer cost is approximately £40,363.",
                    "For aerospace engineers and tech workers at £55,000, employer NI is £7,500 per year and pension £1,322, placing total employer cost at approximately £63,822. Financial services roles at £45,000–£60,000 generate NI of £6,000–£8,250, with pension capped at qualifying earnings of £50,270 (£1,322 minimum pension above that level).",
                    "Bristol's relatively high salary levels mean the April 2025 NI rate increase (from 13.8% to 15%) has a proportionally larger absolute impact than in lower-wage cities. At £50,000, the rate change alone (ignoring the threshold reduction) adds approximately £603 per employee per year versus 2024/25. Combined with the threshold change from £9,100 to £5,000, the total per-employee increase at £50,000 is approximately £1,106.",
                ],
            },
            {
                "heading": "Employment Allowance and Bristol SME employers",
                "paragraphs": [
                    "Bristol's SME ecosystem is particularly strong in tech, creative and professional services. Employment Allowance in 2025/26 offsets up to £10,500 of annual employer NI for eligible businesses. With Bristol's higher average salaries, the NI bill per employee is often above the national average — making Employment Allowance proportionally more valuable per employee than in lower-wage regions.",
                    "A Bristol tech startup with four developers earning an average of £50,000 generates approximately £27,000 in annual employer NI (4 × £6,750). Employment Allowance reduces this to approximately £16,500. For the same team in a city with average salaries of £35,000, total NI would be approximately £18,000 — the allowance has a larger absolute impact in Bristol's higher-wage environment.",
                    "Model Bristol hire costs with and without Employment Allowance using the employer cost calculator. For board presentations and offer approvals, showing the net NI position after allowance is standard practice and gives a more accurate picture of true payroll burden for Bristol employers.",
                ],
            },
        ],
    },
    "hiring-costs-edinburgh": {
        "title": "Cost of Hiring in Edinburgh (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Edinburgh for 2025/26. Salary benchmarks in financial services, public sector, tech and tourism, with employer NI at 15%, pension and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Edinburgh: what it costs employers in 2025/26",
                "paragraphs": [
                    "Edinburgh is Scotland's capital and financial centre, home to major financial institutions including Standard Life Aberdeen, Baillie Gifford, Royal Bank of Scotland and Natwest Group. The public sector is also a major employer through the Scottish Government, NHS Lothian and the University of Edinburgh. Employer NI (15% above £5,000) and pension (3% on qualifying earnings) apply at UK-wide rates — Edinburgh's distinctiveness lies in its salary levels and sector composition.",
                    "Financial services roles in Edinburgh typically range from £28,000 for graduate analysts to £70,000+ for fund managers and senior investment professionals. At £40,000 — a common mid-market salary in financial services and professional services — total employer cost is approximately £46,263 per year. Edinburgh's tech sector, centred around companies like Skyscanner and FanDuel, produces developer salaries of £35,000–£70,000.",
                    "Tourism and hospitality is a significant Edinburgh employer, particularly given the city's prominence as a global tourist destination. Hospitality roles at or near NLW (£12.71/hour, approximately £24,785 full-time) generate employer NI of approximately £2,968 per year. The April 2025 NI threshold change is proportionally larger for these roles than for financial services staff, adding approximately £790 per full-time NLW employee versus 2024/25.",
                ],
            },
            {
                "heading": "Edinburgh salary benchmarks and employer cost worked examples",
                "paragraphs": [
                    "At £28,000 — common for graduate, administrative and junior public sector roles — employer NI is £3,450 and pension approximately £651, giving total employer cost of approximately £32,101 before overheads. At £35,000, total employer cost is approximately £40,363. At £45,000 (common for experienced finance and tech professionals), employer NI is £6,000 and pension £1,163, total approximately £52,163.",
                    "NHS Lothian roles follow national NHS pay bands. Band 5 starting salary of approximately £28,407 generates £3,511 employer NI and £667 pension per year. Band 7 salaries of approximately £46,148 generate NI of approximately £6,172 and pension of £1,177, placing total employer cost at approximately £53,497 before NHS overhead allowances.",
                    "Edinburgh's financial services sector at the senior level produces salaries that trigger significant employer NI: at £70,000, NI is £9,750 per year and pension £1,322 (qualifying earnings capped). Total employer cost before overheads: approximately £81,072. At £90,000, NI is £12,750 and total employer cost approximately £104,072.",
                ],
            },
            {
                "heading": "Employment Allowance and Edinburgh SME employers",
                "paragraphs": [
                    "Edinburgh has a significant SME sector in legal services, accountancy, creative industries and technology. Employment Allowance in 2025/26 — up to £10,500 off annual employer NI — is available to most Edinburgh businesses with more than one employee. The allowance increase from £5,000 to £10,500 is particularly material for Edinburgh firms where per-employee NI averages are above the national average.",
                    "A small Edinburgh fintech with five employees at an average salary of £45,000 generates approximately £30,000 in annual employer NI (5 × £6,000). Employment Allowance reduces net NI payable to approximately £19,500. For Edinburgh's growing startup and scaleup community, this represents a significant annual cash saving on payroll.",
                    "Sole directors of Edinburgh-based limited companies cannot claim Employment Allowance without other employees. Hiring a second person — even part-time — typically unlocks eligibility. Use the employer cost calculator to model Edinburgh hire costs at any salary level, with and without Employment Allowance, to support headcount decisions.",
                ],
            },
        ],
    },
    "hiring-costs-glasgow": {
        "title": "Cost of Hiring in Glasgow (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Glasgow for 2025/26. Salary benchmarks across financial services, healthcare, manufacturing and retail, with employer NI at 15%, pension and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Glasgow: what it costs employers in 2025/26",
                "paragraphs": [
                    "Glasgow is Scotland's largest city and a major employment centre spanning financial services, NHS healthcare, manufacturing, retail and a growing tech sector. Salaries tend to sit broadly in line with other major UK regional cities at the mid-market level, though London premiums do not apply. Employer NI at 15% above the £5,000 secondary threshold and minimum 3% pension apply at UK-wide rates.",
                    "The NHS is one of Glasgow's largest employers through NHS Greater Glasgow and Clyde, employing tens of thousands of staff across hospitals, community services and administrative roles. NHS Band 5 starting salaries of approximately £28,407 generate employer NI of approximately £3,511 per year and pension of approximately £667, giving total employer cost of approximately £32,585. Financial services roles at the city's major banks and insurers typically range from £28,000 to £60,000.",
                    "Glasgow's manufacturing sector — including engineering, shipbuilding heritage and newer precision manufacturing — contributes skilled trades roles typically earning £28,000–£45,000. At £35,000, total employer cost is approximately £40,363. Retail and hospitality, large employers given Glasgow's city centre activity, predominantly pay at or near NLW, generating employer NI of approximately £2,968 per full-time NLW employee.",
                ],
            },
            {
                "heading": "Glasgow salary benchmarks and employer cost worked examples",
                "paragraphs": [
                    "At £25,000 — common for retail, hospitality, administrative and entry-level service roles — employer NI is £3,000 and minimum pension is approximately £563, placing total employer cost at approximately £28,563. At £30,000, total reaches approximately £34,464. Both reflect 2025/26 rates; under 2024/25 assumptions, costs would be approximately £790–£870 lower per employee.",
                    "For Glasgow's professional and financial services sector, salaries of £35,000–£55,000 are typical for experienced staff. At £45,000, employer NI is £6,000 per year and pension £1,163, giving total employer cost of approximately £52,163 before overheads. Senior finance professionals at £60,000 generate NI of £8,250 and total employer cost of approximately £69,572.",
                    "Glasgow's growing tech cluster, particularly in AI, fintech and software, produces roles at £35,000–£70,000 for experienced engineers. At £55,000, total employer cost is approximately £63,822 before overheads. Graduate tech roles typically start at £26,000–£32,000, generating employer NI of £3,150–£4,050 per year.",
                ],
            },
            {
                "heading": "Employment Allowance and Glasgow SME employers",
                "paragraphs": [
                    "Glasgow has a significant SME base in professional services, retail, hospitality and creative industries. Employment Allowance in 2025/26 offsets up to £10,500 of annual employer NI for eligible Glasgow businesses — a significant uplift from the previous £5,000 cap. The eligibility threshold (total NI under £100,000 in the prior year) means many Glasgow businesses that previously could not claim now can.",
                    "A Glasgow accountancy practice with six staff at an average salary of £32,000 generates approximately £20,250 in annual employer NI. Employment Allowance of £10,500 reduces net NI payable to approximately £9,750 — a saving of approximately £875 per month. For Glasgow's hospitality businesses with high headcount and lower average salaries, the absolute value of the allowance is also significant.",
                    "Use the employer cost calculator to model Glasgow hire costs at any salary level. For budget presentations and headcount sign-off, showing the Employment Allowance-adjusted NI figure gives a more accurate picture of what Glasgow employers actually pay through PAYE across the year.",
                ],
            },
        ],
    },
    "hiring-costs-cardiff": {
        "title": "Cost of Hiring in Cardiff (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Cardiff for 2025/26. Salary benchmarks across public sector, media, financial services and retail, with employer NI at 15%, pension and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Cardiff: what it costs employers in 2025/26",
                "paragraphs": [
                    "Cardiff is Wales's capital and dominant employment hub, with the Welsh Government, BBC Wales and a cluster of financial services businesses all headquartered or significantly present in the city. Public sector employment is proportionally larger in Cardiff than in most English cities of comparable size, and salaries tend to sit somewhat below UK national averages across most occupations. Employer NI (15% above £5,000) and pension (3%) apply at the same UK-wide rates.",
                    "Welsh Government and Cardiff Council roles follow national public sector pay frameworks, with administrative and professional roles typically ranging from £22,000 to £50,000. BBC Wales employs production, technical and administrative staff across salary bands from £24,000 to £60,000 for senior programme-makers and editors. At £30,000 — a typical Cardiff public sector mid-level salary — total employer cost is approximately £34,464 per year.",
                    "The Cardiff financial services cluster, including operations for major banks and insurance firms, tends to pay slightly below London and Edinburgh levels for comparable roles. Typical salaries range from £24,000 for operations and back-office staff to £55,000+ for experienced analysts and managers. At £35,000, total employer cost before overheads is approximately £40,363.",
                ],
            },
            {
                "heading": "Cardiff salary benchmarks and employer cost worked examples",
                "paragraphs": [
                    "At £24,000 — common across retail, administrative and lower public sector roles — employer NI is £2,850 and pension approximately £531, giving total employer cost of approximately £27,381. At £28,000 (typical for Band D local authority and junior professional roles), total employer cost is approximately £32,101. Both reflect 2025/26 NI at 15% above the £5,000 threshold.",
                    "Cardiff's median private sector salary is somewhat below the UK average, meaning the April 2025 NI threshold change (from £9,100 to £5,000) has a proportionally larger impact here than in higher-wage cities. The additional NI on salaries of £22,000–£28,000 is approximately £790–£870 per employee versus 2024/25 — a meaningful rise for organisations with high concentrations of lower-paid roles.",
                    "Financial services and insurance operations staff at £35,000–£45,000 generate employer NI of £4,500–£6,000 per year, with pension of £863–£1,163. At £40,000, total employer cost is approximately £46,263. Senior analysts and managers at £50,000–£55,000 generate total employer costs of £58,072–£63,822 per year before overheads.",
                ],
            },
            {
                "heading": "Employment Allowance and Cardiff SME employers",
                "paragraphs": [
                    "Cardiff's private sector includes growing tech, creative and professional services communities. Employment Allowance of up to £10,500 per year is available to eligible Cardiff employers and can significantly reduce NI liability for small businesses. Many Cardiff creative agencies, tech companies and independent professional practices have total NI bills below £10,500, meaning they can eliminate their NI entirely through the allowance.",
                    "A Cardiff digital agency with five staff at an average salary of £28,000 generates approximately £17,250 in annual employer NI. Employment Allowance of £10,500 reduces net NI payable to approximately £6,750 — a saving of nearly 61%. For businesses operating in Cardiff's lower-wage environment, the allowance provides proportionally greater relief than in London or Bristol.",
                    "The Employment Allowance increase from £5,000 to £10,500 in April 2025 is particularly impactful for Cardiff businesses. Previously, only a fraction of NI was offset for many firms; now the entire bill may be eliminated. Use the employer cost calculator to see your Cardiff hire costs with allowance applied before committing to new headcount.",
                ],
            },
        ],
    },
    "hiring-costs-liverpool": {
        "title": "Cost of Hiring in Liverpool (2025/26): Employer NI, Pension & Total Salary Cost",
        "description": "Employer hiring costs in Liverpool for 2025/26. Salary benchmarks across healthcare, logistics, retail and the creative economy, with employer NI at 15%, pension and total above-salary cost.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "Hiring in Liverpool: what it costs employers in 2025/26",
                "paragraphs": [
                    "Liverpool is a major UK employment market with key sectors in NHS healthcare (one of the largest employers in the region), retail and hospitality, port and logistics operations, and an established creative economy. Salaries tend to sit in the lower range of major UK cities, with a median broadly comparable with other North West and Midlands cities. Employer NI (15% above £5,000) and pension (3%) apply at UK-wide rates.",
                    "NHS employment through Liverpool University Hospitals Trust and Mersey Care employs tens of thousands of people across clinical, administrative and support roles. NHS Band 5 starting salary of approximately £28,407 generates employer NI of £3,511 and pension of £667 per year, totalling approximately £32,585 employer cost. Band 3 administrative and support roles at approximately £22,816–£24,336 generate NI of £2,672–£2,900 per year.",
                    "Liverpool's port and logistics sector — one of the UK's busiest — employs warehouse operatives, port staff and logistics managers across a wide salary range. Operative roles typically earn £24,000–£32,000, generating employer NI of £2,850–£4,050. Management and specialist roles at £35,000–£50,000 generate NI of £4,500–£6,750 per year. The April 2025 NI threshold change adds approximately £790–£870 per lower-paid logistics employee versus 2024/25.",
                ],
            },
            {
                "heading": "Liverpool salary benchmarks and employer cost worked examples",
                "paragraphs": [
                    "At £24,000 — common for retail, hospitality, administrative and NHS Band 3 roles — employer NI is £2,850 and pension approximately £531, giving total employer cost of approximately £27,381 before overheads. At £28,000, total employer cost is approximately £32,101. These figures reflect 2025/26 rates; the April 2025 threshold change increases costs by approximately £790 per year for NLW full-time employees versus 2024/25.",
                    "Creative and digital sector roles in Liverpool — supported by organisations like Liverpool Film Office and the growing tech community — typically range from £24,000 for entry-level roles to £45,000–£55,000 for experienced professionals and managers. At £35,000, total employer cost is approximately £40,363. Liverpool's creative sector has relatively high concentrations of freelance and contract workers; converting these to PAYE employment adds NI and pension at the relevant rate.",
                    "Liverpool's retail and hospitality sector employs large numbers of staff at or near NLW. A full-time NLW employee (£24,785/year) generates employer NI of approximately £2,968 and pension of approximately £556, giving total employer cost of approximately £28,309 per year. For retailers and venues employing ten or more staff at NLW, Employment Allowance can eliminate the entire employer NI bill if total NI is below £10,500.",
                ],
            },
            {
                "heading": "Employment Allowance and Liverpool SME employers",
                "paragraphs": [
                    "Liverpool has a substantial SME sector in hospitality, retail, creative industries and professional services. Employment Allowance in 2025/26 — up to £10,500 off annual employer NI — is especially valuable for Liverpool's lower-average-salary businesses, where the allowance can eliminate NI entirely for teams of four to six employees. The previous eligibility cap of £100,000 annual NI has been removed, widening access.",
                    "A Liverpool hospitality business with eight staff earning an average of £24,000 generates approximately £22,800 in annual employer NI. Employment Allowance of £10,500 reduces net NI payable to approximately £12,300 — a saving of nearly 46%. For smaller venues or retailers with five or fewer NLW staff, the total NI bill may fall below £10,500, allowing full elimination through the allowance.",
                    "Use the employer cost calculator to model Liverpool hire costs at any salary level with Employment Allowance applied. For headcount sign-off and cashflow planning, presenting the net NI position after allowance is more useful than the gross NI figure, particularly for Liverpool businesses where allowance covers a large proportion of the annual NI liability.",
                ],
            },
        ],
    },
    "first-employee-cost": {
        "title": "Cost of Hiring Your First Employee in the UK (2025/26)",
        "description": "What does it actually cost to hire your first employee in the UK? This guide covers employer NI at 15%, pension auto-enrolment, Employment Allowance and total true cost for 2025/26.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "What does hiring your first employee actually cost?",
                "paragraphs": [
                    "Many first-time employers focus on the salary figure and miss the mandatory add-ons. In 2025/26, every UK employer must pay employer National Insurance on top of gross salary — 15% on earnings above £5,000 — and once your employee is eligible, you must also make auto-enrolment pension contributions of at least 3% of their qualifying earnings. These two items alone typically add 14–17% on top of the headline salary.",
                    "At a £28,000 starting salary, the true employer cost before overheads is approximately £32,153 per year: £28,000 salary, £3,450 employer NI and £653 employer pension. If you are hiring at £35,000, the total reaches approximately £39,501 before any equipment, software or workspace costs. Use the employer cost calculator to model your specific salary.",
                    "Beyond the statutory costs, factor in one-off hiring costs that do not appear in the recurring model: job board fees (typically £100–£600 per post), any recruitment agency fees (often 10–20% of first-year salary for specialist roles), and the time cost of onboarding. The statutory costs on this page are the recurring floor — the true cost of hiring your first employee is higher when setup costs are included.",
                ],
            },
            {
                "heading": "Employment Allowance — your key relief as a first employer",
                "paragraphs": [
                    "Good news for first-time employers: most new businesses can claim Employment Allowance in 2025/26, which reduces your employer NI bill by up to £10,500. If your first employee is on a salary below approximately £75,000, the allowance will cover your entire employer NI liability for the year.",
                    "The main exception is sole-director companies with no other employees. If you are the only director and have no other employees, you cannot claim. Once you hire your first employee (who is not a fellow director), the allowance becomes available. Check HMRC's guidance or confirm with your accountant before the first payroll run.",
                    "To claim Employment Allowance, select 'Yes' in the Employment Allowance field within your payroll software at the start of the tax year. Most UK payroll software — Xero, QuickBooks, Sage, FreeAgent — handles this automatically once you indicate eligibility. The allowance is applied against your employer NI liability each pay period until used.",
                ],
            },
            {
                "heading": "Auto-enrolment: your pension duties from day one",
                "paragraphs": [
                    "If your first employee is aged 22 or over and earns more than £10,000 per year, you must automatically enrol them into a workplace pension within six weeks of their start date. You must make a minimum employer contribution of 3% on qualifying earnings between £6,240 and £50,270. There is no opt-out for the employer — only the employee can choose to opt out.",
                    "For a £30,000 salary, qualifying earnings are £30,000 minus £6,240 = £23,760. Your minimum employer pension contribution is 3% of £23,760 = £712.80 per year, or approximately £59 per month. This is paid into the employee's pension pot in addition to their employee contribution (minimum 5% of qualifying earnings under auto-enrolment rules).",
                    "Most payroll software handles auto-enrolment automatically once you set it up, but you need to register with a pension provider first. NEST (the National Employment Savings Trust) is a government-backed option available to all UK employers. You can use any authorised pension provider. Set this up before your first payroll run rather than scrambling to catch up.",
                ],
            },
            {
                "heading": "True first-employee cost by salary: worked examples",
                "paragraphs": [
                    "At a £25,000 salary with Employment Allowance: employer NI is £3,000 but fully offset by allowance, so net NI = £0. Pension = £563. True recurring cost = £25,563 per year. This is the best-case scenario for a first employer who qualifies for the allowance.",
                    "At a £30,000 salary with Employment Allowance: NI of £3,750 fully offset. Pension = £714. Recurring cost = £30,714. Without Employment Allowance, the figure rises to £34,464. The difference — £3,750 — is the value of claiming the allowance at this salary.",
                    "At a £45,000 salary, the employer NI is £6,000 per year. Employment Allowance offsets £6,000 fully. Pension on qualifying earnings: (£45,000 − £6,240) × 3% = £1,162.80 per year. Recurring cost with allowance: £46,163. Without allowance: £52,163. Beyond £75,000 salary, NI will exceed the £10,500 allowance and a residual NI liability applies. Use the calculator to model the exact figure.",
                ],
            },
        ],
    },
    "part-time-employee-cost": {
        "title": "Cost of Employing Part-Time Staff UK (2025/26) — Employer NI, Pension & On-Costs",
        "description": "How much does a part-time employee cost a UK employer? Employer NI at 15%, pension at 3%, Employment Allowance and true cost at common part-time salary levels for 2025/26.",
        "topic": "Hiring",
        "sections": [
            {
                "heading": "How part-time employee costs work",
                "paragraphs": [
                    "Part-time employees are subject to the same employer National Insurance and pension rules as full-time staff. The secondary threshold for employer NI is £5,000 per year — not pro-rated for part-time hours. That means a part-time employee earning £15,000 per year still attracts employer NI at 15% on earnings above £5,000, giving £1,500 per year in NI.",
                    "Pension auto-enrolment applies if the employee earns more than £10,000 per year in a single job and is aged between 22 and State Pension Age. If they earn between £6,240 and £10,000, they have the right to opt in but do not have to be automatically enrolled. Below £6,240, no pension duty applies. For a part-time worker on £12,000 per year, qualifying earnings are £12,000 − £6,240 = £5,760, and minimum employer pension is 3% of £5,760 = £172.80 per year.",
                    "This means part-time hires can have a higher percentage-above-salary cost than full-time hires, because the fixed NI threshold is not reduced. A full-time £50,000 salary costs about 16% above salary in NI and pension. A part-time £15,000 salary costs about 12% above salary in NI and pension — but a part-time £20,000 salary costs about 14% above, and that percentage rises toward the full-time equivalent as salary increases.",
                ],
            },
            {
                "heading": "Part-time employer cost: worked examples for 2025/26",
                "paragraphs": [
                    "At a £12,000 part-time salary: employer NI is £1,050 per year (15% of £7,000), pension is £172.80 per year. Total employer cost = £13,222.80 per year or approximately £1,101 per month.",
                    "At a £16,000 part-time salary: employer NI is £1,650 per year, pension is £291.60 per year. Total cost = £17,941.60 per year. At £20,000: NI = £2,250, pension = £411.60. Total = £22,661.60. At £25,000: NI = £3,000, pension = £563. Total = £28,563.",
                    "Employment Allowance applies to part-time employees in the same way as full-time. If you are an eligible employer with employer NI below £10,500 per year across all your employees, the allowance fully offsets the liability. For small businesses with a few part-time workers, this is particularly valuable.",
                ],
            },
            {
                "heading": "Auto-enrolment for part-time workers: what changes",
                "paragraphs": [
                    "The most important distinction for part-time workers and auto-enrolment is the £10,000 earnings threshold. Workers earning below £10,000 per year from you are not automatically enrolled — but they have the right to opt in. If they opt in, you must make the minimum employer contribution.",
                    "The qualifying earnings band (£6,240–£50,270) is also fixed — not pro-rated. So for a worker earning £8,000 per year, qualifying earnings are £8,000 − £6,240 = £1,760, and minimum employer pension is just 3% of £1,760 = £52.80 per year. Low-earning part-time workers carry a very low pension cost.",
                    "If a worker has more than one part-time job, each employer assesses auto-enrolment duties separately based on their own salary payment only — not the employee's total earnings from all jobs. Make sure you assess eligibility accurately at the start of employment and re-assess at the annual re-enrolment date.",
                ],
            },
        ],
    },
}

# Load daily SEO content additions (updated by automation — never edit manually)
_SEO_PATH = os.path.join(os.path.dirname(__file__), "data", "seo_extras.json")
if os.path.exists(_SEO_PATH):
    with open(_SEO_PATH) as _f:
        _seo_extras = json.load(_f)
    GUIDES.update(_seo_extras.get("guides", {}))

STATIC_PAGES = {
    "methodology": {
        "title": "Methodology — How Employer Cost Calculations Work",
        "description": "How EmployerCalculator.co.uk calculates employer NI, pension contributions and total hiring costs. Assumptions, formulae and update schedule for 2025/26.",
        "content": [
            "EmployerCalculator uses deterministic formulae for 2025/26 employer NI, pension minimums and total employer cost modelling. Each result is rendered server-side and included directly in HTML for SEO.",
            "Employer NI assumptions: 15% rate above £5,000 secondary threshold, with support for Employment Allowance up to £10,500 and relief handling for under-21 and apprentice under-25 scenarios up to the upper secondary threshold.",
            "Pension assumptions: employer minimum 3% and total minimum 8% on qualifying earnings band £6,240 to £50,270. Programmatic pages default to minimum employer contribution unless stated.",
            "Update schedule: rates and thresholds are reviewed each tax-year cycle and whenever HMRC issues in-year updates. Pages display tax year explicitly.",
            "Disclaimer: estimates only and not financial or legal advice.",
        ],
    },
    "editorial-standards": {
        "title": "Editorial Standards",
        "description": "Accuracy, review and correction standards for EmployerCalculator.co.uk content.",
        "content": [
            "We publish practical, decision-focused content for UK employers using official sources where available. Content is reviewed against HMRC and GOV.UK guidance before publication.",
            "Every guide includes a byline and source review statement. Calculator assumptions are documented on methodology and source pages.",
            "If we identify an accuracy issue, we correct promptly and update the relevant page copy. We favour clear assumptions and plain English over marketing language.",
        ],
    },
    "sources": {
        "title": "Sources — HMRC & GOV.UK References",
        "description": "Official HMRC and GOV.UK sources used for employer NI rates, pension thresholds, Employment Allowance and statutory pay figures on EmployerCalculator.co.uk.",
        "content": [
            "HMRC Rates and thresholds for employers 2025 to 2026",
            "National Insurance rates and letters",
            "Employment Allowance guidance",
            "Automatic enrolment guidance from The Pensions Regulator",
            "GOV.UK redundancy, notice and statutory payment guidance",
        ],
        "links": [
            ("HMRC rates and thresholds 2025/26", "https://www.gov.uk/guidance/rates-and-thresholds-for-employers-2025-to-2026"),
            ("National Insurance rates and letters", "https://www.gov.uk/national-insurance-rates-letters"),
            ("Employment Allowance", "https://www.gov.uk/employment-allowance"),
            ("Workplace pension contributions", "https://www.thepensionsregulator.gov.uk/en/employers/managing-a-scheme/contributions-and-funding"),
            ("Statutory redundancy pay", "https://www.gov.uk/redundancy-your-rights"),
        ],
    },
    "about": {
        "title": "About",
        "description": "About EmployerCalculator.co.uk.",
        "content": [
            "EmployerCalculator.co.uk is a UK employer-cost calculator hub focused on payroll and HR decision support for the 2025/26 tax year.",
            "It is the employer-side sister site to AfterTaxSalary.co.uk, which focuses on employee take-home pay.",
            "Our goal is simple: help employers understand monthly and annual cost before they hire, budget, or restructure.",
        ],
    },
    "privacy": {
        "title": "Privacy Policy",
        "description": "Privacy policy for EmployerCalculator.co.uk.",
        "content": [
            "We minimise personal data collection. Standard web server logs may include IP address, browser and request metadata for security and operations.",
            "Calculator inputs are processed to produce estimates and are not sold. Contact form submissions are used only to respond to enquiries.",
            "You can contact us for privacy requests using the contact page.",
        ],
    },
    "terms": {
        "title": "Terms of Use",
        "description": "Terms of use for EmployerCalculator.co.uk.",
        "content": [
            "Calculator outputs are estimates based on stated assumptions and are provided for informational purposes only.",
            "The site does not provide legal, tax or financial advice. You remain responsible for payroll compliance and professional advice where required.",
            "By using the site, you accept these terms and agree not to rely solely on estimates for legal or contractual decisions.",
        ],
    },
}

GSC_INTENT_PAGES: Dict[str, Dict] = {
    "/employer-total-cost-calculator": {
        "title": "Total Employer Cost Calculator UK (2025/26) — Salary, NI, Pension & Overheads",
        "description": "Calculate total employer cost in the UK for 2025/26. Salary + employer NI (15% above £5k) + pension (3%) + optional overheads. £35k = £40,363/yr · £50k = £58,063/yr. Free calculator.",
        "h1": "Total employer cost calculator UK (2025/26)",
        "badge": "Calculator intent",
        "intro": "Use the total employer cost calculator to convert a headline salary into the true UK employer budget number for 2025/26. It combines gross salary, employer NI at 15% on earnings above £5,000, employer pension at 3% of qualifying earnings, and optional per-head overhead assumptions. Use the result for offer approvals, headcount plans and finance sign-off.",
        "bullets": [
            "Model the true cost above headline salary for UK hiring decisions.",
            "Switch between minimum pension assumptions and your internal overhead baseline.",
            "Compare 2025/26 versus 2024/25 NI to quantify the April 2025 rate change impact.",
        ],
        "primary_cta": {"label": "Open full employer total cost calculator", "url": "/calculator"},
        "faq_items": [
            {"q": "What does total employer cost include?", "a": "Total employer cost includes gross salary, employer NI, employer pension, and any per-employee overhead assumptions such as equipment or software."},
            {"q": "Is this UK-specific?", "a": "Yes. This page and calculator use UK 2025/26 assumptions, including employer NI at 15% above the £5,000 secondary threshold and auto-enrolment pension minimums."},
            {"q": "What is the total employer cost for a £35,000 salary?", "a": "For a £35,000 salary in 2025/26, total employer cost is approximately £39,500 per year — £35,000 salary plus £4,500 employer NI (15% above £5,000) plus £863 employer pension (3% of qualifying earnings). With a £3,000 overhead assumption, total rises to approximately £42,500."},
            {"q": "How do I calculate total employer cost?", "a": "Formula: total employer cost = gross salary + (gross salary − £5,000) × 15% + (min(salary, £50,270) − £6,240) × 3% + overheads. For a £35,000 salary: £35,000 + £4,500 NI + £863 pension = £40,363 before overheads."},
        ],
    },
    "/employer-cost-calculator-uk": {
        "title": "Employer Cost Calculator UK (2025/26) | EmployerCalculator.co.uk",
        "description": "Employer cost calculator UK page for 2025/26. Check monthly and annual employer spend including NI, pension and optional overheads.",
        "h1": "Employer cost calculator UK",
        "badge": "Calculator intent",
        "intro": "This employer cost calculator UK page is designed for salary budgeting, offer approvals and headcount planning. It focuses on practical employer-side payroll cost rather than employee take-home pay.",
        "bullets": [
            "Get a monthly and annual view of employer payroll cost in one place.",
            "Include Employment Allowance where eligible to model net NI due.",
            "Compare salary-only decisions against true recurring employer spend.",
        ],
        "primary_cta": {"label": "Run employer cost calculation", "url": "/calculator"},
        "faq_items": [
            {"q": "How is employer NI handled in this calculator?", "a": "Employer NI is calculated at 15% on earnings above £5,000 for 2025/26, with optional Employment Allowance offset where selected."},
            {"q": "Does this include pension cost?", "a": "Yes. Minimum employer pension is modelled at 3% of qualifying earnings (£6,240 to £50,270), with adjustable contribution rate input."},
        ],
    },
    "/total-cost-to-employer-calculator-uk": {
        "title": "Total Cost to Employer Calculator UK (2025/26) | EmployerCalculator.co.uk",
        "description": "Total cost to employer calculator UK page. Estimate full annual and monthly employer cost with NI, pension and overhead assumptions.",
        "h1": "Total cost to employer calculator UK",
        "badge": "Calculator intent",
        "intro": "Use this total cost to employer calculator UK page to convert headline salary into a true employer budget number for 2025/26 planning and approval workflows.",
        "bullets": [
            "Translate salary into total employer cost with transparent assumptions.",
            "View NI and pension components separately for better reporting.",
            "Keep output consistent across finance, HR and hiring managers.",
        ],
        "primary_cta": {"label": "Calculate total cost to employer", "url": "/calculator"},
        "faq_items": [
            {"q": "Why is total cost above salary?", "a": "Because UK employers also pay employer NI and pension contributions on top of gross salary, and many businesses carry additional per-employee overhead costs."},
            {"q": "Can I use this for budget sign-off?", "a": "Yes, as a baseline estimator. Use the same assumptions line (tax year, NI rate/threshold, pension basis, overhead rule) across stakeholders."},
        ],
    },
    "/auto-enrolment-payroll-costs": {
        "title": "Auto Enrolment Payroll Costs 2025/26: What Employers Actually Pay | EmployerCalculator.co.uk",
        "description": "Auto enrolment payroll costs explained for UK employers. Minimum 3% employer pension on qualifying earnings £6,240–£50,270. See per-employee cost by salary for 2025/26.",
        "h1": "Auto enrolment payroll costs for UK employers (2025/26)",
        "badge": "Pension costs",
        "intro": "Auto enrolment adds a mandatory pension contribution on top of every eligible employee's salary. For 2025/26, the minimum employer contribution is 3% of qualifying earnings — the slice of salary between £6,240 and £50,270. That means for a £30,000 salary the auto enrolment cost to the employer is approximately £714 per year (3% of £30,000 minus £6,240). For a £50,000 salary it is approximately £1,309 per year. Use the pension cost calculator to model any salary, or the full employer calculator to combine pension with employer NI and overhead costs.",
        "bullets": [
            "Minimum employer contribution: 3% of qualifying earnings.",
            "2025/26 qualifying earnings band: £6,240 to £50,270.",
            "A £30,000 salary adds approximately £714/year in auto enrolment pension cost.",
            "A £50,000 salary adds approximately £1,309/year (capped at upper qualifying earnings limit).",
            "Eligible workers aged 22–State Pension Age earning above £10,000 must be enrolled automatically.",
        ],
        "primary_cta": {"label": "Open auto-enrolment pension cost calculator", "url": "/pension-cost"},
        "faq_items": [
            {"q": "What are qualifying earnings for auto-enrolment in 2025/26?", "a": "For 2025/26, qualifying earnings run from £6,240 to £50,270. The employer's minimum 3% contribution is calculated on the portion of salary that falls within that band, not on the full gross salary."},
            {"q": "How much does auto enrolment cost the employer per month?", "a": "For a £30,000 salary, auto enrolment pension costs the employer around £59 per month (3% of £23,760 qualifying earnings, divided by 12). For a £40,000 salary it is around £84 per month. Use the pension cost calculator for any specific salary."},
            {"q": "Which employees must be auto-enrolled?", "a": "Workers aged between 22 and State Pension Age who earn more than £10,000 per year in a single job must be automatically enrolled. Workers aged 16–21 or over State Pension Age, or those earning below £10,000, have the right to opt in but are not automatically enrolled."},
            {"q": "Can employees opt out of auto-enrolment?", "a": "Yes. Employees can opt out within one month of being enrolled, and if they do the employer stops contributions and refunds theirs. Employers must re-enrol eligible employees every three years even if they previously opted out."},
            {"q": "Does auto enrolment cost change if we offer more than 3%?", "a": "Yes. If you offer a higher employer contribution — common at 5% or 10% — model it using the full employer calculator. The statutory minimum is 3% of qualifying earnings, but many employers pay more to attract and retain staff."},
            {"q": "Where do I calculate full employer cost including NI and pension?", "a": "Use the full employer calculator to combine salary, employer NI (15% above £5,000 for 2025/26) and pension contributions in one result. You can also add per-employee overhead costs."},
        ],
    },
    "/ni-change-calculator": {
        "title": "NI Rise Calculator UK 2025/26 | Employer NI Change After April 2025",
        "description": "Free NI rise calculator for UK employers. April 2025 raised employer NI from 13.8% to 15% and cut the threshold from £9,100 to £5,000. Compare your 2025/26 cost against 2024/25 for any salary.",
        "h1": "NI rise calculator for UK employers (2025/26)",
        "badge": "NI rise / NI change",
        "intro": "From 6 April 2025, employer National Insurance rose from 13.8% to 15% and the secondary threshold fell from £9,100 to £5,000 per year. Both changes hit at once, which means lower-paid employees now attract employer NI on a much larger portion of their salary. At £30,000, the annual NI bill rose from approximately £2,884 to £3,750 — an increase of £866 per employee. At £35,000, the rise is around £915. Use the full employer cost calculator below to run your specific salary and see the exact 2025/26 versus 2024/25 comparison.",
        "bullets": [
            "NI rate change: 13.8% → 15% (from 6 April 2025).",
            "Threshold change: £9,100 → £5,000 secondary threshold.",
            "At £35,000 salary: NI rises from ~£3,585 to ~£4,500 (+£915/year).",
            "At £50,000 salary: NI rises from ~£5,640 to ~£6,750 (+£1,110/year).",
            "Employment Allowance increased from £5,000 to £10,500 for eligible smaller employers.",
        ],
        "primary_cta": {"label": "Run NI change comparison in calculator", "url": "/calculator"},
        "faq_items": [
            {"q": "What changed in April 2025 for employer NI?", "a": "Employer NI rose from 13.8% to 15%, and the secondary threshold fell from £9,100 to £5,000, both effective from 6 April 2025. Both changes apply at once, so lower-paid roles now face NI on a much larger earnings band at a higher rate."},
            {"q": "How much has employer NI increased per employee?", "a": "At £30,000, annual employer NI rose by approximately £866. At £35,000 it rose by around £915. At £50,000 the increase is approximately £1,110. Use the full employer cost calculator to see the exact change for your specific salary."},
            {"q": "Does Employment Allowance offset the NI increase?", "a": "It can offset part or all of employer NI for eligible smaller employers, but it does not change the underlying NI rate or threshold. Employment Allowance itself increased to £10,500 for 2025/26, which partially offsets the impact for eligible employers."},
            {"q": "Is this the same as a payroll NI change calculator?", "a": "Yes, this page explains the April 2025 NI change and links to a full calculator where you can enter salary, pension and overheads to see both 2025/26 and 2024/25 NI outcomes side by side."},
        ],
    },
    "/employer-costs-uk": {
        "title": "Employer Costs UK 2025/26 — What Employers Pay On Top of Salary",
        "description": "Full breakdown of UK employer costs for 2025/26: employer NI at 15% above £5,000, pension at 3% minimum, Employment Allowance up to £10,500. See exactly what you pay per employee.",
        "h1": "Employer costs UK (2025/26) — what you pay on top of salary",
        "badge": "Employer costs UK",
        "intro": "In the UK, an employer's cost is always higher than the stated salary. For 2025/26, you must add employer NI at 15% on earnings above £5,000, a minimum 3% pension contribution under auto-enrolment, and any per-employee overhead costs. For a £35,000 salary, the statutory employer costs (NI + pension) add £5,363 per year — taking total employer spend to at least £40,363 before overheads. Use the full employer cost calculator to model your specific payroll.",
        "bullets": [
            "Employer NI: 15% on all earnings above the £5,000 secondary threshold.",
            "Pension: minimum 3% on qualifying earnings between £6,240 and £50,270.",
            "Employment Allowance: up to £10,500/year off the NI bill for eligible employers.",
            "£30,000 salary → approx £34,464 total employer cost (NI + pension, no overheads).",
            "£50,000 salary → approx £58,063 total employer cost (NI + pension, no overheads).",
        ],
        "primary_cta": {"label": "Calculate your employer costs", "url": "/calculator"},
        "faq_items": [
            {"q": "What are the statutory employer costs in the UK for 2025/26?", "a": "The two statutory employer costs are: employer NI (15% on earnings above £5,000) and employer pension (minimum 3% of qualifying earnings between £6,240 and £50,270 under auto-enrolment). Both are mandatory on top of gross salary for most employees."},
            {"q": "How much do employer costs add on top of salary?", "a": "Typically 12–18% above gross salary for standard salaries. At £35,000: employer NI £4,500 + pension £863 = £5,363 extra (15.3% above salary). At £50,000: employer NI £6,750 + pension £1,313 = £8,063 extra (16.1% above salary)."},
            {"q": "What is Employment Allowance and how does it reduce employer costs?", "a": "Employment Allowance lets eligible employers offset up to £10,500 of their annual employer NI bill. For a small business with total employer NI below £10,500, this can eliminate the entire NI liability. Single-director companies with no other employees cannot claim."},
        ],
    },
    "/how-much-do-i-cost-my-employer": {
        "title": "How Much Do I Cost My Employer UK? 2025/26 | EmployerCalculator.co.uk",
        "description": "Find out what you cost your employer in 2025/26. Your employer pays NI at 15% and pension on top of your salary. Earn £35,000? You cost your employer approximately £40,363/year.",
        "h1": "How much do I cost my employer? (UK, 2025/26)",
        "badge": "Employee perspective",
        "intro": "Your gross salary is not what your employer pays for you. On top of your salary, your employer pays employer NI — 15% on earnings above £5,000 in 2025/26 — and a minimum 3% pension contribution. If you earn £35,000, your employer's total cost is approximately £40,363 per year. If you earn £50,000, it is approximately £58,063. Use the calculator below to see the exact figure for any salary.",
        "bullets": [
            "£25,000 salary → you cost your employer approx £29,214/year.",
            "£35,000 salary → you cost your employer approx £40,363/year.",
            "£50,000 salary → you cost your employer approx £58,063/year.",
            "£75,000 salary → you cost your employer approx £87,063/year.",
            "None of this is deducted from your pay — it is an additional cost on top.",
        ],
        "primary_cta": {"label": "See your true cost to your employer", "url": "/calculator"},
        "faq_items": [
            {"q": "How much more do I cost my employer than my salary?", "a": "Typically 13–18% above your gross salary. At £35,000: your employer pays ~£4,500 in NI and ~£863 in minimum pension on top of your salary — so you cost them roughly £40,363/year before any overheads or benefits."},
            {"q": "Does my employer pay NI on my full salary?", "a": "No — only on earnings above the £5,000 secondary threshold. At £35,000, NI is charged on £30,000 × 15% = £4,500. The first £5,000 of your salary is exempt from employer NI."},
            {"q": "Is employer NI taken from my pay?", "a": "No. Employer NI is paid by your employer on top of your gross salary. It is entirely separate from your own employee NI, which is deducted from your take-home pay at 8% between £12,570 and £50,270."},
        ],
    },
    "/paye-cost-to-employer-calculator": {
        "title": "PAYE Cost to Employer Calculator UK 2025/26 | EmployerCalculator.co.uk",
        "description": "Calculate the PAYE cost to employer for any UK salary. 2025/26: employer NI at 15% above £5,000 plus 3% minimum pension. Monthly and annual totals with 2024/25 comparison.",
        "h1": "PAYE cost to employer calculator (UK, 2025/26)",
        "badge": "PAYE employer cost",
        "intro": "The PAYE employer cost includes employer NI — charged at 15% on earnings above £5,000 for 2025/26 — plus the employer's minimum auto-enrolment pension contribution of 3% on qualifying earnings. The calculator below gives monthly and annual totals, Employment Allowance modelling, and a comparison against 2024/25 figures for any UK salary.",
        "bullets": [
            "Employer NI for 2025/26: 15% on earnings above the £5,000 secondary threshold.",
            "Minimum employer pension: 3% on qualifying earnings (£6,240–£50,270 band).",
            "Employment Allowance reduces employer NI bill by up to £10,500 for eligible employers.",
            "PAYE employer cost for £35,000 salary: approx £5,363/year above salary (NI + pension).",
        ],
        "primary_cta": {"label": "Open PAYE employer cost calculator", "url": "/calculator"},
        "faq_items": [
            {"q": "What is included in PAYE employer costs?", "a": "PAYE employer costs are employer NI (Class 1, secondary contributions) and employer pension under auto-enrolment. In 2025/26, employer NI is 15% above the £5,000 secondary threshold. Employer pension minimum is 3% of qualifying earnings between £6,240 and £50,270. Both are paid by the employer on top of gross salary."},
            {"q": "Is this a PAYE calculator for employers?", "a": "Yes. This page provides the employer-side PAYE cost model: employer NI and pension obligations. For employee take-home pay after income tax and employee NI, use AfterTaxSalary.co.uk."},
        ],
    },
    "/employer-national-insurance-calculator": {
        "title": "Employer National Insurance Calculator UK 2025/26 | EmployerCalculator.co.uk",
        "description": "Employer National Insurance calculator for UK employers. 2025/26: 15% on earnings above £5,000. See NI due by salary — annual and monthly — with 2024/25 comparison and Employment Allowance modelling.",
        "h1": "Employer National Insurance calculator (UK, 2025/26)",
        "badge": "Employer NI",
        "intro": "This employer National Insurance calculator uses 2025/26 rules: 15% on employee earnings above the £5,000 secondary threshold. Enter any salary to see annual and monthly employer NI, the 2024/25 comparison, and the impact of Employment Allowance. Commonly used when budgeting a new hire, checking a payroll assumption, or quantifying the April 2025 NI rise.",
        "bullets": [
            "2025/26 employer NI rate: 15% above the £5,000 secondary threshold.",
            "Employment Allowance up to £10,500 available for eligible employers.",
            "Compare 2024/25 (13.8% above £9,100) with 2025/26 rates.",
            "No upper earnings cap — employer NI continues at 15% on all earnings above threshold.",
        ],
        "primary_cta": {"label": "Open employer NI calculator", "url": "/employer-ni"},
        "faq_items": [
            {"q": "How do I calculate employer National Insurance?", "a": "Multiply (gross salary minus £5,000) by 15%. For example: £35,000 minus £5,000 = £30,000 × 15% = £4,500 employer NI per year (2025/26). Use the employer NI table to look up any standard salary."},
            {"q": "What is the employer NI rate in 2025/26?", "a": "The employer NI rate for 2025/26 is 15% on earnings above the £5,000 secondary threshold (down from £9,100 in 2024/25). The rate itself increased from 13.8% to 15% from 6 April 2025."},
            {"q": "What is Employment Allowance and who can claim it?", "a": "Employment Allowance lets eligible employers reduce their employer NI bill by up to £10,500 per year in 2025/26. Most limited companies with at least one employee who is not a sole director qualify. Single-director companies with no other employees cannot claim."},
        ],
    },
    "/salary-calculator-for-employers": {
        "title": "Salary Calculator for Employers UK 2025/26 — True Cost to Employer | EmployerCalculator.co.uk",
        "description": "Free salary calculator for UK employers. See the true employer cost of any salary — NI at 15%, pension at 3%, and overhead assumptions — with annual and monthly totals for 2025/26.",
        "h1": "Salary calculator for employers (UK, 2025/26)",
        "badge": "Salary cost",
        "intro": "When an employer sees a salary figure, the actual cost is higher — employer NI at 15% above £5,000, pension at 3% of qualifying earnings, and any workspace or equipment overheads on top. This salary calculator for employers converts a gross salary into a full annual and monthly employer cost for 2025/26, so offer approvals, headcount budgets and cost-per-hire estimates use a consistent number.",
        "bullets": [
            "A £30,000 salary costs approximately £34,464/year total — 15% above headline.",
            "A £40,000 salary costs approximately £45,813/year (with £3,000 overheads).",
            "A £60,000 salary costs approximately £68,563/year total.",
            "Adjust pension rate and overhead assumptions for your specific payroll policy.",
        ],
        "primary_cta": {"label": "Open salary calculator for employers", "url": "/calculator"},
        "faq_items": [
            {"q": "Why does a salary cost more than the stated figure?", "a": "UK employers pay employer NI on top of gross salary — 15% of earnings above £5,000 in 2025/26 — plus a minimum 3% employer pension contribution. A £35,000 salary typically costs around £40,363/year total before additional overheads."},
            {"q": "What is included in a full employer salary cost?", "a": "Gross salary, employer NI (15% above £5,000), employer pension (3% minimum on qualifying earnings), and any overhead costs such as equipment, software or workspace. Use the full employer cost calculator to model all four components."},
            {"q": "How do I use this as a pay calculator for employers?", "a": "Enter gross salary, choose your pension rate and overhead assumptions, and apply Employment Allowance if eligible. The calculator shows annual and monthly totals, a cost breakdown chart, and comparison against 2024/25 NI assumptions."},
        ],
    },
    "/employee-cost-calculator-uk": {
        "title": "Employee Cost Calculator UK 2025/26 — True Cost per Employee | EmployerCalculator.co.uk",
        "description": "Employee cost calculator for UK employers. The true cost per employee includes salary, employer NI at 15% above £5,000, and pension at 3% minimum. See annual and monthly totals for 2025/26.",
        "h1": "Employee cost calculator UK (2025/26)",
        "badge": "Employee cost",
        "intro": "The true cost of an employee is not just their salary. UK employers must also pay employer NI — 15% on earnings above the £5,000 secondary threshold from April 2025 — plus a minimum 3% pension contribution under auto-enrolment. This employee cost calculator models those three components for any salary and shows monthly and annual totals. For total workforce cost planning, include per-employee overhead assumptions.",
        "bullets": [
            "Salary + employer NI + pension = baseline employee cost floor.",
            "Add overheads (equipment, software, workspace) for realistic total per-employee spend.",
            "Compare 2024/25 and 2025/26 NI assumptions to understand cost drift.",
            "Employment Allowance can offset NI for eligible smaller employers.",
        ],
        "primary_cta": {"label": "Calculate true cost per employee", "url": "/calculator"},
        "faq_items": [
            {"q": "What is the true cost of an employee UK?", "a": "The statutory minimum cost of an employee in the UK is salary plus employer NI (15% above £5,000 for 2025/26) plus minimum employer pension (3% of qualifying earnings). A £35,000 employee costs approximately £40,363/year before overheads."},
            {"q": "How much does an employee cost on top of their salary in the UK?", "a": "Typically 15–20% above gross salary. At £30,000: roughly £4,464 extra in NI and pension. At £50,000: roughly £8,063 extra. Overheads (equipment, software, workspace) add a further £2,000–£5,000 for most roles."},
            {"q": "Does this include employer pension costs?", "a": "Yes. The calculator includes minimum employer pension at 3% of qualifying earnings (£6,240 to £50,270 band). You can adjust the pension rate to match your actual employer contribution policy."},
        ],
    },
    "/employer-ni-calculator-2025-26": {
        "title": "Employer NI Calculator 2025/26 | 15% Rate, £5,000 Threshold — EmployerCalculator.co.uk",
        "description": "Employer NI calculator for 2025/26: 15% on earnings above the £5,000 secondary threshold. See NI due by salary, monthly and annual. Employment Allowance up to £10,500 included. Compare 2024/25 vs 2025/26.",
        "h1": "Employer NI calculator 2025/26 (UK)",
        "badge": "2025/26 employer NI",
        "intro": "This employer NI calculator covers the 2025/26 rules: 15% on employee earnings above the £5,000 secondary threshold. Enter any salary and see annual and monthly NI, with Employment Allowance modelling and a side-by-side 2024/25 comparison. For a full cost view including pension and overheads, use the total employer cost calculator.",
        "bullets": [
            "2025/26 employer NI rate: 15% above the £5,000 secondary threshold.",
            "Example: £40,000 salary → £5,250 employer NI/year (£437.50/month).",
            "Employment Allowance up to £10,500 can offset eligible employers' NI bill.",
            "No upper earnings cap on employer NI (unlike employee NI which drops to 2% above £50,270).",
            "Use the full calculator for pension, overhead and total employer cost modelling.",
        ],
        "primary_cta": {"label": "Open employer NI calculator 2025/26", "url": "/calculator"},
        "faq_items": [
            {"q": "What is the employer NI rate for 2025/26?", "a": "The employer NI rate for 2025/26 is 15% on employee earnings above the secondary threshold of £5,000 per year (£96.15/week). This applies to standard Class 1 contributions. Reduced rates of 0% apply for employees under 21 and apprentices under 25."},
            {"q": "Is there an upper cap on employer NI?", "a": "No. Employer NI is charged at 15% above the £5,000 threshold with no upper earnings cap. Unlike employee NI which drops to 2% above £50,270, employer NI continues at 15% on all earnings above threshold."},
            {"q": "How do I calculate employers NI on a salary?", "a": "Multiply (gross salary minus £5,000) by 15%. For example: £35,000 salary — £5,000 = £30,000 × 15% = £4,500 employer NI per year."},
        ],
    },
    "/uk-average-salary": {
        "title": "UK Average Salary 2025/26 — What It Costs Employers | EmployerCalculator.co.uk",
        "description": "The UK average salary is approximately £37,430/year (ONS 2024). For employers, that means ~£42,544 total annual cost including employer NI at 15% and 3% pension. See the full breakdown.",
        "h1": "UK average salary — and what it costs employers (2025/26)",
        "badge": "Average salary",
        "intro": "The UK median full-time salary is approximately £37,430 per year according to the ONS Annual Survey of Hours and Earnings (2024). For employers, the total cost is higher — employer NI at 15% above the £5,000 secondary threshold adds approximately £4,864, and minimum auto-enrolment pension at 3% of qualifying earnings adds £942. Total employer cost for the average UK salary: approximately £43,236 per year, or £3,603 per month. Use the calculator to model any salary.",
        "bullets": [
            "UK median full-time salary (ONS 2024): ~£37,430/year (£3,119/month gross).",
            "Employer NI on average salary: ~£4,864/year at 15% above £5,000.",
            "Employer pension on average salary: ~£942/year at 3% of qualifying earnings.",
            "Total cost to employer for average UK salary: approximately £43,236/year.",
            "Average monthly salary UK (gross): ~£3,119. Take-home varies by tax code — see AfterTaxSalary.co.uk.",
        ],
        "primary_cta": {"label": "Calculate cost for any salary", "url": "/calculator"},
        "secondary_cta": {"label": "See take-home pay on AfterTaxSalary.co.uk", "url": "https://aftertaxsalary.co.uk"},
        "faq_items": [
            {"q": "What is the average monthly salary in the UK?", "a": "Based on ONS ASHE 2024 data, the UK median full-time gross salary is approximately £37,430/year — that is roughly £3,119 per month before tax and deductions. Average salary varies significantly by sector, region and role."},
            {"q": "What does the UK average salary cost an employer per month?", "a": "At a £37,430 salary, an employer pays approximately £3,603/month total — the gross salary (£3,119) plus employer NI (~£405/month) plus minimum pension (~£79/month). Overhead costs are additional."},
            {"q": "What is the average take-home pay in the UK?", "a": "Take-home pay on a £37,430 salary is approximately £28,500–£29,500 per year for a standard taxpayer in England — around £2,375–£2,460 per month after income tax and employee NI. The exact figure depends on your tax code and student loan status. Use AfterTaxSalary.co.uk for a precise figure."},
            {"q": "What is the UK average salary in 2025?", "a": "The most recent ONS data (ASHE 2024, published October 2024) puts median full-time UK earnings at £37,430/year. The mean (average) full-time salary is higher at approximately £44,000 due to high earners skewing the average."},
            {"q": "Is the UK average salary before or after tax?", "a": "All salary figures quoted by ONS are gross (before tax). Employers pay this gross amount plus employer NI and pension on top. Employees receive net pay after income tax, employee NI and any student loan deductions."},
        ],
    },
    "/employer-ni-historical-rates": {
        "title": "Employer NI Historical Rates — 2020/21, 2022/23, 2023/24, 2024/25, 2025/26 | EmployerCalculator.co.uk",
        "description": "Employer NI rates and thresholds by tax year: 2020/21 to 2025/26. Rate rose from 13.8% to 15% in April 2025. Secondary threshold dropped from £9,100 to £5,000. Use for prior-year cost comparisons.",
        "h1": "Employer National Insurance — historical rates by tax year",
        "badge": "Historical rates",
        "intro": "Employer National Insurance rates and secondary thresholds have changed significantly in recent years. The most significant change was from April 2025 (2025/26): the rate increased from 13.8% to 15% and the secondary threshold dropped from £9,100 to £5,000, sharply increasing the cost of lower-paid roles. Use this page to look up the correct rate for a prior tax year, or use the calculator for 2025/26 modelling.",
        "bullets": [
            "2025/26: 15% above £5,000 secondary threshold (from April 2025).",
            "2024/25: 13.8% above £9,100 secondary threshold.",
            "2023/24: 13.8% above £9,100 secondary threshold.",
            "2022/23: 13.8% above £9,100 (July 2022 onwards; 15.05% Apr–Jul 2022 with health & social care levy).",
            "2021/22: 13.8% above £8,840 secondary threshold.",
            "2020/21: 13.8% above £8,788 secondary threshold.",
        ],
        "primary_cta": {"label": "Calculate 2025/26 employer NI now", "url": "/employer-ni"},
        "faq_items": [
            {"q": "What was the employer NI rate in 2022/23?", "a": "In 2022/23, employer NI was 13.8% above the £9,100 secondary threshold. From April to July 2022 a temporary 1.25% Health and Social Care Levy uplift applied, making the effective rate 15.05% for that period. It reverted to 13.8% from November 2022."},
            {"q": "What was the employer NI rate in 2023/24?", "a": "In 2023/24, employer NI was 13.8% above the £9,100 secondary threshold. The rate and threshold were unchanged from 2022/23 (post-levy reversal)."},
            {"q": "What was the employer NI rate in 2024/25?", "a": "In 2024/25, employer NI remained at 13.8% above the £9,100 secondary threshold. This changed significantly from April 2025 when the rate rose to 15% and the threshold dropped to £5,000."},
            {"q": "When did employer NI change to 15%?", "a": "Employer NI increased from 13.8% to 15% from 6 April 2025 (the start of the 2025/26 tax year), as announced in the October 2024 Budget. At the same time, the secondary threshold dropped from £9,100 to £5,000."},
            {"q": "How do I calculate employer NI for a previous tax year?", "a": "Multiply (gross salary minus the threshold for that year) by the rate for that year. For 2024/25: (salary − £9,100) × 13.8%. For 2025/26: (salary − £5,000) × 15%. The full-year cost for 2025/26 is substantially higher for most salaries due to both rate and threshold changes."},
        ],
    },
    "/true-cost-of-employee-calculator-uk": {
        "title": "True Cost of an Employee Calculator UK 2025/26 | EmployerCalculator.co.uk",
        "description": "Calculate the true cost of an employee UK. A £35k employee costs £40,363/year — salary plus employer NI at 15% plus 3% pension. Free 2025/26 calculator with overheads and Employment Allowance.",
        "h1": "True cost of an employee calculator (UK, 2025/26)",
        "badge": "True cost",
        "intro": "The true cost of an employee is always higher than the salary on the offer letter. For 2025/26 UK employers must pay employer NI at 15% on earnings above £5,000, a minimum 3% pension under auto-enrolment, and carry any per-employee overhead costs on top. The calculator below gives the true total for any salary — annual and monthly — with Employment Allowance modelling for eligible employers.",
        "bullets": [
            "£25,000 salary → ~£28,563/year true cost (employer NI + pension).",
            "£35,000 salary → ~£40,363/year true cost (with £3,000 overhead assumption).",
            "£50,000 salary → ~£58,063/year true cost (with £3,000 overhead assumption).",
            "£75,000 salary → ~£86,813/year true cost (with £3,000 overhead assumption).",
            "Employment Allowance (up to £10,500) reduces NI for eligible employers.",
        ],
        "primary_cta": {"label": "Calculate true cost of your employee", "url": "/calculator"},
        "faq_items": [
            {"q": "What is the true cost of an employee in the UK?", "a": "In 2025/26, the true minimum cost is gross salary plus employer NI (15% above £5,000) plus employer pension (3% of qualifying earnings). A £35,000 salary costs approximately £40,363/year before additional overheads."},
            {"q": "How much does a £30,000 employee really cost?", "a": "A £30,000 salary costs approximately £34,464/year including employer NI of ~£3,750 and pension of ~£714. With typical overhead assumptions (equipment, software, workspace) the figure rises to approximately £37,464."},
            {"q": "What overheads should I include in employee cost?", "a": "Common overhead inclusions: desk/workspace cost (£1,500–£3,000/year), IT equipment and software licences (£500–£1,500/year), recruitment amortisation, and training budget. The calculator allows a custom overhead figure."},
            {"q": "How does Employment Allowance affect the true cost?", "a": "Eligible employers can offset up to £10,500 of employer NI per year with Employment Allowance. For a small team this can significantly reduce per-employee cost — especially for lower salary ranges where NI is a larger proportion of total cost."},
        ],
    },
    "/employer-salary-cost-calculator-uk": {
        "title": "Employer Salary Cost Calculator UK (2025/26) — True Cost Above Salary | EmployerCalculator.co.uk",
        "description": "UK employer salary cost calculator for 2025/26. See the true cost of any salary — employer NI at 15% above £5,000, pension at 3% minimum. £35k salary = £40,363/yr. Monthly and annual totals.",
        "h1": "Employer salary cost calculator UK (2025/26)",
        "badge": "Salary cost",
        "intro": "An employer's salary cost is always higher than the stated gross salary. For 2025/26, you must add employer NI at 15% on earnings above £5,000 and a minimum 3% employer pension contribution under auto-enrolment. This employer salary cost calculator UK page shows the true annual and monthly cost for any salary, with a side-by-side 2024/25 comparison and optional Employment Allowance and overhead modelling. Use the calculator below for any specific figure.",
        "bullets": [
            "Employer NI is 15% on earnings above £5,000 — no upper earnings cap.",
            "Employer pension minimum is 3% of qualifying earnings between £6,240 and £50,270.",
            "A £35,000 salary costs approximately £39,500/year — £40,363 with £3k overheads.",
            "A £50,000 salary costs approximately £58,063/year including NI, pension and £3k overheads.",
            "Employment Allowance (up to £10,500) can reduce net NI for eligible employers.",
        ],
        "primary_cta": {"label": "Open employer salary cost calculator", "url": "/calculator"},
        "faq_items": [
            {"q": "What does employer salary cost include?", "a": "Employer salary cost includes gross salary, employer NI (15% on earnings above £5,000 for 2025/26), and minimum employer pension (3% of qualifying earnings under auto-enrolment). It does not automatically include recruitment fees, training or equipment — add an overhead figure in the full calculator for a total picture."},
            {"q": "How do I calculate employer salary cost UK?", "a": "Formula: gross salary + (salary − £5,000) × 15% + (min(salary, £50,270) − £6,240) × 3%. For £35,000: £35,000 + £4,500 NI + £863 pension = £40,363. Use the calculator above for any salary."},
            {"q": "What is the employer salary cost for £30,000?", "a": "For a £30,000 salary in 2025/26, the employer cost before overheads is approximately £34,464: £30,000 salary + £3,750 employer NI + £714 pension. With a standard overhead assumption of £3,000, total rises to approximately £37,464."},
            {"q": "Does Employment Allowance reduce employer salary cost?", "a": "Yes. Eligible employers can claim up to £10,500 of Employment Allowance per year, reducing their employer NI bill. This can materially lower the net employer salary cost for smaller businesses. Single-director companies with no other employees cannot claim."},
        ],
    },
    "/first-employee-cost-uk": {
        "title": "Cost of Hiring Your First Employee UK (2025/26) | EmployerCalculator.co.uk",
        "description": "What does it cost to hire your first employee in the UK? Employer NI at 15%, pension at 3%, Employment Allowance for eligible new employers. Free 2025/26 calculator and guide.",
        "h1": "Cost of hiring your first employee in the UK (2025/26)",
        "badge": "First employee",
        "intro": "Hiring your first employee costs more than the salary figure on the offer letter. In 2025/26, UK employers pay employer NI at 15% on earnings above £5,000, and must make minimum 3% pension contributions once the employee is auto-enrolled. Most first-time employers also qualify for Employment Allowance, which can offset up to £10,500 of employer NI. This page gives the true cost model with worked examples and the allowance calculation included.",
        "bullets": [
            "Employer NI for 2025/26: 15% on earnings above £5,000 secondary threshold.",
            "Auto-enrolment pension: 3% minimum on qualifying earnings £6,240–£50,270.",
            "Employment Allowance: up to £10,500 off your NI bill — available to most first employers.",
            "At £28,000 salary with allowance, recurring cost ≈ £28,653/yr.",
            "Without allowance, a £28,000 salary costs approximately £32,153/yr.",
        ],
        "primary_cta": {"label": "Calculate first employee cost", "url": "/calculator"},
        "secondary_cta": {"label": "Read the full guide", "url": "/guides/first-employee-cost"},
        "faq_items": [
            {"q": "Can I claim Employment Allowance for my first employee?", "a": "Most first-time employers who are not sole-director companies can claim Employment Allowance. Once you hire at least one employee who is not a fellow director, you are usually eligible. The allowance offsets up to £10,500 of employer NI per year in 2025/26."},
            {"q": "When do I need to auto-enrol my first employee?", "a": "You must auto-enrol within six weeks of the employee's start date if they are aged 22 to State Pension Age and earn more than £10,000 per year. Set up a pension provider (NEST is a free government-backed option) before their first payroll run."},
            {"q": "What is the true total cost of hiring someone at £30,000?", "a": "At £30,000 salary, employer NI is £3,750 per year (15% above £5,000) and pension is £714 per year (3% of qualifying earnings). Total employer cost before overheads: approximately £34,464 per year. With Employment Allowance, the NI is offset — bringing the figure to approximately £30,714."},
        ],
    },
    "/part-time-employee-cost": {
        "title": "Part-Time Employee Cost UK (2025/26) — Employer NI, Pension & True Cost | EmployerCalculator.co.uk",
        "description": "How much does a part-time employee cost a UK employer? Employer NI at 15% applies on earnings above £5,000, pension applies above £10,000 earnings. Free 2025/26 calculator.",
        "h1": "Part-time employee cost UK (2025/26)",
        "badge": "Part-time cost",
        "intro": "Part-time employees carry most of the same employer cost obligations as full-time staff. Employer NI at 15% applies on earnings above £5,000 regardless of hours — the threshold is not pro-rated. Auto-enrolment pension applies if the part-time employee earns more than £10,000 per year with you and is the right age. This page sets out the true recurring cost of part-time employees at common salary levels for 2025/26.",
        "bullets": [
            "Employer NI threshold of £5,000 is fixed — not reduced for part-time hours.",
            "Auto-enrolment applies above £10,000 earnings in a single job.",
            "At £15,000 part-time salary: NI = £1,500/yr, pension = £262/yr. Total ≈ £16,762/yr.",
            "At £20,000 part-time salary: NI = £2,250/yr, pension = £411/yr. Total ≈ £22,661/yr.",
            "Employment Allowance applies to part-time employees the same as full-time.",
        ],
        "primary_cta": {"label": "Calculate part-time employee cost", "url": "/calculator"},
        "secondary_cta": {"label": "Read the full guide", "url": "/guides/part-time-employee-cost"},
        "faq_items": [
            {"q": "Do I pay employer NI on part-time employees?", "a": "Yes. The £5,000 secondary threshold is not pro-rated for part-time hours. Employer NI at 15% applies to all earnings above £5,000 regardless of how many hours the employee works. A part-time worker earning £15,000 per year generates £1,500 in employer NI."},
            {"q": "Do I need to auto-enrol a part-time worker?", "a": "You must auto-enrol if the worker earns more than £10,000 per year from you, is aged 22 to State Pension Age, and works in the UK. If they earn between £6,240 and £10,000, they can opt in but you do not have to enrol them automatically. Below £6,240, no pension obligation applies."},
            {"q": "How much does a part-time employee on £16,000 cost?", "a": "At £16,000 salary in 2025/26: employer NI is £1,650 per year (15% of £11,000). Pension qualifying earnings are £16,000 − £6,240 = £9,760; minimum employer contribution is £292.80 per year. Total employer cost before overheads: approximately £17,943 per year."},
        ],
    },
    "/minimum-wage-employer-cost": {
        "title": "Minimum Wage Employer Cost UK 2025/26 — NI, Pension & True Total | EmployerCalculator.co.uk",
        "description": "What does a minimum wage employee cost a UK employer in 2025/26? Employer NI at 15%, pension at 3%, and true recurring cost at the 2025/26 National Minimum Wage and National Living Wage rates.",
        "h1": "Minimum wage employer cost UK (2025/26)",
        "badge": "Minimum wage",
        "intro": "The National Living Wage (NLW) for workers aged 21 and over is £12.71 per hour from April 2026, giving an annual salary of approximately £24,785 for a standard 37.5-hour week. For employers, the true cost of a minimum wage employee in 2026/27 is higher — employer NI at 15% on earnings above £5,000 adds approximately £2,968 per year, and minimum auto-enrolment pension adds approximately £556 per year. Total employer cost for a full-time NLW employee: approximately £28,309 per year before overheads. Use the calculator below for any specific salary or hours.",
        "bullets": [
            "National Living Wage (21+): £12.71/hr from April 2026. Full-time ≈ £24,785/yr.",
            "National Minimum Wage (18–20): £10.00/hr. Under-18: £7.55/hr.",
            "Employer NI on £24,785: approximately £2,968/year (15% above £5,000).",
            "Employer pension on £24,785: approximately £556/year (3% of qualifying earnings).",
            "Total employer cost for full-time NLW employee: approximately £28,309/year before overheads.",
        ],
        "primary_cta": {"label": "Calculate minimum wage employer cost", "url": "/calculator"},
        "faq_items": [
            {"q": "What is the National Living Wage from April 2026?", "a": "The National Living Wage (NLW) for workers aged 21 and over is £12.71 per hour from April 2026. For a 37.5-hour week, this gives an annual salary of approximately £24,785. The rate increased from £12.21 per hour in 2025/26."},
            {"q": "How much does a minimum wage employee cost an employer?", "a": "A full-time employee on the 2025/26 National Living Wage (£24,785/year) costs an employer approximately £28,309 per year: £24,785 salary + £2,968 employer NI (15% above £5,000) + £556 employer pension (3% of qualifying earnings). With typical overheads of £2,000–£3,000, total rises to approximately £29,000–£30,000."},
            {"q": "Do employers pay NI on minimum wage workers?", "a": "Yes. Employer NI at 15% applies on all earnings above £5,000 per year, regardless of wage rate. A minimum wage employee earning £24,785 per year generates £2,968 in employer NI. The April 2025 threshold change from £9,100 to £5,000 specifically increased costs for lower-paid workers, including those on minimum wage."},
            {"q": "Has Employment Allowance changed what minimum wage workers cost?", "a": "Employment Allowance can eliminate the employer NI bill for eligible small employers — up to £10,500 per year. For businesses with small teams all earning near minimum wage, this can reduce the per-employee NI cost to zero. Single-director companies without other staff cannot claim."},
        ],
    },
    "/employer-cost-per-employee": {
        "title": "Employer Cost Per Employee UK 2025/26 — NI, Pension & Average Total | EmployerCalculator.co.uk",
        "description": "What is the average employer cost per employee in the UK? At the median salary of £37,430, employer NI and pension add approximately £5,806/year. Full 2025/26 breakdown by salary level.",
        "h1": "Employer cost per employee UK (2025/26)",
        "badge": "Cost per employee",
        "intro": "The employer cost per employee in the UK is always higher than the headline salary. At the UK median full-time salary of approximately £37,430 (ONS ASHE 2024), an employer pays around £4,864 in employer NI (15% above the £5,000 secondary threshold) and £942 in minimum pension (3% on qualifying earnings), bringing the statutory cost per employee to approximately £43,236 per year. This page shows cost per employee at common UK salary levels so you can benchmark and plan headcount budgets for 2025/26.",
        "bullets": [
            "UK median full-time salary 2024/25: approximately £37,430 (ONS ASHE 2024).",
            "Employer NI on £37,430: approximately £4,864/year at 15% above £5,000.",
            "Employer pension on £37,430: approximately £942/year at 3% of qualifying earnings.",
            "Total statutory employer cost at median salary: approximately £43,236/year.",
            "Employment Allowance can offset up to £10,500 NI for eligible smaller employers.",
        ],
        "primary_cta": {"label": "Calculate employer cost per employee", "url": "/calculator"},
        "faq_items": [
            {"q": "What is the average employer cost per employee in the UK?", "a": "At the UK median full-time salary of approximately £37,430 (ONS ASHE 2024), the total employer cost per employee is approximately £43,236 per year — £37,430 salary plus £4,864 employer NI and £942 employer pension. Adding typical workplace overheads of £3,000 per employee brings the figure to approximately £46,236."},
            {"q": "How much does employer NI cost per employee in 2025/26?", "a": "Employer NI per employee depends on salary. At £25,000 it is £3,000/year. At £35,000 it is £4,500/year. At £50,000 it is £6,750/year. The rate is 15% on all earnings above the £5,000 secondary threshold, with no upper cap."},
            {"q": "What overhead costs should I add to per-employee budget?", "a": "Beyond NI and pension, common per-employee overheads include desk space or remote work allowance (£1,000–£3,000/year), IT equipment and software licences (£500–£1,500/year), training budget, and any benefits such as health insurance or enhanced pension. For planning purposes, £2,000–£5,000 per head is a common overhead assumption for UK office-based roles."},
        ],
    },
}


INDUSTRY_PAGES: Dict[str, Dict] = {
    "cost-of-employing-hospitality-staff": {
        "title": "Cost of Employing Hospitality Staff UK 2025/26 — Employer NI, Pension & Total",
        "description": "True employer cost of hospitality staff in 2025/26. Employer NI at 15%, pension at 3%, total cost for chefs, front-of-house and managers at UK hospitality salary levels.",
        "h1": "Cost of employing hospitality staff UK (2025/26)",
        "badge": "Hospitality sector",
        "example_salary": 24000,
        "salary_range": "£23,809 (NLW) – £45,000",
        "intro": "Hospitality is one of the UK's most labour-intensive sectors and one of the hardest hit by the April 2025 employer NI changes. With a large proportion of staff earning at or near the National Living Wage (£12.71/hour), the threshold cut from £9,100 to £5,000 has increased per-employee NI costs proportionally more than in higher-salary industries. At a typical front-of-house salary of £24,000, employer NI is approximately £2,850 per year — up from approximately £2,060 under 2024/25 rules. A kitchen porter or bar worker on NLW full-time (£24,785) generates employer NI of approximately £2,968 per year, pension of approximately £556, giving a total employer cost of approximately £28,309 before overheads.",
        "bullets": [
            "Typical front-of-house salary: £23,809–£27,000 (NLW to senior waiting staff).",
            "Chef de partie / junior chef: £26,000–£35,000. Head chef: £35,000–£55,000.",
            "Employer NI on £24,000 salary: approximately £2,850/year (15% above £5,000).",
            "Minimum employer pension on £24,000: approximately £531/year (3% of qualifying earnings).",
            "Hospitality managers: £28,000–£45,000 salary range, employer NI £3,450–£6,000/year.",
            "April 2025 NI threshold change particularly impacted lower-wage hospitality employers.",
        ],
        "primary_cta": {"label": "Calculate hospitality staff employer cost", "url": "/calculator?salary=24000"},
        "secondary_cta": {"label": "Cost by salary level", "url": "/cost-of-employing"},
        "faq_items": [
            {"q": "How has the employer NI change affected hospitality businesses?", "a": "The April 2025 changes raised employer NI from 13.8% to 15% and cut the secondary threshold from £9,100 to £5,000. For hospitality staff on NLW (£24,785/year), this added approximately £790 per employee per year in NI costs. For a venue employing 10 staff at NLW, that represents around £7,900 per year in additional employer NI."},
            {"q": "Do hospitality employers have to auto-enrol staff?", "a": "Yes, if workers are aged 22–66 and earn more than £10,000 per year. For full-time hospitality staff on NLW earning £24,785, auto-enrolment is mandatory and the minimum employer contribution is 3% of qualifying earnings — approximately £556/year. Workers below £10,000 can opt in, but the employer contribution obligation also applies."},
            {"q": "Can hospitality businesses claim Employment Allowance?", "a": "Yes, if eligible. Most hospitality businesses with more than one employee qualify for Employment Allowance, which offsets up to £10,500 of annual employer NI. For a small restaurant or pub with six to eight staff earning near NLW, this can eliminate the entire annual NI bill — leaving only pension contributions and salary as the above-salary costs."},
        ],
    },
    "cost-of-employing-care-workers": {
        "title": "Cost of Employing Care Workers UK 2025/26 — Employer NI, Pension & Total",
        "description": "Employer cost for care workers in 2025/26. Salary benchmarks, employer NI at 15%, pension at 3%, total cost for domiciliary and residential care staff.",
        "h1": "Cost of employing care workers UK (2025/26)",
        "badge": "Care sector",
        "example_salary": 25000,
        "salary_range": "£23,809 (NLW) – £32,000",
        "intro": "Care workers in England, Scotland, Wales and Northern Ireland are predominantly paid between the National Living Wage and approximately £14–£15 per hour. In 2025/26, employer NI applies at 15% on all earnings above £5,000 — and with care roles typically earning £22,000–£28,000 per year, a larger share of salary falls in the NIable band than before the April 2025 threshold change. At £25,000 salary, employer NI is £3,000 per year and minimum pension is approximately £563, giving a total employer cost of approximately £28,563 before any overheads. For domiciliary care providers with large numbers of part-time workers, NI applies on each employee individually — hours are not pooled.",
        "bullets": [
            "Care assistant / support worker: typically £23,809–£26,000 (NLW to experienced level).",
            "Senior care worker / team leader: £26,000–£32,000.",
            "Care coordinator / registered manager: £28,000–£45,000.",
            "Employer NI on £25,000: approximately £3,000/year (15% above £5,000).",
            "Minimum pension on £25,000: approximately £563/year (3% of qualifying earnings).",
            "NI threshold is NOT pro-rated for part-time hours — applies in full per employee.",
        ],
        "primary_cta": {"label": "Calculate care worker employer cost", "url": "/calculator?salary=25000"},
        "secondary_cta": {"label": "Part-time employee cost", "url": "/part-time-employee-cost"},
        "faq_items": [
            {"q": "Does the employer NI threshold apply per employee or per organisation?", "a": "The £5,000 secondary threshold applies per employee, individually. A domiciliary care provider with 20 part-time workers cannot pool their hours or earnings to benefit from a single threshold — each worker's NI is calculated individually. This means even low-hour part-time care workers generate employer NI once their annual pay exceeds £5,000."},
            {"q": "How much does a care worker cost an employer per year?", "a": "A care assistant earning £25,000 costs an employer approximately £28,563 per year before overheads — £25,000 salary, approximately £3,000 employer NI and approximately £563 minimum pension. With mileage, training and coordination costs typical in domiciliary care, total per-employee cost is often £30,000–£32,000 per year."},
            {"q": "Is Employment Allowance available to care providers?", "a": "Most care employers with more than one employee qualify for Employment Allowance, which offsets up to £10,500 of annual employer NI in 2025/26. For smaller domiciliary care businesses with three to five employees, this can significantly reduce net NI payable. Single-director companies with no other employees cannot claim."},
        ],
    },
    "cost-of-employing-retail-staff": {
        "title": "Cost of Employing Retail Staff UK 2025/26 — Employer NI, Pension & Total",
        "description": "What does it cost to employ retail staff in the UK in 2025/26? Employer NI at 15%, pension contributions and total per-employee cost at typical retail wage levels.",
        "h1": "Cost of employing retail staff UK (2025/26)",
        "badge": "Retail sector",
        "example_salary": 24785,
        "salary_range": "£23,809 (NLW) – £40,000",
        "intro": "Retail is the UK's largest private-sector employer, and the majority of retail staff are paid at or close to the National Living Wage. In 2026/27, a full-time retail assistant on NLW (£12.71/hour) earns approximately £24,785 per year. The employer's total cost — salary, employer NI (15% above £5,000) and minimum pension — is approximately £28,309 per year. For retailers employing large numbers of part-time workers, each individual employee has their own NI threshold assessment. The April 2025 threshold change (from £9,100 to £5,000) has added approximately £790 per full-time NLW employee per year in additional employer NI.",
        "bullets": [
            "Retail sales assistant (NLW full-time): ~£24,785/year salary, ~£28,309 total cost.",
            "Supervisor / team leader: £26,000–£32,000, total cost £30,300–£37,600.",
            "Store manager (small format): £28,000–£40,000, total cost £32,800–£46,300.",
            "Employer NI on NLW salary (£24,785): approximately £2,968/year.",
            "Minimum pension on NLW salary: approximately £556/year.",
            "April 2025 NI change adds ~£790/year per NLW full-time retail worker.",
        ],
        "primary_cta": {"label": "Calculate retail staff employer cost", "url": "/calculator?salary=24785"},
        "secondary_cta": {"label": "Minimum wage employer cost", "url": "/minimum-wage-employer-cost"},
        "faq_items": [
            {"q": "How much does a part-time retail worker cost an employer?", "a": "A part-time retail worker on 20 hours per week at NLW (£12.71/hr) earns approximately £12,699/year. Employer NI on that salary is approximately £1,155 (15% of £7,699 above the £5,000 threshold) and minimum pension is approximately £195. Total employer cost before overheads: approximately £14,049/year. The NI threshold (£5,000) applies in full, not pro-rated for part-time hours."},
            {"q": "Do retailers have to pay pension on minimum wage staff?", "a": "Yes, if the employee is aged 22–66 and earns more than £10,000/year. For full-time NLW staff earning £24,785, auto-enrolment is mandatory. For part-time staff earning under £10,000, they can opt in but are not automatically enrolled — however if they opt in, the employer must still contribute at minimum 3% of qualifying earnings."},
            {"q": "How does Employment Allowance help retail employers?", "a": "For small retailers with total employer NI below £10,500/year, Employment Allowance can eliminate the entire NI bill. A small shop with five full-time NLW staff generates approximately £14,105 in total employer NI per year, so Employment Allowance (£10,500) would reduce net NI payable to approximately £3,605 per year. Larger retail chains above the eligibility criteria cannot claim."},
        ],
    },
    "cost-of-employing-construction-workers": {
        "title": "Cost of Employing Construction Workers UK 2025/26 — Employer NI, Pension & Total",
        "description": "Employer cost for construction workers in the UK in 2025/26. Salary benchmarks for labourers, tradespeople and site managers, with employer NI and pension calculations.",
        "h1": "Cost of employing construction workers UK (2025/26)",
        "badge": "Construction sector",
        "example_salary": 35000,
        "salary_range": "£24,000–£65,000",
        "intro": "Construction employment spans a wide salary range — from general labourers earning close to the National Living Wage to experienced site managers and senior engineers commanding £55,000–£70,000 or more. At a mid-market salary of £35,000 (common for an experienced tradesperson such as a joiner, electrician or plumber), total employer cost in 2025/26 is approximately £40,363 before overheads — £35,000 salary plus £4,500 employer NI and £863 minimum pension. For site managers at £50,000, total employer cost before overheads is approximately £58,072 per year. Many construction businesses also use CIS subcontractor arrangements for self-employed workers, which have a different cost and NI structure.",
        "bullets": [
            "General labourer: ~£24,000–£28,000. Employer NI: £2,850–£3,450.",
            "Experienced tradesperson (electrician, plumber, joiner): £32,000–£45,000.",
            "CSCS-qualified specialist: £35,000–£55,000.",
            "Site manager / project manager: £45,000–£70,000.",
            "Employer NI on £35,000: approximately £4,500/year (15% above £5,000).",
            "CIS subcontractors (self-employed): no employer NI or pension obligation.",
        ],
        "primary_cta": {"label": "Calculate construction worker employer cost", "url": "/calculator?salary=35000"},
        "secondary_cta": {"label": "Contractor vs employee cost", "url": "/contractor-vs-employee-cost"},
        "faq_items": [
            {"q": "What is the difference in cost between employing PAYE and CIS subcontractors in construction?", "a": "A PAYE employee at £35,000 costs an employer approximately £40,363/year in salary, NI and pension. A CIS self-employed subcontractor does not generate employer NI or pension costs — you simply pay the agreed rate. However, CIS workers must be genuinely self-employed (HMRC applies specific tests). Falsely categorising employees as self-employed carries significant penalties including back-payment of NI and interest."},
            {"q": "How much employer NI is due on a construction site manager salary?", "a": "A site manager earning £50,000 per year generates £6,750 in employer NI (15% of £45,000 above the £5,000 threshold) plus approximately £1,322 minimum pension on qualifying earnings. Total employer cost before overheads: approximately £58,072 per year. At £60,000 salary, total employer cost rises to approximately £70,072."},
            {"q": "Does the Construction Industry Scheme affect employer NI?", "a": "CIS affects income tax deductions from payments to subcontractors, not employer NI. CIS only applies to payments for construction work to self-employed workers or subcontractors operating through their own limited companies. Directly employed PAYE construction workers pay standard income tax and NI through payroll — CIS does not apply to them."},
        ],
    },
    "cost-of-employing-it-staff": {
        "title": "Cost of Employing IT Staff UK 2025/26 — Employer NI, Pension & True Total Cost",
        "description": "Employer cost for IT and tech staff in the UK in 2025/26. Developer, data engineer, QA and IT manager salary benchmarks with NI, pension and total employer cost calculations.",
        "h1": "Cost of employing IT staff UK (2025/26)",
        "badge": "Tech & IT sector",
        "example_salary": 55000,
        "salary_range": "£30,000–£100,000+",
        "intro": "IT and technology staff are among the highest-compensated employees in the UK labour market, with demand consistently outpacing supply in software development, data engineering, and cybersecurity roles. At a mid-market developer salary of £55,000, the total employer cost in 2025/26 is approximately £63,822 per year — employer NI of £7,500 (15% above £5,000) plus minimum pension of £1,322 on qualifying earnings. For senior engineers and architects at £75,000–£90,000, employer NI rises to £10,500–£12,750 per year. Many IT employers also compete on benefits, adding further to total employment cost above the statutory floor.",
        "bullets": [
            "Junior developer / IT analyst: £30,000–£40,000. Employer NI: £3,750–£5,250.",
            "Mid-level developer / engineer: £45,000–£65,000. Employer NI: £6,000–£9,000.",
            "Senior developer / tech lead: £65,000–£90,000. Employer NI: £9,000–£12,750.",
            "Data engineer / DevOps: £50,000–£80,000.",
            "IT manager / head of engineering: £70,000–£110,000.",
            "Employer pension capped at qualifying earnings of £50,270 — minimum cost £1,322/year above that.",
        ],
        "primary_cta": {"label": "Calculate IT staff employer cost", "url": "/calculator?salary=55000"},
        "secondary_cta": {"label": "Contractor vs employee comparison", "url": "/contractor-vs-employee-cost"},
        "faq_items": [
            {"q": "Is it cheaper to hire an IT contractor than a permanent developer?", "a": "On day-rate cost, a contractor often appears more expensive than the salary equivalent — but the employer avoids NI (15%), pension, holiday pay (28 days), sick pay and other employment obligations. At £55,000 PAYE salary, total employer cost is approximately £63,822/year (£277/day at 230 days). A contractor at £350/day would cost approximately £80,500/year — but with no ongoing employment commitments. For sustained full-time work, PAYE is typically more cost-effective."},
            {"q": "How much does IT employer NI cost at £70,000 salary?", "a": "Employer NI on £70,000 salary in 2025/26 is £9,750 per year (15% of £65,000 above the £5,000 threshold). Minimum pension on qualifying earnings (£50,270 cap) is £1,322/year. Total employer cost before overheads: approximately £81,072 per year. At £80,000 salary, total employer cost reaches approximately £92,072."},
            {"q": "Does IR35 affect IT employer costs?", "a": "Yes. If a developer working through a limited company is deemed inside IR35, the engaging organisation becomes responsible for operating PAYE and paying employer NI at 15% on the deemed employment income. For medium and large businesses, this assessment responsibility has rested with the engaging company since April 2021. A contractor earning £350/day inside IR35 for 230 days creates approximately £10,100 in employer NI — comparable to a £70,000+ permanent employee."},
        ],
    },
    "cost-of-employing-education-staff": {
        "title": "Cost of Employing Education Staff UK 2025/26 — NI, Pension & Total",
        "description": "Employer costs for education sector staff in the UK — teachers, TAs, support staff. 2025/26 NI, pension scheme contributions and total payroll cost.",
        "h1": "Cost of employing education staff UK (2025/26)",
        "badge": "Education sector",
        "example_salary": 35000,
        "salary_range": "£20,000–£65,000",
        "intro": "Education sector employers face higher-than-average pension costs because most staff in state schools belong to the Teachers' Pension Scheme (employer contribution ~28.6%) or the Local Government Pension Scheme (employer contribution typically 18–23%), not the auto-enrolment 3% minimum. A teacher on £40,000 generates an employer pension contribution of approximately £11,440 per year under TPS — compared with £1,013 under auto-enrolment. For support staff and TAs on LGPS, the pension cost is also significantly above the statutory minimum.",
        "bullets": [
            "Teachers (MPS): £31,650–£43,607. TPS employer pension ~28.6% adds £9,050–£12,472/yr.",
            "Teaching assistants (LGPS): £19,000–£28,000. LGPS employer contribution adds ~20% above salary.",
            "School business managers: £28,000–£45,000. LGPS or auto-enrolment depending on contract.",
            "Independent school staff may use auto-enrolment — lower pension cost but market salaries often higher.",
            "Employer NI on all roles: 15% above £5,000 threshold.",
        ],
        "primary_cta": {"label": "Calculate teacher employer cost", "url": "/calculator?salary=40000"},
        "secondary_cta": {"label": "Cost of hiring a teaching assistant", "url": "/cost-of-hiring-a-teaching-assistant"},
        "faq_items": [
            {"q": "How much does it cost to employ a teacher including pension?", "a": "A teacher on the Main Pay Scale midpoint of £40,000 costs approximately £51,440–£53,000 per year as an employer — salary plus employer NI of £5,250 plus TPS pension contribution of approximately £11,440 (28.6%). This is substantially higher than the auto-enrolment minimum of £1,013. Independent schools using auto-enrolment have lower pension costs but typically pay market salaries above the national pay scales."},
            {"q": "Do teaching assistants belong to a pension scheme?", "a": "Most teaching assistants employed by state schools or local authorities are eligible for the Local Government Pension Scheme (LGPS). Employer contribution rates are set locally but typically range from 18% to 23% of salary. For a TA on £22,000, this adds approximately £3,960–£5,060 per year in pension costs above the standard auto-enrolment minimum of approximately £478."},
        ],
    },
    "cost-of-employing-healthcare-workers": {
        "title": "Cost of Employing Healthcare Workers UK 2025/26 — NI, Pension & Total",
        "description": "Employer cost for healthcare and NHS workers in the UK. Band 2–8 salary benchmarks, employer NI, NHS Pension Scheme and total payroll cost for 2025/26.",
        "h1": "Cost of employing healthcare workers UK (2025/26)",
        "badge": "Healthcare sector",
        "example_salary": 38000,
        "salary_range": "£23,000–£65,000",
        "intro": "Healthcare employers face above-average pension costs through the NHS Pension Scheme, where employer contributions are approximately 23.7% of pensionable pay. For a Band 5 nurse at £35,000, employer pension adds approximately £8,295 per year — compared with £873 under auto-enrolment. Private healthcare employers using auto-enrolment have lower statutory pension costs but typically pay above NHS rates to compete for staff. At £38,000, the total NHS employer cost including NI (£4,950) and NHS pension (£9,006) is approximately £51,956 per year.",
        "bullets": [
            "Band 2 (HCA, porter): £23,615–£25,674. NHS pension adds ~£5,597–£6,085/yr.",
            "Band 3 (senior HCA, admin): £24,071–£25,674.",
            "Band 5 (RN, ODP, radiographer): £29,970–£36,483. NHS pension adds ~£7,103–£8,646.",
            "Band 6 (specialist): £37,338–£44,962. NHS pension adds ~£8,849–£10,656.",
            "Private sector: typically auto-enrolment (3%) with market premium on salary.",
        ],
        "primary_cta": {"label": "Calculate healthcare employer cost", "url": "/calculator?salary=35000"},
        "secondary_cta": {"label": "Cost of hiring a nurse", "url": "/cost-of-hiring-a-nurse"},
        "faq_items": [
            {"q": "What is the NHS Pension Scheme employer contribution rate?", "a": "From 2023/24, the NHS Pension Scheme employer contribution rate is 23.7% of pensionable pay. This compares to the auto-enrolment minimum of 3% on qualifying earnings. For a Band 5 nurse at £33,000, the employer NHS pension cost is approximately £7,821 per year — roughly 9× the auto-enrolment minimum. This is the single biggest above-salary cost for NHS employers and must be included in any accurate headcount budget."},
            {"q": "Do private healthcare employers pay NHS pension rates?", "a": "Only NHS employers and bodies with NHS contracts participate in the NHS Pension Scheme. Private healthcare employers use auto-enrolment at a minimum employer contribution of 3% on qualifying earnings (£6,240–£50,270). This reduces statutory pension cost significantly but private sector employers usually pay market salaries above NHS pay scales to attract clinical staff."},
        ],
    },
    "cost-of-employing-logistics-staff": {
        "title": "Cost of Employing Logistics Staff UK 2025/26 — NI, Pension & Total",
        "description": "Employer cost for logistics, warehouse and transport staff in the UK. Salary benchmarks, employer NI and total payroll cost for 2025/26.",
        "h1": "Cost of employing logistics staff UK (2025/26)",
        "badge": "Logistics & transport",
        "example_salary": 30000,
        "salary_range": "£22,000–£45,000",
        "intro": "The UK logistics sector employs over 2.5 million people, ranging from warehouse operatives on National Living Wage to HGV Class 1 drivers commanding premium rates following post-Brexit driver shortages. At a warehouse operative salary of £25,000, employer NI adds £3,000 and minimum pension adds £563, bringing total annual employer cost to approximately £28,563. Agency workers add further cost — agency margins of 15–30% are common. Shift premiums and weekend working allowances add 10–25% to base salary cost in 24/7 operations.",
        "bullets": [
            "Warehouse operative (NLW): ~£25,350/yr. Employer NI: ~£3,053. Total: ~£29,017.",
            "Forklift operator / FLT driver: £26,000–£32,000.",
            "HGV Class 2 driver: £28,000–£35,000. Employer NI: £3,450–£4,500.",
            "HGV Class 1 (artic): £32,000–£45,000. Shortage role — wage growth continues.",
            "Logistics manager / transport planner: £35,000–£55,000.",
            "Night shift / weekend premiums typically add 15–25% to base salary cost.",
        ],
        "primary_cta": {"label": "Calculate logistics employer cost", "url": "/calculator?salary=28000"},
        "secondary_cta": {"label": "Cost of hiring a delivery driver", "url": "/cost-of-hiring-a-delivery-driver"},
        "faq_items": [
            {"q": "How much does it cost to hire an HGV driver in the UK?", "a": "A Class 1 HGV driver earning £38,000 costs approximately £43,800 per year as an employer — salary plus employer NI of £4,950 plus minimum pension of £963. Night driving allowances, tachograph compliance time, and agency margin (if used) can push total effective cost significantly higher. The driver shortage has kept rates elevated: many experienced Class 1 drivers now command £40,000–£45,000+ in competitive markets."},
            {"q": "Is using an agency worker cheaper than a direct hire for logistics roles?", "a": "Agency workers avoid employer NI and pension obligations on the payroll, but agency margins of 15–30% typically make them more expensive per hour than equivalent PAYE employees. For short-term or seasonal cover, agencies offer flexibility worth the premium. For consistent full-time roles, direct PAYE employment is usually more cost-effective once the recruitment cost is amortised over 12+ months."},
        ],
    },
}


# NLW 2025/26
_NLW = 12.71
_HOURS_PER_YEAR = lambda h: round(h * 52)

HOURS_SCENARIO_PAGES: Dict[str, Dict] = {
    "cost-of-employing-someone-16-hours-a-week": {
        "hours": 16,
        "annual_salary_nlw": round(_NLW * _HOURS_PER_YEAR(16)),
        "title": "Cost of Employing Someone 16 Hours a Week UK (2025/26)",
        "description": "What does it cost to employ someone 16 hours a week in the UK? Employer NI, pension and total cost at common part-time wages. 2025/26 rates.",
        "h1": "Cost of employing someone 16 hours a week (2025/26)",
        "badge": "Part-time · 16 hrs/wk",
        "intro": "Employing someone for 16 hours a week in the UK generates employer NI, pension obligations and total payroll costs that are not simply half the full-time figure. The employer NI secondary threshold (£5,000/year) is not pro-rated for part-time workers — it applies in full regardless of hours. At 16 hours per week on the 2025/26 National Living Wage (£12.71/hour), annual salary is approximately £10,158, and employer NI applies on £5,158 of earnings above the threshold at 15% — adding approximately £774 per year. Use the calculator below to model any salary or hourly rate.",
        "key_rate": "£12.71/hr",
    },
    "cost-of-employing-someone-20-hours-a-week": {
        "hours": 20,
        "annual_salary_nlw": round(_NLW * _HOURS_PER_YEAR(20)),
        "title": "Cost of Employing Someone 20 Hours a Week UK (2025/26)",
        "description": "Employer cost for a 20-hour part-time employee in the UK. NI, pension and true total cost at NLW and common pay rates. 2025/26 figures.",
        "h1": "Cost of employing someone 20 hours a week (2025/26)",
        "badge": "Part-time · 20 hrs/wk",
        "intro": "A 20-hour-per-week employee working at the National Living Wage (£12.71/hour) earns approximately £12,698 per year. The employer NI secondary threshold of £5,000 is not reduced for part-time hours, so employer NI applies on £7,698 at 15% — adding approximately £1,155 per year. Minimum pension adds a further £194 on qualifying earnings above £6,240. Total statutory employer cost above salary: approximately £1,349 per year. Use the calculator for any salary.",
        "key_rate": "£12.71/hr",
    },
    "cost-of-employing-someone-24-hours-a-week": {
        "hours": 24,
        "annual_salary_nlw": round(_NLW * _HOURS_PER_YEAR(24)),
        "title": "Cost of Employing Someone 24 Hours a Week UK (2025/26)",
        "description": "True employer cost for a 24-hour part-time worker in the UK — NI, pension and on-costs for 2025/26.",
        "h1": "Cost of employing someone 24 hours a week (2025/26)",
        "badge": "Part-time · 24 hrs/wk",
        "intro": "At 24 hours per week on the National Living Wage (£12.71/hour), annual salary is approximately £15,237. Employer NI on earnings above the £5,000 secondary threshold is approximately £1,536 per year. Minimum auto-enrolment pension on qualifying earnings (above £6,240) adds approximately £269 per year. Total statutory employer cost above salary: approximately £1,805 per year before overheads.",
        "key_rate": "£12.71/hr",
    },
    "cost-of-employing-someone-25-hours-a-week": {
        "hours": 25,
        "annual_salary_nlw": round(_NLW * _HOURS_PER_YEAR(25)),
        "title": "Cost of Employing Someone 25 Hours a Week UK (2025/26)",
        "description": "Employer cost for a 25-hour part-time worker — NI, pension, total cost. UK 2025/26.",
        "h1": "Cost of employing someone 25 hours a week (2025/26)",
        "badge": "Part-time · 25 hrs/wk",
        "intro": "At 25 hours per week on the National Living Wage, annual salary is approximately £15,873. Employer NI applies on £10,873 above the £5,000 secondary threshold at 15%, adding approximately £1,631 per year. The NI threshold is annual and applies in full regardless of contracted hours. Minimum pension adds approximately £288 per year on qualifying earnings.",
        "key_rate": "£12.71/hr",
    },
    "cost-of-employing-someone-30-hours-a-week": {
        "hours": 30,
        "annual_salary_nlw": round(_NLW * _HOURS_PER_YEAR(30)),
        "title": "Cost of Employing Someone 30 Hours a Week UK (2025/26)",
        "description": "Employer cost for someone working 30 hours a week — NI, pension and total. UK 2025/26.",
        "h1": "Cost of employing someone 30 hours a week (2025/26)",
        "badge": "Part-time · 30 hrs/wk",
        "intro": "At 30 hours per week on the National Living Wage (£12.71/hour), annual salary is approximately £19,046. Employer NI on £14,046 above the secondary threshold amounts to approximately £2,107 per year. Minimum pension on qualifying earnings adds approximately £382 per year. Total statutory employer cost: approximately £21,535 per year at NLW — roughly 13% above the headline salary.",
        "key_rate": "£12.71/hr",
    },
    "cost-of-employing-someone-37-5-hours-a-week": {
        "hours": 37.5,
        "annual_salary_nlw": round(_NLW * round(37.5 * 52)),
        "title": "Cost of Employing Someone 37.5 Hours a Week UK (2025/26)",
        "description": "True employer cost for a standard 37.5-hour full-time employee. NI, pension, total cost. UK 2025/26.",
        "h1": "Cost of employing someone 37.5 hours a week (2025/26)",
        "badge": "Full-time · 37.5 hrs/wk",
        "intro": "A standard full-time employee working 37.5 hours per week earns approximately £24,785 per year at the National Living Wage. Employer NI on £18,810 above the £5,000 secondary threshold adds approximately £2,968 per year. Auto-enrolment pension at the 3% minimum adds approximately £556 per year on qualifying earnings. Total statutory employer cost: approximately £28,309 per year at NLW — around 14% above gross salary.",
        "key_rate": "£12.71/hr",
    },
    "cost-of-employing-someone-40-hours-a-week": {
        "hours": 40,
        "annual_salary_nlw": round(_NLW * _HOURS_PER_YEAR(40)),
        "title": "Cost of Employing Someone 40 Hours a Week UK (2025/26)",
        "description": "Employer cost for a 40-hour full-time worker in the UK — NI, pension and total on-costs. 2025/26.",
        "h1": "Cost of employing someone 40 hours a week (2025/26)",
        "badge": "Full-time · 40 hrs/wk",
        "intro": "At 40 hours per week on the National Living Wage (£12.71/hour), annual salary is approximately £25,397. Employer NI on £20,397 above the secondary threshold adds approximately £3,060 per year. Minimum pension on qualifying earnings adds approximately £576 per year. Total statutory employer cost: approximately £29,033 per year — around 14.3% above the headline wage.",
        "key_rate": "£12.71/hr",
    },
}

HOURLY_RATE_PAGES: Dict[str, Dict] = {
    "employer-cost-at-10-pounds-per-hour": {
        "hourly_rate": 10.00,
        "annual_salary_ft": 19500,  # 10 × 37.5 × 52
        "title": "Employer Cost at £10 Per Hour UK (2025/26) — NI, Pension & Total",
        "description": "True employer cost for a £10/hour employee in the UK. Annual salary, employer NI, pension and total payroll cost. 2025/26 rates.",
        "h1": "Employer cost at £10 per hour (2025/26)",
        "badge": "£10/hr",
    },
    "employer-cost-at-11-pounds-per-hour": {
        "hourly_rate": 11.00,
        "annual_salary_ft": 21450,  # 11 × 37.5 × 52
        "title": "Employer Cost at £11 Per Hour UK (2025/26) — NI, Pension & Total",
        "description": "Employer cost for a £11/hour worker — NI, pension, total payroll cost. UK 2025/26.",
        "h1": "Employer cost at £11 per hour (2025/26)",
        "badge": "£11/hr",
    },
    "employer-cost-at-minimum-wage-per-hour": {
        "hourly_rate": 12.71,
        "annual_salary_ft": 24785,  # NLW × 37.5 × 52
        "title": "Employer Cost at National Living Wage Per Hour (£12.71) UK 2026/27",
        "description": "What does it cost to employ someone at the National Living Wage? £12.71/hr = £24,785/yr + employer NI + pension. Full 2026/27 breakdown.",
        "h1": "Employer cost at National Living Wage — £12.71/hour (2025/26)",
        "badge": "NLW · £12.71/hr",
    },
    "employer-cost-at-13-pounds-per-hour": {
        "hourly_rate": 13.00,
        "annual_salary_ft": 25350,  # 13 × 37.5 × 52
        "title": "Employer Cost at £13 Per Hour UK (2025/26) — NI, Pension & Total",
        "description": "Employer cost for a £13/hour employee in the UK. Annual cost, NI, pension, total payroll burden. 2025/26 figures.",
        "h1": "Employer cost at £13 per hour (2025/26)",
        "badge": "£13/hr",
    },
    "employer-cost-at-14-pounds-per-hour": {
        "hourly_rate": 14.00,
        "annual_salary_ft": 27300,  # 14 × 37.5 × 52
        "title": "Employer Cost at £14 Per Hour UK (2025/26) — NI, Pension & Total",
        "description": "True employer cost for a £14/hour worker in the UK — NI, pension and total on-costs. 2025/26.",
        "h1": "Employer cost at £14 per hour (2025/26)",
        "badge": "£14/hr",
    },
    "employer-cost-at-15-pounds-per-hour": {
        "hourly_rate": 15.00,
        "annual_salary_ft": 29250,  # 15 × 37.5 × 52
        "title": "Employer Cost at £15 Per Hour UK (2025/26) — NI, Pension & Total",
        "description": "What does a £15/hour employee cost an employer in the UK? Salary, NI, pension and total annual cost for 2025/26.",
        "h1": "Employer cost at £15 per hour (2025/26)",
        "badge": "£15/hr",
    },
    "employer-cost-at-20-pounds-per-hour": {
        "hourly_rate": 20.00,
        "annual_salary_ft": 39000,  # 20 × 37.5 × 52
        "title": "Employer Cost at £20 Per Hour UK (2025/26) — NI, Pension & Total",
        "description": "Employer cost for a £20/hour employee — full-time salary, NI, pension and total payroll cost. UK 2025/26.",
        "h1": "Employer cost at £20 per hour (2025/26)",
        "badge": "£20/hr",
    },
    "employer-cost-at-25-pounds-per-hour": {
        "hourly_rate": 25.00,
        "annual_salary_ft": 48750,  # 25 × 37.5 × 52
        "title": "Employer Cost at £25 Per Hour UK (2025/26) — NI, Pension & Total",
        "description": "True employer cost for a £25/hour employee — annual salary, NI, pension and total cost. 2025/26 UK.",
        "h1": "Employer cost at £25 per hour (2025/26)",
        "badge": "£25/hr",
    },
    "employer-cost-at-30-pounds-per-hour": {
        "hourly_rate": 30.00,
        "annual_salary_ft": 58500,  # 30 × 37.5 × 52
        "title": "Employer Cost at £30 Per Hour UK (2025/26) — NI, Pension & Total",
        "description": "Employer cost at £30 per hour — salary, NI, pension and total annual payroll cost for UK employers. 2025/26.",
        "h1": "Employer cost at £30 per hour (2025/26)",
        "badge": "£30/hr",
    },
}

ROLE_PAGES: Dict[str, Dict] = {
    "cost-of-hiring-a-software-developer": {
        "title": "Cost of Hiring a Software Developer UK (2025/26) — Salary, NI & Total",
        "description": "What does it cost to hire a software developer in the UK? Salary benchmarks, employer NI and total payroll cost for junior, mid and senior developers. 2025/26.",
        "h1": "Cost of hiring a software developer UK (2025/26)",
        "badge": "Software developer",
        "salary_range": "£35,000–£90,000",
        "example_salary": 55000,
        "intro": "Hiring a software developer in the UK is one of the most significant payroll commitments a business can make. Salaries range from around £35,000 for junior roles in most UK cities to £80,000–£90,000+ for senior engineers in London or specialist areas. At a mid-level salary of £55,000, the total employer cost before overheads is approximately £64,638 per year — salary plus £7,500 employer NI plus £1,313 pension on qualifying earnings.",
        "role_levels": [
            {"level": "Junior developer", "salary_range": "£30,000–£42,000", "example": 36000},
            {"level": "Mid-level developer", "salary_range": "£42,000–£65,000", "example": 55000},
            {"level": "Senior developer", "salary_range": "£65,000–£90,000", "example": 75000},
        ],
    },
    "cost-of-hiring-an-admin-assistant": {
        "title": "Cost of Hiring an Admin Assistant UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost for hiring an admin assistant in the UK. Salary benchmarks, NI, pension and total annual payroll cost. 2025/26.",
        "h1": "Cost of hiring an admin assistant UK (2025/26)",
        "badge": "Admin assistant",
        "salary_range": "£21,000–£32,000",
        "example_salary": 26000,
        "intro": "Admin assistants typically earn between £21,000 and £32,000 per year in the UK, depending on experience, location and sector. At a salary of £26,000, the total employer cost including employer NI (£3,150) and minimum pension (£588) is approximately £29,738 per year before overheads. London salaries sit towards the upper end of this range; regional UK salaries are typically £21,000–£26,000.",
        "role_levels": [
            {"level": "Entry-level admin", "salary_range": "£21,000–£24,000", "example": 22000},
            {"level": "Experienced admin assistant", "salary_range": "£24,000–£30,000", "example": 26000},
            {"level": "Senior admin / PA", "salary_range": "£28,000–£38,000", "example": 32000},
        ],
    },
    "cost-of-hiring-a-care-worker": {
        "title": "Cost of Hiring a Care Worker UK (2025/26) — Salary, NI & Total",
        "description": "True employer cost for a care worker in the UK — salary from NLW upwards, NI and pension included. 2025/26.",
        "h1": "Cost of hiring a care worker UK (2025/26)",
        "badge": "Care worker",
        "salary_range": "£22,000–£28,000",
        "example_salary": 24000,
        "intro": "Care workers in the UK are typically paid between the National Living Wage (£12.71/hour) and around £14–£15 per hour depending on the employer and role. At a salary of £24,000, employer NI adds approximately £2,850 per year and minimum pension adds approximately £531. Total employer cost: approximately £27,381 per year before overheads. For domiciliary care, many workers are part-time, further complicating the cost picture.",
        "role_levels": [
            {"level": "Care assistant (NLW)", "salary_range": "£22,000–£24,000", "example": 24785},
            {"level": "Senior care worker", "salary_range": "£24,000–£28,000", "example": 26000},
            {"level": "Care coordinator", "salary_range": "£26,000–£32,000", "example": 28000},
        ],
    },
    "cost-of-hiring-a-warehouse-operative": {
        "title": "Cost of Hiring a Warehouse Operative UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost for a warehouse operative in the UK — NLW salary, employer NI, pension and total. 2025/26.",
        "h1": "Cost of hiring a warehouse operative UK (2025/26)",
        "badge": "Warehouse operative",
        "salary_range": "£22,000–£32,000",
        "example_salary": 26000,
        "intro": "Warehouse operatives in the UK typically earn between the National Living Wage (approximately £24,785/year full-time) and £14–£15/hour for roles requiring forklift licences or specialist skills. At £26,000 annual salary, the total employer cost including NI (£3,150) and pension (£588) is approximately £29,738 per year. Shift premiums and overtime can add significantly to payroll costs.",
        "role_levels": [
            {"level": "General warehouse operative", "salary_range": "£22,000–£26,000", "example": 24000},
            {"level": "Forklift / specialist operative", "salary_range": "£26,000–£32,000", "example": 28000},
            {"level": "Team leader / supervisor", "salary_range": "£28,000–£36,000", "example": 32000},
        ],
    },
    "cost-of-hiring-a-receptionist": {
        "title": "Cost of Hiring a Receptionist UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost for a receptionist in the UK — salary benchmarks, NI, pension and total. 2025/26.",
        "h1": "Cost of hiring a receptionist UK (2025/26)",
        "badge": "Receptionist",
        "salary_range": "£21,000–£30,000",
        "example_salary": 24000,
        "intro": "Receptionists and front-of-house staff in the UK typically earn between £21,000 and £27,000, with London roles at the higher end. At a salary of £24,000, total employer cost including NI (£2,850) and pension (£531) is approximately £27,381 per year. Many receptionist roles are part-time, which changes the NI calculation — the £5,000 threshold applies in full regardless of hours worked.",
        "role_levels": [
            {"level": "Junior receptionist", "salary_range": "£21,000–£24,000", "example": 22000},
            {"level": "Experienced receptionist", "salary_range": "£24,000–£28,000", "example": 25000},
            {"level": "Medical / legal receptionist", "salary_range": "£25,000–£32,000", "example": 27000},
        ],
    },
    "cost-of-hiring-a-sales-executive": {
        "title": "Cost of Hiring a Sales Executive UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost for a UK sales executive — base salary, commission, employer NI and total payroll cost. 2025/26.",
        "h1": "Cost of hiring a sales executive UK (2025/26)",
        "badge": "Sales executive",
        "salary_range": "£25,000–£45,000 base",
        "example_salary": 32000,
        "intro": "Sales executives in the UK typically have a base salary of £25,000–£35,000 plus commission. Employer payroll costs are calculated on the base salary plus any commission payments — employer NI and pension apply to the full taxable pay. At a £32,000 base salary, employer NI adds approximately £4,050 and minimum pension adds approximately £775. If the employee earns £10,000 in commission, the additional NI cost to the employer is £1,500.",
        "role_levels": [
            {"level": "Junior / telesales", "salary_range": "£22,000–£28,000 base", "example": 25000},
            {"level": "Sales executive (B2B)", "salary_range": "£28,000–£38,000 base", "example": 32000},
            {"level": "Senior sales / account manager", "salary_range": "£35,000–£50,000 base", "example": 42000},
        ],
    },
    "cost-of-hiring-a-marketing-executive": {
        "title": "Cost of Hiring a Marketing Executive UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost for a UK marketing executive — salary benchmarks, NI, pension and total on-costs. 2025/26.",
        "h1": "Cost of hiring a marketing executive UK (2025/26)",
        "badge": "Marketing executive",
        "salary_range": "£25,000–£45,000",
        "example_salary": 32000,
        "intro": "Marketing executives in the UK typically earn between £25,000 and £38,000, rising to £40,000–£50,000 for digital specialists or those in larger businesses. At a salary of £32,000, the total employer cost including NI (£4,050) and pension (£775) is approximately £36,825 per year before overheads. Marketing roles in London or for fast-growing tech businesses frequently sit at the higher end.",
        "role_levels": [
            {"level": "Marketing assistant", "salary_range": "£23,000–£28,000", "example": 25000},
            {"level": "Marketing executive", "salary_range": "£28,000–£38,000", "example": 32000},
            {"level": "Senior / digital marketing", "salary_range": "£35,000–£50,000", "example": 42000},
        ],
    },
    "cost-of-hiring-a-cleaner": {
        "title": "Cost of Hiring a Cleaner UK (2025/26) — Employer NI, Pension & Total",
        "description": "Employer cost for a UK cleaner — NLW or above, NI, pension and total on-costs for full-time and part-time. 2025/26.",
        "h1": "Cost of hiring a cleaner UK (2025/26)",
        "badge": "Cleaner",
        "salary_range": "NLW–£14/hr",
        "example_salary": 24785,
        "intro": "Cleaners in the UK are typically paid at or slightly above the National Living Wage (£12.71/hour from April 2025). Many cleaning roles are part-time. A full-time cleaner on NLW earns approximately £24,785 per year. Employer NI adds approximately £2,968 per year and minimum pension adds approximately £524. Many employers hire cleaners for fewer than 16 hours per week, in which case earnings may fall below the auto-enrolment threshold.",
        "role_levels": [
            {"level": "Part-time cleaner (16 hrs/wk)", "salary_range": "NLW · approx £10,158/yr", "example": 10158},
            {"level": "Part-time cleaner (20 hrs/wk)", "salary_range": "NLW · approx £12,698/yr", "example": 12698},
            {"level": "Full-time cleaner (37.5 hrs/wk)", "salary_range": "NLW · approx £24,785/yr", "example": 24785},
        ],
    },
    "cost-of-hiring-hospitality-staff": {
        "title": "Cost of Hiring Hospitality Staff UK (2025/26) — NI, Pension & Total",
        "description": "Employer cost for UK hospitality staff — kitchen, front of house and bar staff. NLW upwards, NI, pension and total. 2025/26.",
        "h1": "Cost of hiring hospitality staff UK (2025/26)",
        "badge": "Hospitality",
        "salary_range": "NLW–£13/hr",
        "example_salary": 24785,
        "intro": "Hospitality employers in the UK — restaurants, bars, hotels and catering businesses — predominantly employ staff at or near the National Living Wage. Many roles are part-time or casual. A full-time front-of-house worker on NLW earns approximately £24,785 per year. For kitchens, junior chefs typically start between £24,000 and £28,000. Employer NI on a £26,000 salary adds approximately £3,150 per year — a significant overhead for hospitality margins.",
        "role_levels": [
            {"level": "Front of house / bar staff", "salary_range": "NLW · £23,000–£25,000", "example": 24000},
            {"level": "Kitchen porter / prep cook", "salary_range": "NLW–£13/hr · £22,000–£25,000", "example": 24785},
            {"level": "Sous chef / senior chef", "salary_range": "£28,000–£38,000", "example": 32000},
        ],
    },
    "cost-of-hiring-a-teaching-assistant": {
        "title": "Cost of Hiring a Teaching Assistant UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost for a teaching assistant in the UK — term-time salary, NI, pension and true total cost. 2025/26.",
        "h1": "Cost of hiring a teaching assistant UK (2025/26)",
        "badge": "Teaching assistant",
        "salary_range": "£19,000–£26,000",
        "example_salary": 22000,
        "intro": "Teaching assistants in UK state schools are often employed on term-time-only contracts at spinal column points in the range of approximately £19,000–£26,000 pro rata (full-time equivalent). The actual cost depends on whether the role is full-time, term-time only, or part-time. For a full-year equivalent salary of £22,000, employer NI adds approximately £2,550 per year. State school employees typically contribute to the Local Government Pension Scheme — employer contribution rates are set at around 20–23%, not the auto-enrolment minimum.",
        "role_levels": [
            {"level": "Level 1 TA", "salary_range": "£19,000–£22,000 FTE", "example": 20000},
            {"level": "Level 2/3 TA", "salary_range": "£22,000–£26,000 FTE", "example": 23000},
            {"level": "HLTA / senior TA", "salary_range": "£25,000–£30,000 FTE", "example": 26000},
        ],
    },
    "cost-of-hiring-a-nurse": {
        "title": "Cost of Hiring a Nurse UK (2025/26) — NHS & Private Salary, NI & Total",
        "description": "What does it cost to hire a nurse in the UK? NHS Band 5–7 salary benchmarks, employer NI at 15%, pension and total employer cost for 2025/26.",
        "h1": "Cost of hiring a nurse UK (2025/26)",
        "badge": "Nurse",
        "salary_range": "£28,000–£52,000",
        "example_salary": 37000,
        "intro": "Nursing salaries in the UK are structured by NHS Agenda for Change pay bands. Band 5 (newly qualified RN) starts at approximately £29,970, rising to around £36,483 with experience. Band 6 (specialist/team leader) ranges from £37,338 to £44,962. Private sector nursing salaries often sit 5–15% above NHS rates. At a Band 5 mid-point of £37,000, total employer cost including 15% NI (£4,800) and 3% minimum pension (£923) is approximately £42,723 per year — though NHS employers pay substantially higher pension contributions under the NHS Pension Scheme.",
        "role_levels": [
            {"level": "Band 5 (newly qualified RN)", "salary_range": "£29,970–£36,483", "example": 33000},
            {"level": "Band 6 (specialist nurse)", "salary_range": "£37,338–£44,962", "example": 41000},
            {"level": "Band 7 (advanced/ward manager)", "salary_range": "£46,148–£52,809", "example": 49000},
        ],
    },
    "cost-of-hiring-a-teacher": {
        "title": "Cost of Hiring a Teacher UK (2025/26) — Salary, NI, Pension & Total",
        "description": "Employer cost of hiring a teacher in England and Wales. MPS/UPS salary scales, employer NI at 15%, Teachers' Pension Scheme contributions and total school payroll cost. 2025/26.",
        "h1": "Cost of hiring a teacher UK (2025/26)",
        "badge": "Teacher",
        "salary_range": "£31,000–£65,000",
        "example_salary": 42000,
        "intro": "Teacher salaries in England are set by the School Teachers' Pay and Conditions Document. The Main Pay Scale (MPS) runs from £31,650 to £43,607 outside London. The Upper Pay Scale (UPS) adds a further tier up to £49,084. Leadership pay extends significantly higher. Critically for budget planning: state school teachers belong to the Teachers' Pension Scheme, where employer contributions are approximately 28.6% of salary — far above the auto-enrolment 3% minimum. At a £42,000 MPS salary, the pension contribution alone adds approximately £12,012 per year to the employer cost.",
        "role_levels": [
            {"level": "MPS 1–3 (NQT/early career)", "salary_range": "£31,650–£38,000", "example": 34000},
            {"level": "MPS 4–6 (experienced)", "salary_range": "£38,000–£43,607", "example": 42000},
            {"level": "UPS (upper pay scale)", "salary_range": "£45,000–£49,084", "example": 47000},
        ],
    },
    "cost-of-hiring-a-project-manager": {
        "title": "Cost of Hiring a Project Manager UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost of hiring a project manager in the UK. Salary benchmarks by sector and seniority, employer NI, pension and total annual payroll cost. 2025/26.",
        "h1": "Cost of hiring a project manager UK (2025/26)",
        "badge": "Project manager",
        "salary_range": "£35,000–£75,000",
        "example_salary": 52000,
        "intro": "Project manager salaries in the UK vary significantly by sector, seniority and location. Junior PMs in non-technical roles typically earn £35,000–£42,000. Mid-level PMs with 3–7 years' experience earn £42,000–£60,000. Senior or programme managers in IT, construction or financial services can reach £65,000–£85,000+. At a mid-level salary of £52,000, total employer cost including NI (£7,050) and pension (£1,313) is approximately £60,363 per year before overheads.",
        "role_levels": [
            {"level": "Junior PM / coordinator", "salary_range": "£32,000–£42,000", "example": 38000},
            {"level": "Project manager", "salary_range": "£42,000–£60,000", "example": 52000},
            {"level": "Senior PM / programme manager", "salary_range": "£60,000–£80,000", "example": 70000},
        ],
    },
    "cost-of-hiring-a-delivery-driver": {
        "title": "Cost of Hiring a Delivery Driver UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost of hiring a delivery or HGV driver in the UK. Hourly rates, salary equivalents, employer NI and total payroll cost for 2025/26.",
        "h1": "Cost of hiring a delivery driver UK (2025/26)",
        "badge": "Delivery driver",
        "salary_range": "£22,000–£40,000",
        "example_salary": 30000,
        "intro": "Delivery driver salaries depend on vehicle type, shift pattern, and operator. Van drivers typically earn £22,000–£28,000 per year or £11–£14/hr. HGV Class 2 drivers earn approximately £28,000–£35,000. Class 1 (articulated) HGV drivers have seen strong wage growth and now command £32,000–£45,000 with experienced drivers earning more. At £30,000, employer NI adds £3,750 and minimum pension adds £713, bringing total annual employer cost to approximately £34,463.",
        "role_levels": [
            {"level": "Van / courier driver", "salary_range": "£22,000–£28,000", "example": 25000},
            {"level": "HGV Class 2 driver", "salary_range": "£27,000–£35,000", "example": 31000},
            {"level": "HGV Class 1 / artic driver", "salary_range": "£32,000–£45,000", "example": 38000},
        ],
    },
    "cost-of-hiring-a-chef": {
        "title": "Cost of Hiring a Chef UK (2025/26) — Salary, NI & Total Employer Cost",
        "description": "Employer cost of hiring a chef in the UK. Commis to head chef salary benchmarks, employer NI, pension and total payroll cost for 2025/26.",
        "h1": "Cost of hiring a chef UK (2025/26)",
        "badge": "Chef",
        "salary_range": "£22,000–£50,000",
        "example_salary": 32000,
        "intro": "Chef salaries vary widely by level, cuisine type and establishment. Commis chefs typically start at £22,000–£26,000. Chef de partie roles earn £26,000–£32,000. Sous chefs range from £30,000–£40,000. Head chefs at independent restaurants typically earn £35,000–£50,000, with executive chefs at larger groups earning significantly more. At a sous chef salary of £32,000, employer NI adds £4,050 and minimum pension adds £773, bringing total employer cost to approximately £36,823 per year.",
        "role_levels": [
            {"level": "Commis / chef de partie", "salary_range": "£22,000–£30,000", "example": 26000},
            {"level": "Sous chef", "salary_range": "£28,000–£40,000", "example": 34000},
            {"level": "Head chef / executive chef", "salary_range": "£38,000–£55,000", "example": 45000},
        ],
    },
    "cost-of-hiring-an-accountant": {
        "title": "Cost of Hiring an Accountant UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost of hiring an accountant in the UK. Salary benchmarks by qualification and seniority, employer NI, pension and total cost. 2025/26.",
        "h1": "Cost of hiring an accountant UK (2025/26)",
        "badge": "Accountant",
        "salary_range": "£28,000–£70,000",
        "example_salary": 45000,
        "intro": "Accountant salaries in the UK depend heavily on qualification (AAT, ACCA, CIMA, ACA) and whether the role is in industry or practice. Newly qualified ACCA/CIMA accountants typically earn £35,000–£45,000. Part-qualified roles in industry: £28,000–£38,000. Finance managers with post-qualification experience: £45,000–£65,000. At £45,000, employer NI adds £6,000 and pension adds £1,163, bringing total employer cost to approximately £52,163 per year before overheads.",
        "role_levels": [
            {"level": "Part-qualified / accounts assistant", "salary_range": "£24,000–£35,000", "example": 30000},
            {"level": "Newly qualified (ACCA/CIMA/ACA)", "salary_range": "£35,000–£48,000", "example": 42000},
            {"level": "Finance manager / senior accountant", "salary_range": "£48,000–£70,000", "example": 58000},
        ],
    },
    "cost-of-hiring-an-hr-manager": {
        "title": "Cost of Hiring an HR Manager UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost of hiring an HR manager or HR Business Partner in the UK. Salary benchmarks, employer NI, pension and total cost for 2025/26.",
        "h1": "Cost of hiring an HR manager UK (2025/26)",
        "badge": "HR manager",
        "salary_range": "£32,000–£65,000",
        "example_salary": 45000,
        "intro": "HR manager salaries vary by company size, sector and whether the role is generalist or specialist. HR advisors and junior managers typically earn £32,000–£42,000. HR managers at small-to-mid businesses earn £42,000–£55,000. HR Business Partners or heads of people at growing companies: £55,000–£75,000. At £45,000, total employer cost including NI (£6,000) and pension (£1,163) is approximately £52,163 per year. HR roles in London sit 15–25% above these figures.",
        "role_levels": [
            {"level": "HR advisor / junior HR manager", "salary_range": "£30,000–£42,000", "example": 36000},
            {"level": "HR manager", "salary_range": "£40,000–£55,000", "example": 47000},
            {"level": "HR Business Partner / Head of People", "salary_range": "£52,000–£75,000", "example": 62000},
        ],
    },
    "cost-of-hiring-a-customer-service-advisor": {
        "title": "Cost of Hiring a Customer Service Advisor UK (2025/26) — Salary, NI & Total",
        "description": "Employer cost of hiring a customer service advisor or agent in the UK. Salary benchmarks, employer NI, pension and total annual cost for 2025/26.",
        "h1": "Cost of hiring a customer service advisor UK (2025/26)",
        "badge": "Customer service advisor",
        "salary_range": "£21,000–£32,000",
        "example_salary": 26000,
        "intro": "Customer service advisor salaries typically range from £21,000 to £30,000 depending on sector, shift requirements and whether the role involves technical or specialist support. Contact centre roles often sit at £22,000–£26,000. Specialist support or team leader positions reach £26,000–£35,000. At £26,000, employer NI adds £3,150 and minimum pension adds £588, giving a total employer cost of approximately £29,738 per year. Shift allowances and weekend premiums can add 5–15% to the base cost.",
        "role_levels": [
            {"level": "Customer service agent / advisor", "salary_range": "£21,000–£26,000", "example": 24000},
            {"level": "Senior advisor / specialist support", "salary_range": "£26,000–£32,000", "example": 29000},
            {"level": "Team leader / CS manager", "salary_range": "£30,000–£42,000", "example": 35000},
        ],
    },
}


def gbp(value: float) -> str:
    return f"£{value:,.0f}"


def pct(value: float) -> str:
    return f"{value:.1f}%"


def request_path() -> str:
    return request.path if request.path.startswith("/") else "/"


def _apply_year(text: str) -> str:
    """Replace any hardcoded tax-year label in a string with the active year."""
    yr = active_tax_year()
    return text.replace("2025/26", yr).replace("2026/27", yr)


def _apply_year_deep(value):
    """Recursively replace current-year labels in nested page content."""
    if isinstance(value, str):
        return _apply_year(value)
    if isinstance(value, list):
        return [_apply_year_deep(item) for item in value]
    if isinstance(value, dict):
        return {key: _apply_year_deep(item) for key, item in value.items()}
    return value


def with_meta(context: Dict, title: str, description: str, breadcrumbs: List[Dict]) -> Dict:
    canonical = f"{SITE_URL}{request_path()}"
    context = _apply_year_deep(context)
    breadcrumbs = _apply_year_deep(breadcrumbs)
    context.update(
        {
            "title": _apply_year(title),
            "meta_description": _apply_year(description),
            "canonical_url": canonical,
            "site_url": SITE_URL,
            "canonical_host": CANONICAL_HOST,
            "ga_measurement_id": GA_MEASUREMENT_ID,
            "adsense_client": ADSENSE_CLIENT,
            "breadcrumbs": breadcrumbs,
            "tax_year": active_tax_year(),
            "now": datetime.utcnow(),
            "salary_amounts": SALARY_AMOUNTS,
            "guides": GUIDES,
            "tool_cards": TOOL_CARDS,
            "min_employer_pension": MIN_EMPLOYER_PENSION_RATE,
            "min_total_pension": MIN_TOTAL_PENSION_RATE,
        }
    )
    return context


def default_faq() -> List[Dict[str, str]]:
    return [
        {
            "q": "How much does it cost to employ someone in the UK?",
            "a": "The true cost to employ someone in the UK is typically 15–20% above gross salary. At £30,000: employer NI £3,750 + pension £713 = approximately £34,463 per year. At £50,000: employer NI £6,750 + pension £1,313 = approximately £58,063 per year. Adding workplace overheads of £2,000–£5,000 can bring the total to 20–25% above the headline salary.",
        },
        {
            "q": "What is the employer NI rate for 2025/26?",
            "a": "For 2025/26, employer Class 1 National Insurance is charged at 15% on employee earnings above the secondary threshold of £5,000 per year (£96 per week, £416 per month). This rate increased from 13.8% in April 2025, when the threshold was simultaneously cut from £9,100 to £5,000. Both changes apply from 6 April 2025.",
        },
        {
            "q": "How much employer NI do I pay on a £35,000 salary?",
            "a": "At £35,000 salary, employer NI for 2025/26 is £4,500 per year — 15% on £30,000 of earnings above the £5,000 threshold. That is £375 per month. In 2024/25, the same salary produced £3,585 in employer NI. The April 2025 changes therefore add £915 per year on this salary alone.",
        },
        {
            "q": "What is Employment Allowance and who can claim it?",
            "a": "Employment Allowance lets eligible employers reduce their annual employer NI bill by up to £10,500 in 2025/26, increased from £5,000 in 2024/25. The previous £100,000 NI bill eligibility cap has been removed, so more businesses qualify. Companies where the only paid employee is also a director cannot claim. Apply through payroll software via the Employer Payment Summary indicator.",
        },
        {
            "q": "What is the total employer cost above salary?",
            "a": "Beyond salary, employer cost includes: employer NI (15% on earnings above £5,000), employer pension (minimum 3% of qualifying earnings between £6,240 and £50,270), and overheads such as equipment, software and workspace. For most UK salaries this adds 12–20% above headline pay. Use the inputs above to set your exact pension rate and overhead figure.",
        },
        {
            "q": "What changed for employers in April 2025?",
            "a": "Three changes took effect from 6 April 2025: the employer NI rate rose from 13.8% to 15%, the secondary threshold was cut from £9,100 to £5,000, and Employment Allowance increased from £5,000 to £10,500 with the eligibility cap removed. For a £30,000 salary, annual employer NI increased from approximately £2,884 to £3,750 — a rise of £866 per year.",
        },
        {
            "q": "How is employer NI different from employee NI?",
            "a": "Employer NI is a cost paid by the employer on top of gross salary — it does not reduce take-home pay. Employee NI is deducted from the employee's wages instead. For 2025/26, employees pay 8% on earnings between £12,570 and £50,270, then 2% above that. Employers pay 15% on all earnings above £5,000 with no upper cap. This calculator covers the employer side; for employee take-home pay see AfterTaxSalary.co.uk.",
        },
        {
            "q": "What are employer costs in the UK?",
            "a": "UK employer costs in 2025/26 are: gross salary, employer NI at 15% on earnings above £5,000, employer pension at minimum 3% of qualifying earnings (£6,240–£50,270), and any operational overheads such as equipment or software. For a £35,000 salary, statutory employer costs (NI + pension) add approximately £5,363/year before overheads.",
        },
        {
            "q": "How much do I cost my employer in the UK?",
            "a": "If you earn £35,000, you cost your employer roughly £40,363/year — your salary plus £4,500 employer NI and £863 minimum pension. At £50,000, the total is approximately £58,063. Your employer pays these on top of your salary; they are not deducted from your pay. Use this calculator to see the exact figure for your salary.",
        },
        {
            "q": "Is this a PAYE cost calculator for employers?",
            "a": "Yes. PAYE employer costs include employer NI — calculated at 15% above £5,000 for 2025/26 — plus the employer's auto-enrolment pension contribution. The full calculator models both alongside any overhead assumptions to give a total PAYE-basis employer spend per employee.",
        },
        {
            "q": "What is a cost to company (CTC) salary in the UK?",
            "a": "Cost to company (CTC) in the UK refers to the total annual cost of an employee to their employer — salary, employer NI, pension, and overheads combined. A £35,000 CTC salary typically means a gross salary of roughly £30,000–£32,000 once the employer's NI and pension obligations are included in the total. Use this calculator to work backwards from a CTC budget to a gross salary.",
        },
    ]


def calculator_faq() -> List[Dict[str, str]]:
    return default_faq() + [
        {
            "q": "Is this an employer total cost calculator for the UK?",
            "a": "Yes. This is an employer total cost calculator UK tool for 2025/26. It combines gross salary, employer NI, auto-enrolment pension and optional overheads into one annual and monthly employer cost output.",
        },
        {
            "q": "Can I use this as a total cost to employer calculator UK page?",
            "a": "Yes. Use this page as a total cost to employer calculator UK workflow: enter salary, choose pension rate, add overheads, and apply Employment Allowance if eligible to see net employer NI and full cost.",
        },
        {
            "q": "Does this work as an NI change calculator?",
            "a": "Yes. It works as an NI change calculator because it uses 2025/26 rules (15% above £5,000) and shows a comparison against 2024/25 assumptions so you can quantify the April 2025 employer NI change.",
        },
        {
            "q": "Where can I estimate auto enrolment payroll costs?",
            "a": "This calculator includes baseline auto enrolment payroll costs via employer pension on qualifying earnings. For pension-only scenarios, use the dedicated page at /pension-cost.",
        },
        {
            "q": "Is this an employer NI calculator 2025/26?",
            "a": "Yes. This page is an employer NI calculator 2025/26 tool and applies the current-year employer NI rate and threshold to your salary input, with monthly and annual outputs.",
        },
    ]


@app.route("/")
def home():
    default_result = calculate_employer_cost(salary=35000, pension_rate=3, overheads=3000, allowance=0)
    context = {
        "calc": default_result,
        "faq_items": default_faq(),
        "highlight_costs": [20000, 25000, 30000, 35000, 40000, 50000, 60000, 75000, 100000, 150000],
        "show_cross_links": True,
        "tools_block": _TOOLS_BLOCK_DEFAULT,
    }
    return render_template(
        "landing.html",
        **with_meta(
            context,
            title="Cost to Employer Calculator UK (2025/26) | Employer NI, Pension & Hiring Cost",
            description="UK cost to employer calculator for salary, employer NI, pension and total hiring cost. See true payroll cost by employee salary, with Employment Allowance and 2024/25 comparison included.",
            breadcrumbs=[{"name": "Home", "url": f"{SITE_URL}/"}],
        ),
    )


@app.route("/calculator")
def calculator_page():
    salary = max(1000, int(request.args.get("salary", 35000)))
    pension = float(request.args.get("pension", 3))
    overheads = max(0, int(request.args.get("overheads", 3000)))
    allowance = float(request.args.get("allowance", 0))
    result = calculate_employer_cost(salary=salary, pension_rate=pension, overheads=overheads, allowance=allowance)
    context = {
        "calc": result,
        "faq_items": calculator_faq(),
        "query_state": {"salary": salary, "pension": pension, "overheads": overheads, "allowance": allowance},
        "comparison_2024": employer_ni_2024(salary),
        "tools_block": _TOOLS_BLOCK_DEFAULT,
    }
    return render_template(
        "calculator.html",
        **with_meta(
            context,
            title="UK Employer Cost Calculator (2025/26) | Salary, NI, Pension & Total Cost",
            description="Calculate employer cost in the UK for any salary, including employer National Insurance, auto-enrolment pension and total payroll cost per month and year.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Calculator", "url": f"{SITE_URL}/calculator"},
            ],
        ),
    )


@app.route("/employer-ni-calculator")
@app.route("/cost-of-hiring-calculator")
@app.route("/employer-cost-calculator")
@app.route("/cost-to-employer-calculator")
@app.route("/cost-to-employer-calculator-uk")
@app.route("/total-cost-to-employer-calculator")
def calculator_aliases():
    alias_target = {
        "/employer-ni-calculator": "/employer-ni",
        "/employer-cost-calculator": "/employer-cost-calculator-uk",
        "/cost-to-employer-calculator": "/total-cost-to-employer-calculator-uk",
        "/cost-to-employer-calculator-uk": "/total-cost-to-employer-calculator-uk",
        "/total-cost-to-employer-calculator": "/total-cost-to-employer-calculator-uk",
    }.get(request.path, "/calculator")
    return redirect(alias_target, code=301)


@app.route("/employer-total-cost-calculator")
@app.route("/employer-cost-calculator-uk")
@app.route("/total-cost-to-employer-calculator-uk")
@app.route("/ni-change-calculator")
@app.route("/employer-ni-calculator-2025-26")
@app.route("/auto-enrolment-payroll-costs")
@app.route("/employer-costs-uk")
@app.route("/how-much-do-i-cost-my-employer")
@app.route("/paye-cost-to-employer-calculator")
@app.route("/employer-national-insurance-calculator")
@app.route("/salary-calculator-for-employers")
@app.route("/employee-cost-calculator-uk")
@app.route("/uk-average-salary")
@app.route("/employer-ni-historical-rates")
@app.route("/true-cost-of-employee-calculator-uk")
@app.route("/employer-salary-cost-calculator-uk")
@app.route("/first-employee-cost-uk")
@app.route("/part-time-employee-cost")
@app.route("/minimum-wage-employer-cost")
@app.route("/employer-cost-per-employee")
def gsc_intent_pages():
    page = GSC_INTENT_PAGES.get(request.path)
    if not page:
        abort(404)

    sample_salary = 35000 if request.path != "/auto-enrolment-payroll-costs" else 30000
    sample_calc = calculate_employer_cost(salary=sample_salary, pension_rate=3, overheads=3000, allowance=0)
    context = {
        "page": page,
        "sample_calc": sample_calc,
        "faq_items": page["faq_items"],
    }
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            context,
            title=page["title"],
            description=page["description"],
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Calculator intents", "url": f"{SITE_URL}/calculators"},
                {"name": page["h1"], "url": f"{SITE_URL}{request.path}"},
            ],
        ),
    )


@app.route("/cost-of-employing-someone-16-hours-a-week")
@app.route("/cost-of-employing-someone-20-hours-a-week")
@app.route("/cost-of-employing-someone-24-hours-a-week")
@app.route("/cost-of-employing-someone-25-hours-a-week")
@app.route("/cost-of-employing-someone-30-hours-a-week")
@app.route("/cost-of-employing-someone-37-5-hours-a-week")
@app.route("/cost-of-employing-someone-40-hours-a-week")
def hours_scenario_page():
    slug = request.path.lstrip("/")
    page_data = HOURS_SCENARIO_PAGES.get(slug)
    if not page_data:
        abort(404)
    page_data = _apply_year_deep(page_data)
    hours = page_data["hours"]
    salary = page_data["annual_salary_nlw"]
    calc = calculate_employer_cost(salary=salary, pension_rate=3, overheads=0, allowance=0)
    salary_mid = round(salary * 1.15 / 1000) * 1000  # a slightly higher example salary
    calc_mid = calculate_employer_cost(salary=salary_mid, pension_rate=3, overheads=2000, allowance=0)
    ni_above_threshold = max(0, salary - 5000)
    ni_cost = round(ni_above_threshold * 0.15)
    pension_qualifying = max(0, min(salary, 50270) - 6240)
    pension_cost = round(pension_qualifying * 0.03)
    page = {
        "badge": page_data["badge"],
        "h1": page_data["h1"],
        "intro": page_data["intro"],
        "bullets": [
            f"Hours per week: {hours} hrs (approximately {round(hours * 52):,} hours per year).",
            f"Annual salary at NLW (£12.71/hr): approximately £{salary:,}.",
            f"Employer NI (15% above £5,000): approximately £{ni_cost:,}/year.",
            f"Minimum employer pension (3% qualifying earnings): approximately £{pension_cost:,}/year.",
            f"Total statutory employer cost: approximately £{salary + ni_cost + pension_cost:,}/year before overheads.",
            "The employer NI secondary threshold (£5,000/year) is not pro-rated — it applies in full regardless of contracted hours.",
        ],
        "primary_cta": {"label": "Calculate exact employer cost", "url": f"/calculator?salary={salary}"},
        "secondary_cta": {"label": "Part-time employee cost overview", "url": "/part-time-employee-cost"},
        "faq_items": [
            {"q": f"Do employers pay NI on {hours}-hour part-time workers?", "a": f"Yes, if annual earnings exceed the £5,000 secondary threshold. At {hours} hours per week on the National Living Wage, annual salary is approximately £{salary:,}, which is above the threshold. Employer NI at 15% applies on earnings above £5,000, regardless of whether the employee is part-time or full-time. The threshold is not pro-rated for contracted hours."},
            {"q": "Does auto-enrolment apply to part-time employees?", "a": "Auto-enrolment triggers when a worker earns more than £10,000 per year and is aged 22–66. Part-time workers earning below £10,000 per year do not need to be automatically enrolled but can opt in, in which case the employer must still make contributions. Workers earning between £6,240 and £10,000 can opt in and the employer must contribute at the minimum rate on qualifying earnings."},
            {"q": "Is it cheaper to employ someone part-time than full-time per hour?", "a": "The gross wage cost per hour is identical for part-time and full-time staff on the same hourly rate. However, the employer NI secondary threshold (£5,000/year) is not reduced for part-time hours. This means the NI cost as a percentage of gross salary is higher for lower-paid part-time workers than for higher-earning full-time staff. For very low-hour workers earning below £5,000/year, there is no employer NI at all."},
            {"q": "What is the National Living Wage from April 2026?", "a": "The National Living Wage for workers aged 21 and over is £12.71 per hour from April 2026, rising from £12.21 per hour in 2025/26. The National Minimum Wage for workers aged 18–20 is £10.00 per hour."},
        ],
    }
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            {"page": page, "sample_calc": calc, "faq_items": page["faq_items"], "tools_block": _TOOLS_BLOCK_DEFAULT},
            title=page_data["title"] + " | EmployerCalculator.co.uk",
            description=page_data["description"],
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Cost of employing", "url": f"{SITE_URL}/cost-of-employing"},
                {"name": page_data["h1"], "url": f"{SITE_URL}/{slug}"},
            ],
        ),
    )


@app.route("/employer-cost-at-10-pounds-per-hour")
@app.route("/employer-cost-at-11-pounds-per-hour")
@app.route("/employer-cost-at-minimum-wage-per-hour")
@app.route("/employer-cost-at-13-pounds-per-hour")
@app.route("/employer-cost-at-14-pounds-per-hour")
@app.route("/employer-cost-at-15-pounds-per-hour")
@app.route("/employer-cost-at-20-pounds-per-hour")
@app.route("/employer-cost-at-25-pounds-per-hour")
@app.route("/employer-cost-at-30-pounds-per-hour")
def hourly_rate_page():
    slug = request.path.lstrip("/")
    page_data = HOURLY_RATE_PAGES.get(slug)
    if not page_data:
        abort(404)
    page_data = _apply_year_deep(page_data)
    rate = page_data["hourly_rate"]
    salary_ft = page_data["annual_salary_ft"]
    calc = calculate_employer_cost(salary=salary_ft, pension_rate=3, overheads=0, allowance=0)
    ni = calc.employer_ni.ni_due
    pension = calc.pension_contribution
    total = salary_ft + ni + pension
    hourly_total = round(total / 1950, 2)  # 37.5 × 52 = 1950 hours
    # Part-time variants at 20 and 30 hrs/wk
    salary_20h = round(rate * 20 * 52)
    salary_30h = round(rate * 30 * 52)
    calc_20h = calculate_employer_cost(salary=salary_20h, pension_rate=3, overheads=0, allowance=0)
    calc_30h = calculate_employer_cost(salary=salary_30h, pension_rate=3, overheads=0, allowance=0)
    page = {
        "badge": page_data["badge"],
        "h1": page_data["h1"],
        "intro": f"An employee paid £{rate:.2f} per hour, working full-time (37.5 hours per week), earns approximately £{salary_ft:,} per year. The true employer cost is higher: employer NI at 15% on earnings above the £5,000 secondary threshold adds £{int(ni):,} per year, and minimum auto-enrolment pension at 3% adds £{int(pension):,} per year on qualifying earnings. Total employer cost: approximately £{int(total):,} per year — or roughly £{hourly_total:.2f} per productive hour before overheads.",
        "bullets": [
            f"Hourly rate: £{rate:.2f}/hour.",
            f"Full-time annual salary (37.5 hrs/wk): approximately £{salary_ft:,}/year.",
            f"Employer NI (15% above £5,000): approximately £{int(ni):,}/year.",
            f"Minimum employer pension (3% on qualifying earnings): approximately £{int(pension):,}/year.",
            f"Total statutory employer cost full-time: approximately £{int(total):,}/year.",
            f"At 20 hrs/week: salary ≈ £{salary_20h:,} · total employer cost ≈ £{int(calc_20h.total_cost):,}/year.",
            f"At 30 hrs/week: salary ≈ £{salary_30h:,} · total employer cost ≈ £{int(calc_30h.total_cost):,}/year.",
        ],
        "primary_cta": {"label": "Calculate exact employer cost", "url": f"/calculator?salary={salary_ft}"},
        "secondary_cta": {"label": "Cost of employing by salary", "url": "/cost-of-employing"},
        "faq_items": [
            {"q": f"What does a £{rate:.2f}/hour employee cost an employer per year?", "a": f"A full-time employee at £{rate:.2f}/hour (37.5 hours per week) earns approximately £{salary_ft:,} per year. Adding employer NI of approximately £{int(ni):,} and minimum pension of approximately £{int(pension):,}, the total employer cost before overheads is approximately £{int(total):,} per year."},
            {"q": "Does the employer NI rate change for lower-paid workers?", "a": "No — employer NI is always 15% on earnings above the £5,000 secondary threshold for 2025/26. There is no reduced rate for lower-paid workers. The practical effect is that lower wages carry a higher NI burden as a percentage of salary, because a larger proportion of total earnings falls in the NIable band relative to the threshold."},
            {"q": "How does hourly employer cost differ from hourly wage?", "a": "The hourly wage is what the employee receives. The true employer hourly cost includes the wage plus the employer's share of NI and pension contributions. For a £15/hour worker on full-time hours, the true employer cost per hour is approximately £17.00–£17.50 depending on pension rate and overheads."},
        ],
    }
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            {"page": page, "sample_calc": calc, "faq_items": page["faq_items"], "tools_block": _TOOLS_BLOCK_DEFAULT},
            title=page_data["title"],
            description=page_data["description"],
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Cost of employing", "url": f"{SITE_URL}/cost-of-employing"},
                {"name": page_data["h1"], "url": f"{SITE_URL}/{slug}"},
            ],
        ),
    )


@app.route("/cost-of-hiring-a-software-developer")
@app.route("/cost-of-hiring-an-admin-assistant")
@app.route("/cost-of-hiring-a-care-worker")
@app.route("/cost-of-hiring-a-warehouse-operative")
@app.route("/cost-of-hiring-a-receptionist")
@app.route("/cost-of-hiring-a-sales-executive")
@app.route("/cost-of-hiring-a-marketing-executive")
@app.route("/cost-of-hiring-a-cleaner")
@app.route("/cost-of-hiring-hospitality-staff")
@app.route("/cost-of-hiring-a-teaching-assistant")
@app.route("/cost-of-hiring-a-nurse")
@app.route("/cost-of-hiring-a-teacher")
@app.route("/cost-of-hiring-a-project-manager")
@app.route("/cost-of-hiring-a-delivery-driver")
@app.route("/cost-of-hiring-a-chef")
@app.route("/cost-of-hiring-an-accountant")
@app.route("/cost-of-hiring-an-hr-manager")
@app.route("/cost-of-hiring-a-customer-service-advisor")
def role_page():
    slug = request.path.lstrip("/")
    page_data = ROLE_PAGES.get(slug)
    if not page_data:
        abort(404)
    page_data = _apply_year_deep(page_data)
    example_salary = page_data["example_salary"]
    calc = calculate_employer_cost(salary=example_salary, pension_rate=3, overheads=2000, allowance=0)
    ni = calc.employer_ni.ni_due
    pension = calc.pension_contribution
    total_no_oh = example_salary + ni + pension
    # Build salary table rows
    levels_data = []
    for lvl in page_data.get("role_levels", []):
        lc = calculate_employer_cost(salary=lvl["example"], pension_rate=3, overheads=0, allowance=0)
        levels_data.append({
            "level": lvl["level"],
            "salary_range": lvl["salary_range"],
            "example": lvl["example"],
            "ni": lc.employer_ni.ni_due,
            "pension": lc.pension_contribution,
            "total": lc.total_cost,
        })
    page = {
        "badge": page_data["badge"],
        "h1": page_data["h1"],
        "intro": page_data["intro"],
        "bullets": [
            f"Typical salary range: {page_data['salary_range']}.",
            f"At £{example_salary:,} salary: employer NI ≈ £{int(ni):,}/year, pension ≈ £{int(pension):,}/year.",
            f"Total employer cost at £{example_salary:,} (before overheads): approximately £{int(total_no_oh):,}/year.",
            "Employer NI: 15% on earnings above the £5,000 secondary threshold (2025/26).",
            "Minimum employer pension: 3% on qualifying earnings between £6,240 and £50,270.",
            "Employment Allowance (up to £10,500) can offset NI for eligible small employers.",
        ],
        "primary_cta": {"label": f"Calculate cost at any salary", "url": f"/calculator?salary={example_salary}"},
        "secondary_cta": {"label": "All employer cost calculators", "url": "/calculators"},
        "faq_items": [
            {"q": f"How much does it cost to hire {page_data['badge'].lower()} in the UK?", "a": f"At a salary of £{example_salary:,}, the total employer cost including NI and minimum pension is approximately £{int(total_no_oh):,} per year before overheads. Adding typical workplace costs of £2,000–£5,000 per employee brings the realistic total to £{int(total_no_oh) + 2000:,}–£{int(total_no_oh) + 5000:,} per year."},
            {"q": "What is employer NI and how is it calculated?", "a": "Employer Class 1 National Insurance is paid by the employer at 15% on employee earnings above the secondary threshold of £5,000 per year in 2025/26. It is in addition to the employee's NI contribution and does not reduce take-home pay. For a salary of £35,000, employer NI is £4,500 per year (15% of £30,000 above the threshold)."},
            {"q": "Can Employment Allowance reduce my NI bill?", "a": "Yes. Eligible employers can offset up to £10,500 of annual employer NI through Employment Allowance in 2025/26. Most limited companies with at least one employee who is not also the sole director qualify. Single-director companies with no other employees cannot claim."},
        ],
    }
    return render_template(
        "role_page.html",
        **with_meta(
            {"page": page, "sample_calc": calc, "faq_items": page["faq_items"], "levels_data": levels_data, "tools_block": _TOOLS_BLOCK_DEFAULT},
            title=page_data["title"],
            description=page_data["description"],
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Hiring cost by role", "url": f"{SITE_URL}/cost-of-hiring"},
                {"name": page_data["h1"], "url": f"{SITE_URL}/{slug}"},
            ],
        ),
    )


@app.route("/cost-of-employing-hospitality-staff")
@app.route("/cost-of-employing-care-workers")
@app.route("/cost-of-employing-retail-staff")
@app.route("/cost-of-employing-construction-workers")
@app.route("/cost-of-employing-it-staff")
@app.route("/cost-of-employing-education-staff")
@app.route("/cost-of-employing-healthcare-workers")
@app.route("/cost-of-employing-logistics-staff")
def industry_page():
    slug = request.path.lstrip("/")
    page_data = INDUSTRY_PAGES.get(slug)
    if not page_data:
        abort(404)
    page_data = _apply_year_deep(page_data)
    salary = page_data["example_salary"]
    calc = calculate_employer_cost(salary=salary, pension_rate=3, overheads=0, allowance=0)
    ni = calc.employer_ni.ni_due
    pension = calc.pension_contribution
    page = {
        "badge": page_data["badge"],
        "h1": page_data["h1"],
        "intro": page_data["intro"],
        "bullets": page_data["bullets"],
        "primary_cta": page_data["primary_cta"],
        "secondary_cta": page_data["secondary_cta"],
        "faq_items": page_data["faq_items"],
    }
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            {"page": page, "sample_calc": calc, "faq_items": page["faq_items"], "tools_block": _TOOLS_BLOCK_DEFAULT},
            title=page_data["title"],
            description=page_data["description"],
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Industry employer costs", "url": f"{SITE_URL}/cost-of-hiring"},
                {"name": page_data["h1"], "url": f"{SITE_URL}/{slug}"},
            ],
        ),
    )


@app.route("/contractor-vs-employee-cost")
@app.route("/employee-vs-contractor-cost-uk")
def contractor_vs_employee():
    # Day rate equivalences at common salary points
    examples = []
    for salary in [35000, 50000, 70000, 100000]:
        calc = calculate_employer_cost(salary=salary, pension_rate=3, overheads=3000, allowance=0)
        # Day rate equivalent: total employer cost / 230 working days
        day_rate = round(calc.total_cost / 230)
        examples.append({
            "salary": salary,
            "employer_ni": calc.employer_ni.ni_due,
            "pension": calc.pension_contribution,
            "total_employer_cost": calc.total_cost,
            "equivalent_day_rate": day_rate,
        })
    page = {
        "badge": "Contractor vs employee",
        "h1": "Contractor vs employee cost UK (2025/26)",
        "intro": "Choosing between a permanent employee and a contractor involves more than the headline day rate. A PAYE employee at £50,000 salary costs an employer approximately £59,063 per year including NI, pension and modest overheads. The equivalent contractor at a day rate of approximately £257 per day for 230 days costs £59,110 — similar on paper, but with very different risk profiles, IR35 implications, and ongoing commitments. This page breaks down both sides so you can make a properly costed decision.",
        "bullets": [
            "PAYE employee total cost = salary + employer NI (15% above £5,000) + pension (3% minimum) + overheads.",
            "Contractor cost = day rate × days worked (no employer NI, pension, holiday pay or sick pay obligations).",
            "IR35 (off-payroll working rules): if a contractor works inside IR35, PAYE deductions apply and the employer cost structure changes significantly.",
            "Contractor day rates typically embed a premium for flexibility, lack of benefits and self-employment risk.",
            "Employment Allowance (up to £10,500) can offset employer NI costs for eligible PAYE employees.",
        ],
        "primary_cta": {"label": "Calculate employee total cost", "url": "/calculator"},
        "secondary_cta": {"label": "What is Employment Allowance?", "url": "/guides/employment-allowance-guide"},
        "faq_items": [
            {"q": "Is a contractor cheaper than an employee in the UK?", "a": "On a day-rate basis, a contractor often appears more expensive than an equivalent PAYE salary. However, the employer avoids employer NI (15%), pension contributions, holiday pay (up to 28 days/year), sick pay obligations, and statutory payments. For short-term or specialist work, a contractor can be cost-effective. For long-term, consistent roles, a permanent employee is usually more economical once day-rate premiums are accounted for."},
            {"q": "What is IR35 and how does it affect contractor costs?", "a": "IR35 (the off-payroll working rules) determines whether a contractor working through a limited company should be treated as an employee for tax purposes. If a contractor is deemed inside IR35, the engaging business must deduct PAYE tax and employee NI, and pay employer NI at 15%, eliminating most of the tax efficiency of contracting. Large and medium businesses have been responsible for assessing IR35 status since April 2021. Small businesses (meeting two of three criteria: fewer than 50 employees, turnover below £10.2m, balance sheet below £5.1m) are exempt and the contractor assesses their own status."},
            {"q": "What day rate is equivalent to a £50,000 salary?", "a": "A £50,000 salary costs an employer approximately £58,063 per year including NI and minimum pension (before overheads). At 230 working days per year, this equates to approximately £252 per day. A contractor day rate of £252 would therefore represent breakeven before accounting for the employer's overhead savings on holiday pay, sick pay, and employment admin. In practice, contractors command a premium above this breakeven figure."},
            {"q": "Do employers pay NI on contractor payments?", "a": "Employers do not pay employer NI on payments to genuine self-employed contractors or limited company contractors working outside IR35. If the contractor is deemed inside IR35, the fee-payer (usually the engaging business for medium/large companies) must operate PAYE and pay employer NI at 15% on the deemed employment income."},
        ],
    }
    page = _apply_year_deep(page)
    sample_calc = calculate_employer_cost(salary=50000, pension_rate=3, overheads=3000, allowance=0)
    return render_template(
        "contractor_vs_employee.html",
        **with_meta(
            {"page": page, "sample_calc": sample_calc, "faq_items": page["faq_items"], "examples": examples, "tools_block": _TOOLS_BLOCK_DEFAULT},
            title="Contractor vs Employee Cost UK (2025/26) — Day Rate, NI & Total Comparison",
            description="Should you hire a contractor or employee? Compare true employer cost at common salary levels. PAYE vs day-rate breakdown with IR35 context. UK 2025/26.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Contractor vs employee", "url": f"{SITE_URL}/contractor-vs-employee-cost"},
            ],
        ),
    )


@app.route("/cost-of-hiring")
@app.route("/cost-of-hiring-someone")
def cost_of_hiring_hub():
    role_list = [
        {"slug": "cost-of-hiring-a-software-developer", "title": "Software developer", "range": "£35k–£90k", "example_cost": 64638},
        {"slug": "cost-of-hiring-an-admin-assistant", "title": "Admin assistant", "range": "£21k–£32k", "example_cost": 29738},
        {"slug": "cost-of-hiring-a-care-worker", "title": "Care worker", "range": "£22k–£28k", "example_cost": 27381},
        {"slug": "cost-of-hiring-a-warehouse-operative", "title": "Warehouse operative", "range": "£22k–£32k", "example_cost": 29738},
        {"slug": "cost-of-hiring-a-receptionist", "title": "Receptionist", "range": "£21k–£30k", "example_cost": 27381},
        {"slug": "cost-of-hiring-a-sales-executive", "title": "Sales executive", "range": "£25k–£45k base", "example_cost": 36825},
        {"slug": "cost-of-hiring-a-marketing-executive", "title": "Marketing executive", "range": "£25k–£45k", "example_cost": 36825},
        {"slug": "cost-of-hiring-a-cleaner", "title": "Cleaner", "range": "NLW–£14/hr", "example_cost": 27155},
        {"slug": "cost-of-hiring-hospitality-staff", "title": "Hospitality staff", "range": "NLW–£13/hr", "example_cost": 27381},
        {"slug": "cost-of-hiring-a-teaching-assistant", "title": "Teaching assistant", "range": "£19k–£26k FTE", "example_cost": 25150},
    ]
    hours_list = [
        {"slug": "cost-of-employing-someone-16-hours-a-week", "label": "16 hrs/wk", "nlw_salary": 10158},
        {"slug": "cost-of-employing-someone-20-hours-a-week", "label": "20 hrs/wk", "nlw_salary": 12698},
        {"slug": "cost-of-employing-someone-24-hours-a-week", "label": "24 hrs/wk", "nlw_salary": 15237},
        {"slug": "cost-of-employing-someone-30-hours-a-week", "label": "30 hrs/wk", "nlw_salary": 19046},
        {"slug": "cost-of-employing-someone-37-5-hours-a-week", "label": "37.5 hrs/wk (full-time)", "nlw_salary": 24785},
        {"slug": "cost-of-employing-someone-40-hours-a-week", "label": "40 hrs/wk", "nlw_salary": 25397},
    ]
    industry_list = [
        {"slug": "cost-of-employing-hospitality-staff", "title": "Hospitality staff", "range": "NLW–£45k", "badge": "Hospitality"},
        {"slug": "cost-of-employing-care-workers", "title": "Care workers", "range": "£23,809–£32k", "badge": "Care"},
        {"slug": "cost-of-employing-retail-staff", "title": "Retail staff", "range": "NLW–£40k", "badge": "Retail"},
        {"slug": "cost-of-employing-construction-workers", "title": "Construction workers", "range": "£24k–£65k", "badge": "Construction"},
        {"slug": "cost-of-employing-it-staff", "title": "IT & tech staff", "range": "£30k–£100k+", "badge": "Tech"},
        {"slug": "cost-of-employing-education-staff", "title": "Education staff", "range": "£19k–£65k", "badge": "Education"},
        {"slug": "cost-of-employing-healthcare-workers", "title": "Healthcare workers", "range": "£23k–£65k", "badge": "Healthcare"},
        {"slug": "cost-of-employing-logistics-staff", "title": "Logistics & transport", "range": "£22k–£45k", "badge": "Logistics"},
    ]
    scenario_list = [
        {"slug": "contractor-vs-employee-cost", "title": "Contractor vs employee", "desc": "Day-rate vs PAYE total cost comparison"},
        {"slug": "full-time-vs-part-time-employee-cost", "title": "Full-time vs part-time", "desc": "NI threshold effect on hours split"},
        {"slug": "sole-director-employer-ni", "title": "Sole director NI", "desc": "No Employment Allowance — optimal salary"},
        {"slug": "first-employee-cost-uk", "title": "First employee cost", "desc": "What hiring your first person actually costs"},
        {"slug": "minimum-wage-employer-cost", "title": "Minimum wage employer cost", "desc": "NLW total cost including NI and pension"},
    ]
    return render_template(
        "cost_of_hiring_hub.html",
        **with_meta(
            {"role_list": role_list, "hours_list": hours_list, "industry_list": industry_list, "scenario_list": scenario_list, "tools_block": _TOOLS_BLOCK_DEFAULT},
            title="Cost of Hiring Someone UK (2025/26) — By Role, Hours & Salary | EmployerCalculator.co.uk",
            description="Browse UK employer hiring costs by job role, hours worked or salary level. Includes NI, pension and total cost for 2025/26. Covers developers, admin, care workers, hospitality and more.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Cost of hiring", "url": f"{SITE_URL}/cost-of-hiring"},
            ],
        ),
    )


@app.route("/cost/<int:amount>")
def cost_page(amount: int):
    if amount not in SALARY_AMOUNTS:
        abort(404)

    calc = calculate_employer_cost(salary=amount, pension_rate=3, allowance=0, overheads=0)
    with_allowance = calculate_employer_cost(salary=amount, pension_rate=3, allowance=EMPLOYMENT_ALLOWANCE_2025, overheads=0)
    diff = change_2025_vs_2024(amount)
    nearby = salary_neighbours(SALARY_AMOUNTS, amount, window=2)

    faq_items = [
        {
            "q": f"How much does employer NI add at £{amount:,}?",
            "a": f"At £{amount:,}, standard employer NI for 2025/26 is {gbp(calc.employer_ni.gross_ni)} before Employment Allowance.",
        },
        {
            "q": "Does Employment Allowance remove NI completely?",
            "a": "It can for smaller annual NI bills, but only if your business is eligible and allowance remains available.",
        },
        {
            "q": "Are these numbers monthly or annual?",
            "a": "The headline is annual, and monthly equivalents are shown throughout to support payroll planning.",
        },
    ]

    context = {
        "salary": amount,
        "calc": calc,
        "with_allowance": with_allowance,
        "year_change": diff,
        "nearby": nearby,
        "faq_items": faq_items,
    }

    ni_meta = gbp(calc.employer_ni.gross_ni)
    return render_template(
        "cost_page.html",
        **with_meta(
            context,
            title=f"Cost of Employing Someone on £{amount:,} (2025/26): {gbp(calc.total_cost)}/year Total",
            description=(
                f"A £{amount:,} salary costs {gbp(calc.total_cost)} per year total in 2025/26 — "
                f"{gbp(calc.total_cost / 12)} per month. Includes {ni_meta} employer NI at 15%, "
                f"{gbp(calc.pension_contribution)} pension (3% minimum) and full monthly breakdown."
            ),
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Cost of employing", "url": f"{SITE_URL}/cost-of-employing"},
                {"name": f"£{amount:,}", "url": f"{SITE_URL}/cost/{amount}"},
            ],
        ),
    )


@app.route("/employer-ni/<int:amount>")
def employer_ni_page(amount: int):
    if amount not in SALARY_AMOUNTS:
        abort(404)

    ni_current = employer_ni_2025(amount)
    ni_previous = employer_ni_2024(amount)
    with_allowance = employer_ni_2025(amount, allowance=EMPLOYMENT_ALLOWANCE_2025)
    nearby = salary_neighbours(SALARY_AMOUNTS, amount, window=2)

    faq_items = [
        {
            "q": f"How much employer NI is due on £{amount:,}?",
            "a": f"Standard employer NI is {gbp(ni_current.gross_ni)} for 2025/26 before allowance offsets.",
        },
        {
            "q": "How does this compare with 2024/25?",
            "a": f"The equivalent 2024/25 NI estimate is {gbp(ni_previous['gross_ni'])} before allowance.",
        },
    ]

    context = {
        "salary": amount,
        "ni_current": ni_current,
        "ni_previous": ni_previous,
        "with_allowance": with_allowance,
        "nearby": nearby,
        "faq_items": faq_items,
        "ni_rate": 15,
        "ni_threshold": SECONDARY_THRESHOLD_2025,
    }

    return render_template(
        "employer_ni_page.html",
        **with_meta(
            context,
            title=f"Employer NI on £{amount:,} (2025/26): {gbp(ni_current.gross_ni)}/year — {gbp(monthly(ni_current.gross_ni))}/month",
            description=f"Employer NI on a £{amount:,} salary is {gbp(ni_current.gross_ni)}/year ({gbp(monthly(ni_current.gross_ni))}/month) in 2025/26. Up {gbp(ni_current.gross_ni - ni_previous['gross_ni'])} from 2024/25. Rate 15% above £5,000. Employment Allowance offset included.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Employer NI by salary", "url": f"{SITE_URL}/employer-ni"},
                {"name": f"£{amount:,}", "url": f"{SITE_URL}/employer-ni/{amount}"},
            ],
        ),
    )


@app.route("/guides")
def guides_index():
    context = {"guide_items": GUIDES, "show_cross_links": True}
    return render_template(
        "guides_index.html",
        **with_meta(
            context,
            title="UK Employer Guides — NI, Pension, Hiring Costs & Employment Law (2025/26)",
            description="Practical guides for UK employers: employer NI at 15%, Employment Allowance, auto-enrolment pension, redundancy pay and hiring cost planning for 2025/26.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Guides", "url": f"{SITE_URL}/guides"},
            ],
        ),
    )


@app.route("/guides/<slug>")
def guide_page(slug: str):
    guide = GUIDES.get(slug)
    if not guide:
        abort(404)
    related = [
        {"slug": s, "title": g["title"]}
        for s, g in GUIDES.items()
        if s != slug
    ][:3]
    _payroll_guides = {"employer-on-costs-explained", "hiring-costs-edinburgh", "hiring-costs-cardiff", "hiring-costs-leeds", "hiring-costs-manchester", "hiring-costs-birmingham", "hiring-costs-london", "hiring-costs-liverpool", "hiring-costs-bristol", "hiring-costs-newcastle", "hiring-costs-sheffield", "hiring-costs-nottingham", "first-employee-cost", "part-time-employee-cost"}
    context = {
        "guide": guide,
        "slug": slug,
        "related_guides": related,
        "faq_items": guide.get("faq") or default_faq(),
        "show_cross_links": True,
        "tools_block": _TOOLS_BLOCK_DEFAULT if slug in _payroll_guides else None,
        "payroll_software_link": True,
    }
    return render_template(
        "guide_page.html",
        **with_meta(
            context,
            title=f"{guide['title']} | EmployerCalculator.co.uk",
            description=guide["description"],
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Guides", "url": f"{SITE_URL}/guides"},
                {"name": guide["title"], "url": f"{SITE_URL}/guides/{slug}"},
            ],
        ),
    )


@app.route("/calculators")
def calculators_index():
    context = {"tools": TOOL_CARDS}
    return render_template(
        "calculators_index.html",
        **with_meta(
            context,
            title="UK Employer Calculators — NI, Payroll & HR Planning Tools (2025/26)",
            description="Free UK employer calculators for 2025/26. Employer NI at 15%, total cost of hiring, pension contributions, redundancy pay, holiday entitlement and more.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Calculators", "url": f"{SITE_URL}/calculators"},
            ],
        ),
    )


@app.route("/employer-ni")
def employer_ni_index():
    context = {
        "amounts": SALARY_AMOUNTS,
        "faq_items": [
            {
                "q": "How is employer NI calculated in 2025/26?",
                "a": "Employer NI is 15% of the employee's earnings above the secondary threshold of £5,000 per year. Multiply (gross salary minus £5,000) by 0.15 to get the annual liability. For example: £40,000 salary — £5,000 threshold = £35,000 × 15% = £5,250 employer NI per year, or £437.50 per month.",
            },
            {
                "q": "What was employer NI before April 2025?",
                "a": "Before 6 April 2025, employer NI was 13.8% on earnings above the £9,100 secondary threshold. The April 2025 Budget changes raised the rate to 15% and cut the threshold to £5,000 — a dual impact that increased employer NI at virtually every salary level, particularly for lower-paid employees where the threshold reduction is proportionally larger.",
            },
            {
                "q": "Is there an upper limit on employer NI?",
                "a": "No. Unlike employee NI, which drops to 2% above £50,270, employer NI is charged at a flat 15% on all earnings above the £5,000 threshold with no cap. Reduced rates (0%) apply for employees under 21 and apprentices under 25, up to the upper secondary threshold of £50,270.",
            },
            {
                "q": "Can Employment Allowance reduce my employer NI bill?",
                "a": "Yes. Eligible employers can offset up to £10,500 of their annual employer NI liability through Employment Allowance in 2025/26. For small businesses with total employer NI below £10,500, this can eliminate the entire bill. The allowance is claimed via payroll software and applies against your cumulative employer NI payments during the tax year.",
            },
            {
                "q": "Is this page an NI rise calculator?",
                "a": "Yes. This employer NI calculator doubles as an NI rise calculator by showing 2025/26 NI outcomes against 2024/25 assumptions. The key policy shift is a rate increase to 15% and a lower secondary threshold (£5,000), which increases NI due at most salary levels.",
            },
            {
                "q": "Where can I check total cost, not just NI?",
                "a": "Use the full calculator at /calculator to include pension and overheads, or use /cost-of-employing for salary-by-salary total employer cost pages. Those pages combine salary, employer NI and minimum pension in one annual and monthly view.",
            },
            {
                "q": "How do I calculate employer NI on a salary?",
                "a": "The formula is: (gross salary − £5,000) × 15%. Examples: £25,000 salary → £3,000/yr. £35,000 → £4,500/yr. £50,000 → £6,750/yr. £75,000 → £10,500/yr. £100,000 → £14,250/yr. There is no upper earnings cap on employer NI.",
            },
            {
                "q": "What is the employer NI threshold in 2025/26?",
                "a": "The secondary threshold (the point above which employer NI is charged) is £5,000 per year in 2025/26, equivalent to £96.15 per week. This was cut from £9,100 in April 2025. Employer NI applies at 15% on all earnings above this threshold.",
            },
            {
                "q": "How much is employers NI per month?",
                "a": "Divide the annual employer NI by 12. At £30,000 salary: £3,750/yr ÷ 12 = £312.50/month. At £40,000: £5,250/yr ÷ 12 = £437.50/month. At £60,000: £8,250/yr ÷ 12 = £687.50/month. Select any salary from the table above for the exact monthly figure.",
            },
            {
                "q": "Do employers pay NI on all of the salary or just above the threshold?",
                "a": "Only on earnings above the £5,000 threshold. The first £5,000 is exempt. So on a £30,000 salary, NI is applied to £25,000 × 15% = £3,750. The threshold reduces the bill for every employee, but it is much lower in 2025/26 than it was pre-April 2025 (previously £9,100).",
            },
        ],
    }
    return render_template(
        "employer_ni_index.html",
        **with_meta(
            context,
            title="Employer NI Calculator UK 2025/26 — Calculate National Insurance by Salary",
            description="Calculate employer NI on any UK salary. 2025/26: 15% above £5,000. £30k = £3,750/yr · £35k = £4,500/yr · £50k = £6,750/yr · £75k = £10,500/yr. Monthly figures and 2024/25 comparison. Free.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Employer NI by salary", "url": f"{SITE_URL}/employer-ni"},
            ],
        ),
    )


@app.route("/cost-of-employing")
@app.route("/cost-of-employing-someone")
def cost_index():
    context = {
        "amounts": SALARY_AMOUNTS,
        "faq_items": [
            {
                "q": "What is the true cost of employing someone in the UK?",
                "a": "The true employer cost is salary plus employer National Insurance (15% above £5,000 for 2025/26) plus employer pension (minimum 3% of qualifying earnings) plus any overhead costs such as equipment, software or workspace. For a £35,000 salary with standard pension and no overheads, total employer cost is approximately £39,500 — about 13% above the headline salary.",
            },
            {
                "q": "How does employer cost change above £50,270?",
                "a": "Employer NI continues at 15% above the threshold with no upper cap — unlike employee NI which drops to 2% above £50,270. Pension qualifying earnings are capped at £50,270, so employer pension contributions stop increasing above that level. This means employer NI becomes a larger portion of total cost for higher salaries.",
            },
            {
                "q": "What is auto-enrolment and what does it cost employers?",
                "a": "Auto-enrolment requires employers to enrol eligible workers into a workplace pension and make contributions. The minimum employer contribution is 3% of qualifying earnings between £6,240 and £50,270 per year. For a £35,000 salary, qualifying earnings are £28,760 and minimum employer pension is £862.80 per year. Employers can pay more, but 3% is the statutory minimum.",
            },
            {
                "q": "Do these costs include recruitment and training?",
                "a": "These pages show the recurring employer cost — salary, NI, pension — not one-off hiring costs. Recruitment fees, onboarding, training, and equipment are additional. Use the full employer cost calculator at /calculator to add an overhead figure that captures your organisation-specific costs per head.",
            },
            {
                "q": "Can I use this as a hiring budget calculator?",
                "a": "Yes. These pages are designed as a practical hiring budget baseline: salary + employer NI + minimum pension. For role approval workflows, start with these baseline figures and then add your internal overhead assumptions in the full calculator.",
            },
            {
                "q": "Why did employer cost jump in 2025/26?",
                "a": "The jump comes from the April 2025 NI policy change: rate up from 13.8% to 15% and threshold down from £9,100 to £5,000. This raises recurring payroll cost even before discretionary benefits or one-off hiring spend.",
            },
        ],
    }
    return render_template(
        "cost_index.html",
        **with_meta(
            context,
            title="Cost of Employing Someone UK (2025/26) — Employer NI, Pension & Total Cost by Salary",
            description="What does it cost to employ someone in the UK? Salary + employer NI (15% above £5k) + pension (3%). £30k = £34,464/yr · £35k = £39,501/yr · £50k = £58,063/yr. Includes 2024/25 NI comparison.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Cost of employing", "url": f"{SITE_URL}/cost-of-employing"},
            ],
        ),
    )


@app.route("/contact")
def contact_page():
    context = {
        "title_override": "Contact",
        "lead": "Contact EmployerCalculator Editorial for corrections, source updates or general queries.",
        "content": [
            "Email: hello@employercalculator.co.uk",
            "We aim to respond within two business days.",
            "Please include the page URL and a concise description if reporting an issue.",
        ],
    }
    return render_template(
        "contact.html",
        **with_meta(
            context,
            title="Contact EmployerCalculator.co.uk — Corrections & Feedback",
            description="Contact the EmployerCalculator.co.uk editorial team for corrections, data-quality feedback or queries about UK employer cost and payroll content.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Contact", "url": f"{SITE_URL}/contact"},
            ],
        ),
    )


@app.route("/methodology")
@app.route("/sources")
@app.route("/privacy")
@app.route("/terms")
def static_pages():
    slug = request.path.strip("/")
    page = STATIC_PAGES.get(slug)
    if not page:
        abort(404)
    context = {"page": page, "slug": slug}
    return render_template(
        "static_page.html",
        **with_meta(
            context,
            title=f"{page['title']} | EmployerCalculator.co.uk",
            description=page["description"],
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": page["title"], "url": f"{SITE_URL}/{slug}"},
            ],
        ),
    )


@app.route("/about")
def about_page():
    return render_template(
        "about.html",
        **with_meta(
            {},
            title="About EmployerCalculator.co.uk — UK Employer Cost Resource",
            description="EmployerCalculator.co.uk is a UK employer cost and payroll reference maintained by a small editorial team. See how employer NI, pension costs and total hiring cost estimates are researched and kept current.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "About", "url": f"{SITE_URL}/about"},
            ],
        ),
    )


@app.route("/editorial-standards")
def editorial_standards_page():
    return render_template(
        "editorial_standards.html",
        **with_meta(
            {},
            title="Editorial Standards — EmployerCalculator.co.uk",
            description="Editorial and quality standards used for UK employer cost, payroll and NI content on EmployerCalculator.co.uk. How we research, review and update our content.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Editorial Standards", "url": f"{SITE_URL}/editorial-standards"},
            ],
        ),
    )


@app.route("/html-sitemap")
@app.route("/sitemap")
@app.route("/sitemap.html")
def html_sitemap():
    context = {}
    return render_template(
        "html_sitemap.html",
        **with_meta(
            context,
            title="HTML sitemap",
            description="HTML sitemap for EmployerCalculator.co.uk.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "HTML sitemap", "url": f"{SITE_URL}/html-sitemap"},
            ],
        ),
    )


@app.route("/trap")
def honeypot_trap():
    """Hidden honeypot — any visitor is a bot. Block their IP instantly."""
    ip_str = _get_real_ip()
    if ip_str:
        _HONEYPOT_BLOCKED.add(ip_str)
    abort(403)


@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /trap\n"
        "Disallow: /*?salary=\n"
        "Disallow: /*?pension=\n"
        "Allow: /calculator\n"
        "Allow: /employer-total-cost-calculator\n"
        "Allow: /employer-cost-calculator-uk\n"
        "Allow: /total-cost-to-employer-calculator-uk\n"
        "Allow: /auto-enrolment-payroll-costs\n"
        "Allow: /favicon.ico\n"
        "Allow: /favicon-32x32.png\n"
        "Allow: /favicon-16x16.png\n"
        "Allow: /apple-touch-icon.png\n"
        "Allow: /site.webmanifest\n"
        "Allow: /static/\n"
        "\n"
        "User-agent: Bytespider\n"
        "Disallow: /\n"
        "\n"
        "User-agent: CCBot\n"
        "Disallow: /\n"
        "\n"
        "User-agent: PetalBot\n"
        "Disallow: /\n"
        "\n"
        "User-agent: DataForSeoBot\n"
        "Disallow: /\n"
        "\n"
        f"Sitemap: {SITE_URL}/sitemap.xml\n"
    )
    response = make_response(body)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response


@app.route("/ads.txt")
def ads_txt():
    client = ADSENSE_CLIENT.replace("ca-", "").strip()
    body = f"google.com, {client}, DIRECT, f08c47fec0942fa0\n"
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/plain"
    return resp


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/vnd.microsoft.icon")

@app.route("/site.webmanifest")
def site_webmanifest():
    return send_from_directory(app.static_folder, "site.webmanifest", mimetype="application/manifest+json")

@app.route("/apple-touch-icon.png")
def apple_touch_icon():
    return send_from_directory(app.static_folder, "apple-touch-icon.png", mimetype="image/png")

@app.route("/favicon-32x32.png")
def favicon_32():
    return send_from_directory(app.static_folder, "favicon-32x32.png", mimetype="image/png")

@app.route("/favicon-16x16.png")
def favicon_16():
    return send_from_directory(app.static_folder, "favicon-16x16.png", mimetype="image/png")


@app.route("/llms.txt")
def llms_txt():
    body = f"""# EmployerCalculator.co.uk

> Free UK employer cost calculator covering employer National Insurance, pension contributions, and total hiring costs for the 2025/26 tax year.

EmployerCalculator.co.uk is an independent tool that helps UK employers, HR teams, and finance professionals calculate the true cost of employing someone. It uses current HMRC-published rates and thresholds.

## What we calculate

- Employer Class 1 National Insurance at 15% above the £5,000 secondary threshold (from 6 April 2025)
- Employer pension contributions under auto-enrolment (3% minimum on qualifying earnings)
- Total annual and monthly employer cost per employee
- Cost increase from 2024/25 to 2025/26 rates
- Employment Allowance offset modelling (£10,500 relief in 2025/26, no £100,000 NI bill cap)

## Key 2025/26 figures

- Employer NI rate: 15% (up from 13.8% in 2024/25)
- Secondary threshold: £5,000 per year (down from £9,100)
- Employment Allowance: £10,500 (up from £5,000; eligibility cap removed)
- Minimum employer pension: 3% of qualifying earnings
- Upper secondary threshold (under-21, apprentices): £50,270

## Coverage

- 48 salary reference points from £18,000 to £200,000
- England, Wales, Scotland and Northern Ireland employer costs
- Guides on employer NI, hiring costs, Employment Allowance, and pensions
- Methodology and editorial standards published at {SITE_URL}/methodology

## Pages

- Calculator: {SITE_URL}/calculator
- Cost of employing hub: {SITE_URL}/cost-of-employing
- Employer NI hub: {SITE_URL}/employer-ni
- Employer total cost calculator: {SITE_URL}/employer-total-cost-calculator
- Employer cost calculator UK: {SITE_URL}/employer-cost-calculator-uk
- Total cost to employer calculator UK: {SITE_URL}/total-cost-to-employer-calculator-uk
- Auto-enrolment payroll costs: {SITE_URL}/auto-enrolment-payroll-costs
- NI change calculator: {SITE_URL}/ni-change-calculator
- Employer NI calculator 2025/26: {SITE_URL}/employer-ni-calculator-2025-26
- Guides index: {SITE_URL}/guides
- Methodology: {SITE_URL}/methodology
- Sources: {SITE_URL}/sources
- Editorial standards: {SITE_URL}/editorial-standards

## Data sources

- HMRC — Rates and thresholds for employers 2025 to 2026: https://www.gov.uk/guidance/rates-and-thresholds-for-employers-2025-to-2026
- HMRC — National Insurance rates and categories: https://www.gov.uk/national-insurance-rates-letters
- The Pensions Regulator — Automatic enrolment contributions: https://www.thepensionsregulator.gov.uk/en/employers/automatic-enrolment-guide-for-employers/contributions
- GOV.UK — Employment Allowance: https://www.gov.uk/claim-employment-allowance

## How to cite

Name: EmployerCalculator.co.uk
URL: {SITE_URL}/
Calculator: {SITE_URL}/calculator
Contact: {SITE_URL}/contact

## Licensing

Factual HMRC data is Crown copyright and open government licensed. Calculator outputs and editorial content are copyright EmployerCalculator.co.uk. Content may be cited with attribution. See {SITE_URL}/terms for usage terms.
"""
    response = make_response(body)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response


@app.route("/sitemap.xml")
def sitemap_xml():
    # (url, priority, changefreq)
    url_entries = [
        (f"{SITE_URL}/", "1.0", "daily"),
        (f"{SITE_URL}/calculator", "0.9", "weekly"),
        (f"{SITE_URL}/employer-total-cost-calculator", "0.8", "weekly"),
        (f"{SITE_URL}/employer-cost-calculator-uk", "0.8", "weekly"),
        (f"{SITE_URL}/total-cost-to-employer-calculator-uk", "0.8", "weekly"),
        (f"{SITE_URL}/auto-enrolment-payroll-costs", "0.8", "weekly"),
        (f"{SITE_URL}/ni-change-calculator", "0.8", "weekly"),
        (f"{SITE_URL}/employer-ni-calculator-2025-26", "0.8", "weekly"),
        (f"{SITE_URL}/employer-national-insurance-calculator", "0.8", "weekly"),
        (f"{SITE_URL}/employer-costs-uk", "0.8", "weekly"),
        (f"{SITE_URL}/how-much-do-i-cost-my-employer", "0.8", "weekly"),
        (f"{SITE_URL}/paye-cost-to-employer-calculator", "0.8", "weekly"),
        (f"{SITE_URL}/salary-calculator-for-employers", "0.8", "weekly"),
        (f"{SITE_URL}/employee-cost-calculator-uk", "0.8", "weekly"),
        (f"{SITE_URL}/cost-of-employing", "0.8", "weekly"),
        (f"{SITE_URL}/employer-ni", "0.8", "weekly"),
        (f"{SITE_URL}/guides", "0.8", "weekly"),
        (f"{SITE_URL}/payroll-software-uk", "0.8", "monthly"),
        (f"{SITE_URL}/calculators", "0.7", "weekly"),
        (f"{SITE_URL}/methodology", "0.6", "monthly"),
        (f"{SITE_URL}/editorial-standards", "0.6", "monthly"),
        (f"{SITE_URL}/sources", "0.6", "monthly"),
        (f"{SITE_URL}/about", "0.5", "monthly"),
        (f"{SITE_URL}/contact", "0.5", "monthly"),
        (f"{SITE_URL}/holiday-entitlement", "0.8", "monthly"),
        (f"{SITE_URL}/redundancy-pay", "0.8", "monthly"),
        (f"{SITE_URL}/maternity-pay", "0.8", "monthly"),
        (f"{SITE_URL}/notice-period", "0.8", "monthly"),
        (f"{SITE_URL}/settlement-agreement", "0.7", "monthly"),
        (f"{SITE_URL}/pro-rata-salary", "0.8", "monthly"),
        (f"{SITE_URL}/sick-pay", "0.8", "monthly"),
        (f"{SITE_URL}/pension-cost", "0.8", "monthly"),
        (f"{SITE_URL}/bradford-factor", "0.7", "monthly"),
        (f"{SITE_URL}/unfair-dismissal", "0.7", "monthly"),
        (f"{SITE_URL}/html-sitemap", "0.3", "monthly"),
        (f"{SITE_URL}/privacy", "0.3", "yearly"),
        (f"{SITE_URL}/terms", "0.3", "yearly"),
        (f"{SITE_URL}/uk-average-salary", "0.8", "monthly"),
        (f"{SITE_URL}/employer-ni-historical-rates", "0.8", "monthly"),
        (f"{SITE_URL}/true-cost-of-employee-calculator-uk", "0.8", "monthly"),
        (f"{SITE_URL}/employer-salary-cost-calculator-uk", "0.8", "weekly"),
        (f"{SITE_URL}/first-employee-cost-uk", "0.8", "monthly"),
        (f"{SITE_URL}/part-time-employee-cost", "0.8", "monthly"),
        (f"{SITE_URL}/minimum-wage-employer-cost", "0.8", "monthly"),
        (f"{SITE_URL}/employer-cost-per-employee", "0.8", "monthly"),
        # Hours-based scenario pages
        (f"{SITE_URL}/cost-of-employing-someone-16-hours-a-week", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-someone-20-hours-a-week", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-someone-24-hours-a-week", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-someone-25-hours-a-week", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-someone-30-hours-a-week", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-someone-37-5-hours-a-week", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-someone-40-hours-a-week", "0.8", "monthly"),
        # Hourly rate pages
        (f"{SITE_URL}/employer-cost-at-10-pounds-per-hour", "0.8", "monthly"),
        (f"{SITE_URL}/employer-cost-at-11-pounds-per-hour", "0.8", "monthly"),
        (f"{SITE_URL}/employer-cost-at-minimum-wage-per-hour", "0.8", "monthly"),
        (f"{SITE_URL}/employer-cost-at-13-pounds-per-hour", "0.8", "monthly"),
        (f"{SITE_URL}/employer-cost-at-14-pounds-per-hour", "0.8", "monthly"),
        (f"{SITE_URL}/employer-cost-at-15-pounds-per-hour", "0.8", "monthly"),
        (f"{SITE_URL}/employer-cost-at-20-pounds-per-hour", "0.8", "monthly"),
        (f"{SITE_URL}/employer-cost-at-25-pounds-per-hour", "0.8", "monthly"),
        (f"{SITE_URL}/employer-cost-at-30-pounds-per-hour", "0.8", "monthly"),
        # Role pages
        (f"{SITE_URL}/cost-of-hiring-a-software-developer", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-an-admin-assistant", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-care-worker", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-warehouse-operative", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-receptionist", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-sales-executive", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-marketing-executive", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-cleaner", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-hospitality-staff", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-teaching-assistant", "0.8", "monthly"),
        # Hubs and special pages
        (f"{SITE_URL}/cost-of-hiring", "0.8", "weekly"),
        (f"{SITE_URL}/contractor-vs-employee-cost", "0.8", "monthly"),
        (f"{SITE_URL}/team-cost-planner", "0.9", "weekly"),
        # Payroll software comparison pages
        (f"{SITE_URL}/xero-vs-sage-payroll", "0.8", "monthly"),
        (f"{SITE_URL}/xero-vs-quickbooks-payroll", "0.8", "monthly"),
        (f"{SITE_URL}/best-payroll-software-1-employee", "0.8", "monthly"),
        # Apprenticeship Levy
        (f"{SITE_URL}/apprenticeship-levy-calculator", "0.8", "monthly"),
        # Industry cost pages
        (f"{SITE_URL}/cost-of-employing-hospitality-staff", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-care-workers", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-retail-staff", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-construction-workers", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-it-staff", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-education-staff", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-healthcare-workers", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-employing-logistics-staff", "0.8", "monthly"),
        # New role pages
        (f"{SITE_URL}/cost-of-hiring-a-nurse", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-teacher", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-project-manager", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-delivery-driver", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-chef", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-an-accountant", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-an-hr-manager", "0.8", "monthly"),
        (f"{SITE_URL}/cost-of-hiring-a-customer-service-advisor", "0.8", "monthly"),
        # Director and comparison pages
        (f"{SITE_URL}/sole-director-employer-ni", "0.8", "monthly"),
        (f"{SITE_URL}/full-time-vs-part-time-employee-cost", "0.8", "monthly"),
    ]
    for slug in GUIDES:
        url_entries.append((f"{SITE_URL}/guides/{slug}", "0.8", "monthly"))
    for s in SALARY_AMOUNTS:
        url_entries.append((f"{SITE_URL}/cost/{s}", "0.7", "monthly"))
    for s in SALARY_AMOUNTS:
        url_entries.append((f"{SITE_URL}/employer-ni/{s}", "0.6", "monthly"))
    now = datetime.utcnow().date().isoformat()
    xml = render_template("sitemap.xml", url_entries=url_entries, now=now)
    response = make_response(xml)
    response.headers["Content-Type"] = "application/xml; charset=utf-8"
    return response


@app.route("/health")
@app.route("/healthz")
def health_check():
    return {"status": "ok", "site": "employercalculator", "tax_year": active_tax_year()}


@app.template_filter("money")
def money_filter(value: float) -> str:
    return gbp(float(value))


@app.template_filter("monthly")
def monthly_filter(value: float) -> str:
    return gbp(monthly(float(value)))


@app.template_filter("weekly")
def weekly_filter(value: float) -> str:
    return gbp(weekly(float(value)))


@app.template_filter("percent")
def percent_filter(value: float) -> str:
    return pct(float(value))


@app.route("/holiday-entitlement-calculator")
def holiday_entitlement_alias():
    return redirect("/holiday-entitlement", code=301)


@app.route("/holiday-entitlement")
def holiday_entitlement():
    return render_template(
        "holiday_entitlement.html",
        **with_meta(
            {},
            title="Holiday Entitlement Calculator 2025/26 | EmployerCalculator.co.uk",
            description="UK holiday entitlement calculator for 2025/26. Full-time: 28 days statutory minimum. Part-time: pro-rated by days or hours. Supports mid-year starters.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Holiday Entitlement Calculator", "url": f"{SITE_URL}/holiday-entitlement"},
            ],
        ),
    )


@app.route("/redundancy-pay-calculator")
def redundancy_pay_alias():
    return redirect("/redundancy-pay", code=301)


@app.route("/redundancy-pay")
def redundancy_pay():
    return render_template(
        "redundancy_pay.html",
        **with_meta(
            {},
            title="Statutory Redundancy Pay Calculator 2025/26 | EmployerCalculator.co.uk",
            description="Statutory redundancy pay calculator for 2025/26. Age-banded calculation — up to 1.5 weeks' pay per year of service. Weekly pay capped at £700.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Redundancy Pay Calculator", "url": f"{SITE_URL}/redundancy-pay"},
            ],
        ),
    )


@app.route("/maternity-pay-calculator")
def maternity_pay_alias():
    return redirect("/maternity-pay", code=301)


@app.route("/maternity-pay")
def maternity_pay():
    return render_template(
        "maternity_pay.html",
        **with_meta(
            {},
            title="Statutory Maternity Pay Calculator 2025/26 | EmployerCalculator.co.uk",
            description="Statutory maternity pay calculator for 2025/26. 6 weeks at 90% AWE, then 33 weeks at £184.03/week. Includes HMRC recovery at 92% or 103% for small employers.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Statutory Maternity Pay Calculator", "url": f"{SITE_URL}/maternity-pay"},
            ],
        ),
    )


@app.route("/notice-period-calculator")
def notice_period_alias():
    return redirect("/notice-period", code=301)


@app.route("/notice-period")
def notice_period():
    return render_template(
        "notice_period.html",
        **with_meta(
            {},
            title="Notice Period Calculator UK 2025/26 | EmployerCalculator.co.uk",
            description="UK notice period calculator. Statutory minimum: 1 week per year of service (max 12 weeks). Calculates PILON and compares statutory vs contractual notice.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Notice Period Calculator", "url": f"{SITE_URL}/notice-period"},
            ],
        ),
    )


@app.route("/settlement-agreement-calculator")
def settlement_agreement_alias():
    return redirect("/settlement-agreement", code=301)


@app.route("/settlement-agreement")
def settlement_agreement():
    return render_template(
        "settlement_agreement.html",
        **with_meta(
            {},
            title="Settlement Agreement Calculator 2025/26 | EmployerCalculator.co.uk",
            description="Settlement agreement calculator for UK employers. Estimates notice pay, statutory redundancy and compensatory amounts. First £30,000 generally tax-free.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Settlement Agreement Calculator", "url": f"{SITE_URL}/settlement-agreement"},
            ],
        ),
    )


@app.route("/pro-rata-salary-calculator")
def pro_rata_alias():
    return redirect("/pro-rata-salary", code=301)


@app.route("/pro-rata-salary")
def pro_rata_salary():
    return render_template(
        "pro_rata_salary.html",
        **with_meta(
            {},
            title="Pro Rata Salary Calculator UK | EmployerCalculator.co.uk",
            description="Free pro-rata salary calculator for part-time workers. Convert full-time salary by days or hours per week. Shows annual, monthly and weekly pro-rata pay.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Pro Rata Salary Calculator", "url": f"{SITE_URL}/pro-rata-salary"},
            ],
        ),
    )


@app.route("/sick-pay-calculator")
def sick_pay_alias():
    return redirect("/sick-pay", code=301)


@app.route("/sick-pay")
def sick_pay():
    return render_template(
        "sick_pay.html",
        **with_meta(
            {},
            title="Statutory Sick Pay Calculator 2025/26 | EmployerCalculator.co.uk",
            description="SSP calculator for 2025/26. Rate: £116.75 per week. Checks earnings eligibility (£123/week minimum), deducts 3 waiting days and applies 28-week cap.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Statutory Sick Pay Calculator", "url": f"{SITE_URL}/sick-pay"},
            ],
        ),
    )


@app.route("/pension-cost-calculator")
def pension_cost_alias():
    return redirect("/pension-cost", code=301)


@app.route("/auto-enrollment-payroll-costs")
def auto_enrolment_payroll_costs_alias():
    return redirect("/auto-enrolment-payroll-costs", code=301)


@app.route("/pension-cost")
def pension_cost():
    return render_template(
        "pension_cost.html",
        **with_meta(
            {},
            title="Employer Pension Cost Calculator UK (2025/26) — Auto-Enrolment Costs",
            description="Employer pension cost calculator UK for 2025/26. Estimate auto-enrolment payroll costs on qualifying earnings (£6,240–£50,270), including total contributions.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Employer Pension Cost Calculator", "url": f"{SITE_URL}/pension-cost"},
            ],
        ),
    )


@app.route("/bradford-factor-calculator")
def bradford_factor_alias():
    return redirect("/bradford-factor", code=301)


@app.route("/bradford-factor")
def bradford_factor():
    return render_template(
        "bradford_factor.html",
        **with_meta(
            {},
            title="Bradford Factor Calculator | EmployerCalculator.co.uk",
            description="Bradford Factor calculator for HR teams. Formula: S² × D. Enter absence spells and total days to get your score, risk band and comparison with common benchmarks.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Bradford Factor Calculator", "url": f"{SITE_URL}/bradford-factor"},
            ],
        ),
    )


@app.route("/unfair-dismissal-calculator")
def unfair_dismissal_alias():
    return redirect("/unfair-dismissal", code=301)


@app.route("/unfair-dismissal")
def unfair_dismissal():
    return render_template(
        "unfair_dismissal.html",
        **with_meta(
            {},
            title="Unfair Dismissal Compensation Calculator 2025/26 | EmployerCalculator.co.uk",
            description="Unfair dismissal calculator for 2025/26. Estimates basic award and compensatory award (capped at £105,707). Updated for Employment Rights Act 2025 changes.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Unfair Dismissal Calculator", "url": f"{SITE_URL}/unfair-dismissal"},
            ],
        ),
    )


@app.route("/national-insurance-increase-calculator")
@app.route("/national-insurance-rise-calculator-uk")
@app.route("/national-insurance-rise-calculator")
def ni_rise_alias():
    return redirect("/ni-change-calculator", code=301)


@app.route("/employer-nic-calculator")
@app.route("/employers-ni-calculator")
@app.route("/employers-ni-calculator-monthly")
@app.route("/national-insurance-calculator-for-employers")
@app.route("/calculate-employers-ni")
@app.route("/calculate-employers-ni-on-salary")
@app.route("/ni-calculator-2025-26")
@app.route("/employers-ni-calculator-2025-26")
def employer_ni_aliases():
    return redirect("/employer-ni", code=301)


@app.route("/employment-cost-calculator")
@app.route("/cost-to-employ-calculator")
@app.route("/salary-calculator-employers-uk")
@app.route("/employer-salary-calculator")
@app.route("/employers-salary-calculator")
@app.route("/cost-to-employer-salary-calculator-uk")
@app.route("/pay-calculator-for-employers")
@app.route("/true-cost-of-employee-calculator-uk")
@app.route("/uk-employee-cost-calculator")
def employer_cost_aliases():
    return redirect("/calculator", code=301)


@app.route("/employer-salary-cost-calculator")
def employer_salary_cost_calculator_alias():
    return redirect("/employer-salary-cost-calculator-uk", code=301)


@app.route("/first-employee-cost")
@app.route("/hiring-first-employee-uk")
def first_employee_cost_alias():
    return redirect("/first-employee-cost-uk", code=301)


@app.route("/part-time-employee-cost-uk")
@app.route("/cost-of-part-time-employee")
def part_time_cost_alias():
    return redirect("/part-time-employee-cost", code=301)


@app.route("/cost-per-employee-uk")
@app.route("/average-employer-cost-per-employee")
def employer_cost_per_employee_alias():
    return redirect("/employer-cost-per-employee", code=301)


@app.route("/cost-of-employment-calculator-uk")
@app.route("/cost-of-employee-calculator-uk")
@app.route("/how-much-does-it-cost-to-employ-someone")
@app.route("/salary-cost-to-employer")
def cost_index_aliases():
    return redirect("/cost-of-employing", code=301)


@app.route("/auto-enrolment-pension-rates")
@app.route("/how-much-is-auto-enrolment-pension")
def pension_aliases():
    return redirect("/pension-cost", code=301)


@app.route("/human-resources-calculator")
def hr_calculator_alias():
    return redirect("/calculators", code=301)


@app.route("/employment-calculator")
@app.route("/salary-employment-calculator")
@app.route("/employee-salary-calculator-uk")
def employment_calculator_alias():
    return redirect("/calculator", code=301)


@app.route("/on-costs-calculator")
@app.route("/salary-on-costs-calculator")
@app.route("/salary-on-costs-calculator-uk")
@app.route("/employer-on-costs-calculator")
@app.route("/employer-on-costs-calculator-uk")
@app.route("/salary-costs-calculator")
def on_costs_alias():
    return redirect("/cost-of-employing", code=301)


@app.route("/uk-average-salary-2025")
@app.route("/average-salary-uk-2025")
@app.route("/average-monthly-salary-uk")
@app.route("/average-salary-uk")
def average_salary_alias():
    return redirect("/uk-average-salary", code=301)


@app.route("/employer-ni-calculator-2022-23")
@app.route("/employer-ni-calculator-2023-24")
@app.route("/employer-ni-calculator-2024-25")
@app.route("/employer-ni-rates-history")
@app.route("/employer-ni-rates-by-year")
@app.route("/historical-employer-ni-rates")
@app.route("/employer-nic-rates-history")
def historical_ni_alias():
    return redirect("/employer-ni-historical-rates", code=301)


@app.route("/paye-calculator-uk-for-employers")
@app.route("/employer-paye-calculator")
@app.route("/employer-paye-calculator-uk")
@app.route("/employer-paye-tax-calculator")
@app.route("/employer-payroll-tax-calculator")
@app.route("/employers-tax-calculator")
@app.route("/uk-employer-tax-calculator")
@app.route("/cost-to-company-salary-calculator")
@app.route("/total-payroll-cost-calculator")
@app.route("/payroll-cost-calculator")
@app.route("/staff-cost-calculator-uk")
@app.route("/cost-of-employing-staff-calculator-uk")
@app.route("/cost-to-employ-someone-calculator-uk")
@app.route("/employee-costs-calculator")
@app.route("/employer-costs-calculator")
@app.route("/paye-cost-to-employer")
@app.route("/total-employment-cost-calculator")
@app.route("/employer-cost-salary-calculator")
@app.route("/employers-cost-calculator-uk")
@app.route("/employer-calculator")
def calculator_more_aliases():
    return redirect("/calculator", code=301)


@app.route("/employers-nic-calculator")
@app.route("/employer-ni-contribution-calculator")
@app.route("/employer-ni-contributions-calculator")
@app.route("/calculate-employer-ni")
@app.route("/calculating-employers-ni")
@app.route("/how-to-calculate-employers-ni")
@app.route("/how-to-work-out-employers-ni")
@app.route("/employer-ni-calculation")
@app.route("/employers-ni-calculation")
@app.route("/employer-ni-calculations")
@app.route("/employers-national-insurance-calculations")
@app.route("/employers-national-insurance-calculator")
@app.route("/employers-national-insurance-calculator-2025-26")
@app.route("/employer-national-insurance-calculator-uk")
def employer_ni_more_aliases():
    return redirect("/employer-ni", code=301)


@app.route("/salary-on-costs")
@app.route("/on-costs-salary")
@app.route("/salary-oncosts")
@app.route("/total-cost-of-employment")
@app.route("/cost-of-employment-calculator")
@app.route("/costs-of-an-employee")
@app.route("/cost-of-an-employee-uk")
@app.route("/cost-of-an-employee")
@app.route("/cost-of-employee")
@app.route("/employer-on-costs")
@app.route("/employment-costs")
@app.route("/employer-costs-for-employee-uk")
def cost_index_more_aliases():
    return redirect("/cost-of-employing", code=301)


@app.route("/employer-contribution-calculator")
@app.route("/pension-calculator-employer")
@app.route("/employer-pension-calculator")
@app.route("/pension-calculator-for-employers")
@app.route("/employer-contribution-calculation")
@app.route("/pension-calculator-for-employer")
def pension_more_aliases():
    return redirect("/pension-cost", code=301)


@app.route("/payroll-software-uk")
@app.route("/best-payroll-software-uk")
@app.route("/payroll-software-for-small-business-uk")
def payroll_software_page():
    comparison_table = [
        {"name": "Xero Payroll", "best_for": "Xero accounting users, 1–20 staff", "accounting": "Yes (Xero)", "hr": "Basic", "hmrc_rti": "Yes"},
        {"name": "QuickBooks Payroll", "best_for": "QuickBooks accounting users", "accounting": "Yes (QuickBooks)", "hr": "Basic", "hmrc_rti": "Yes"},
        {"name": "Sage Payroll", "best_for": "Standalone payroll, accountant-managed", "accounting": "Optional (Sage)", "hr": "Add-on", "hmrc_rti": "Yes"},
        {"name": "FreeAgent", "best_for": "Micro-businesses, NatWest/RBS customers", "accounting": "Yes", "hr": "Minimal", "hmrc_rti": "Yes"},
        {"name": "Employment Hero", "best_for": "HR + payroll, 5–50 staff", "accounting": "Integration", "hr": "Yes", "hmrc_rti": "Yes"},
        {"name": "Rippling", "best_for": "Multi-country, fast-growing teams", "accounting": "Integration", "hr": "Yes", "hmrc_rti": "Yes"},
    ]
    faq_items = [
        {"q": "What payroll software do UK small businesses use?", "a": "The most commonly used payroll software for UK small businesses are Xero Payroll, QuickBooks Payroll, Sage Payroll, and FreeAgent. All support HMRC RTI submissions and auto-enrolment pension handling."},
        {"q": "Do I need payroll software if I only have one employee?", "a": "You can use HMRC's free Basic PAYE Tools for very small employers (fewer than 10 employees), but most small business owners prefer dedicated software for payslip generation, pension management, and accountant integration. HMRC Basic PAYE Tools is free but limited in features."},
        {"q": "What is RTI and why does it matter?", "a": "RTI (Real Time Information) is HMRC's system that requires employers to submit payroll data on or before each pay day. All payroll software listed on this page handles RTI submissions automatically, which is the most important HMRC compliance requirement for employers."},
        {"q": "Can payroll software handle Employment Allowance?", "a": "Yes. Xero, QuickBooks, and Sage all support Employment Allowance claims, which allows eligible employers to offset up to £10,500 of their annual employer NI bill in 2025/26. You declare eligibility through your payroll software."},
        {"q": "What is the difference between payroll software and an HR system?", "a": "Payroll software handles wage calculations, PAYE deductions, RTI submissions, and payslips. An HR system (also called HRIS) handles contracts, onboarding, leave management, performance reviews, and other people operations. Products like Employment Hero combine both. For employers with under 10 staff, standalone payroll software is usually sufficient."},
    ]
    return render_template(
        "payroll_software.html",
        **with_meta(
            {"comparison_table": comparison_table, "faq_items": faq_items},
            title="Best Payroll Software for UK Small Businesses (2025/26) — Xero, QuickBooks, Sage",
            description="Compare payroll software for UK small businesses in 2025/26 — Xero, QuickBooks, Sage, FreeAgent and Employment Hero. Includes HMRC RTI support, pricing overview, and which to use after calculating employer costs.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Payroll software", "url": f"{SITE_URL}/payroll-software-uk"},
            ],
        ),
    )


_TOOLS_BLOCK_DEFAULT = [
    {
        "name": "Xero Payroll",
        "short_desc": "Cloud payroll bundled with Xero accounting. Handles RTI submissions, auto-enrolment and payslip generation. Commonly used by UK small businesses already on Xero for bookkeeping.",
        "href": "https://www.xero.com/uk/accounting-software/payroll/",
        "cta": "See Xero Payroll",
        "is_affiliate": False,
        "enabled": True,
    },
    {
        "name": "QuickBooks Payroll",
        "short_desc": "Payroll add-on for QuickBooks. Used by UK small employers for PAYE, NI, pension and HMRC RTI. Integrates with QuickBooks accounting.",
        "href": "https://quickbooks.intuit.com/uk/payroll/",
        "cta": "See QuickBooks Payroll",
        "is_affiliate": False,
        "enabled": True,
    },
    {
        "name": "Sage Payroll",
        "short_desc": "Long-established UK payroll software with HMRC recognition. Works standalone (without Sage accounting) and is widely used in small businesses and accountancy practices.",
        "href": "https://sageuklimited.sjv.io/n44Vmx",
        "cta": "See Sage Payroll",
        "is_affiliate": True,
        "enabled": True,
    },
    {
        "name": "Employment Hero",
        "short_desc": "HR and payroll platform used by growing UK teams. Combines contracts, onboarding, leave management and payroll in one system. HMRC RTI integrated.",
        "href": "https://employmenthero.com/uk/",
        "cta": "See Employment Hero",
        "is_affiliate": False,
        "enabled": True,
    },
]


@app.route("/sole-director-employer-ni")
@app.route("/sole-director-national-insurance")
@app.route("/director-employer-ni-uk")
def sole_director_ni():
    calc_12570 = calculate_employer_cost(salary=12570, pension_rate=3, overheads=0, allowance=0)
    page = {
        "badge": "Sole director · 2025/26",
        "h1": "Sole director employer NI UK (2025/26)",
        "intro": "Sole directors of their own limited company face a unique NI planning situation. Unlike most businesses, a sole director company with no other employees cannot claim Employment Allowance — meaning there is no offset against the employer NI bill. Many accountants recommend paying a director salary at or near the personal allowance (£12,570) to preserve an NI qualifying year while keeping employer NI to a minimum. At £12,570, employer NI is approximately £1,136 per year (15% above the £5,000 threshold). Above that level, dividends are typically more tax-efficient than salary for sole directors.",
        "bullets": [
            "Sole director companies with no other employees CANNOT claim Employment Allowance.",
            "Salary at £5,000 or below: zero employer NI (below the secondary threshold).",
            "Salary at £12,570 (personal allowance): employer NI ≈ £1,136/year.",
            "Salary at £50,270 (NI qualifying earnings cap): employer NI ≈ £6,791/year.",
            "Above the personal allowance, dividends typically attract less NI than salary for sole directors.",
            "Hiring a second employee (even part-time) unlocks Employment Allowance eligibility.",
        ],
        "primary_cta": {"label": "Calculate director salary employer NI", "url": "/calculator?salary=12570"},
        "secondary_cta": {"label": "Employment Allowance guide", "url": "/guides/employment-allowance-guide"},
        "faq_items": [
            {"q": "Can a sole director claim Employment Allowance?", "a": "No. A limited company where the sole director is the only employee cannot claim Employment Allowance. The rule requires at least one employee who is not also the only director. If you hire even one other employee through PAYE, the company typically becomes eligible for the full £10,500 allowance."},
            {"q": "What is the most tax-efficient director salary in 2025/26?", "a": "Many accountants recommend a director salary at the personal allowance level (£12,570), which preserves an NI qualifying year without triggering income tax. This generates approximately £1,136 in employer NI per year. Additional remuneration above this level is often more efficiently extracted as dividends, which do not attract NI."},
            {"q": "Does a sole director need auto-enrolment pension?", "a": "Directors who are the sole employee are exempt from auto-enrolment — they cannot legally enrol themselves. Once a non-director employee is hired, the company must comply with auto-enrolment obligations for that employee."},
            {"q": "How does hiring my first employee change my NI position?", "a": "Hiring your first non-director employee unlocks Employment Allowance (up to £10,500/year). If your combined employer NI bill is below £10,500 — common for directors paying themselves £12,570 with one other employee — Employment Allowance can eliminate the entire NI liability, which is one of the most significant tax-planning benefits of growing beyond a sole director structure."},
        ],
    }
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            {"page": page, "sample_calc": calc_12570, "faq_items": page["faq_items"], "tools_block": _TOOLS_BLOCK_DEFAULT},
            title="Sole Director Employer NI UK 2025/26 — Optimal Salary & Employment Allowance",
            description="Sole director employer NI guide for 2025/26. No Employment Allowance if you have no other employees. Optimal director salary of £12,570 explained. How to minimise employer NI as a sole director.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Employer NI", "url": f"{SITE_URL}/employer-ni"},
                {"name": "Sole director NI", "url": f"{SITE_URL}/sole-director-employer-ni"},
            ],
        ),
    )


@app.route("/full-time-vs-part-time-employee-cost")
@app.route("/part-time-vs-full-time-cost-uk")
def full_vs_part_time():
    rate = 15.0
    ft_salary = round(rate * 37.5 * 52)
    ft_calc = calculate_employer_cost(salary=ft_salary, pension_rate=3, overheads=0, allowance=0)
    pt20_salary = round(rate * 20 * 52)
    pt20_calc = calculate_employer_cost(salary=pt20_salary, pension_rate=3, overheads=0, allowance=0)
    pt25_salary = round(rate * 25 * 52)
    pt25_calc = calculate_employer_cost(salary=pt25_salary, pension_rate=3, overheads=0, allowance=0)
    ft_ni_pct = round(ft_calc.employer_ni.ni_due / ft_salary * 100, 1)
    pt20_ni_pct = round(pt20_calc.employer_ni.ni_due / pt20_salary * 100, 1)
    page = {
        "badge": "Full-time vs part-time",
        "h1": "Full-time vs part-time employee cost UK (2025/26)",
        "intro": f"Comparing full-time and part-time employment costs is more nuanced than it looks. At the same hourly rate (£{rate:.0f}/hour in this example), a full-time employee (37.5 hrs/week, £{ft_salary:,}/year) costs more in total — but employer NI as a percentage of salary is actually lower for full-time workers, because the £5,000 NI threshold is not pro-rated for hours. Two part-time workers at 20 hours per week do NOT share one threshold — each gets their own £5,000. This means splitting a full-time role into two part-time roles does not reduce the overall NI bill — it typically increases it.",
        "bullets": [
            f"Full-time (37.5 hrs/wk, £{rate:.0f}/hr): salary £{ft_salary:,}, employer NI £{int(ft_calc.employer_ni.ni_due):,}, pension £{int(ft_calc.pension_contribution):,}, total £{int(ft_calc.total_cost):,}.",
            f"Part-time 20 hrs/wk (£{rate:.0f}/hr): salary £{pt20_salary:,}, employer NI £{int(pt20_calc.employer_ni.ni_due):,}, pension £{int(pt20_calc.pension_contribution):,}, total £{int(pt20_calc.total_cost):,}.",
            f"Part-time 25 hrs/wk (£{rate:.0f}/hr): salary £{pt25_salary:,}, employer NI £{int(pt25_calc.employer_ni.ni_due):,}, pension £{int(pt25_calc.pension_contribution):,}, total £{int(pt25_calc.total_cost):,}.",
            "The £5,000 NI threshold is NOT pro-rated for hours — it applies in full per individual employee.",
            f"NI as a share of salary: {pt20_ni_pct}% for 20-hour worker vs {ft_ni_pct}% for full-time at same hourly rate.",
            "Two 20-hr workers generate more combined NI than one 40-hr worker at the same hourly rate.",
        ],
        "primary_cta": {"label": "Calculate employer cost for any salary", "url": "/calculator"},
        "secondary_cta": {"label": "Part-time employee cost guide", "url": "/guides/part-time-employee-cost"},
        "faq_items": [
            {"q": "Is it cheaper to employ two part-time workers instead of one full-time?", "a": f"Not on NI. Two part-time workers each get their own £5,000 threshold, and combined they generate more NI than one full-time worker at the same total hours. At £{rate:.0f}/hour, two 20-hour workers generate combined NI of approximately £{int(pt20_calc.employer_ni.ni_due * 2):,}/year versus £{int(ft_calc.employer_ni.ni_due):,} for one full-time worker. You may save on pension if part-timers earn under the £10,000 auto-enrolment trigger, and on pro-rata holiday and benefits."},
            {"q": "Is the employer NI threshold the same for part-time and full-time workers?", "a": "Yes. The £5,000 secondary threshold is fixed per employee per tax year and is not adjusted for contracted hours. This means lower-paid part-time workers have a higher NI burden as a share of salary than full-time staff at the same hourly rate."},
            {"q": "Do you pay pension on part-time staff?", "a": "Auto-enrolment is triggered for workers aged 22–66 earning more than £10,000/year. Part-time workers earning below £10,000 are not auto-enrolled but can opt in — in which case the employer must contribute at 3% of qualifying earnings. Workers earning between £6,240 and £10,000 are entitled to opt in."},
        ],
    }
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            {"page": page, "sample_calc": ft_calc, "faq_items": page["faq_items"], "tools_block": _TOOLS_BLOCK_DEFAULT},
            title="Full-time vs Part-time Employee Cost UK (2025/26) — NI, Pension & True Total",
            description="Compare full-time vs part-time employee costs in the UK for 2025/26. The NI threshold isn't pro-rated for hours — see how this affects employer cost at the same hourly rate.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Scenarios", "url": f"{SITE_URL}/cost-of-hiring"},
                {"name": "Full-time vs part-time", "url": f"{SITE_URL}/full-time-vs-part-time-employee-cost"},
            ],
        ),
    )


@app.route("/team-cost-planner")
@app.route("/team-payroll-calculator")
@app.route("/payroll-cost-calculator-multiple-employees")
def team_cost_planner():
    return render_template(
        "team_cost_planner.html",
        **with_meta(
            {"tools_block": _TOOLS_BLOCK_DEFAULT},
            title="Team Payroll Cost Planner UK 2025/26 — Model Multiple Employees",
            description="Plan total payroll costs for your whole team. Add multiple employees, set individual salaries and pension rates, and calculate total employer NI, pension and overhead burden for 2025/26. Includes Employment Allowance.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Calculators", "url": f"{SITE_URL}/calculators"},
                {"name": "Team cost planner", "url": f"{SITE_URL}/team-cost-planner"},
            ],
        ),
    )


@app.route("/xero-vs-sage-payroll")
@app.route("/xero-vs-sage-payroll-uk")
def xero_vs_sage():
    comparisons = [
        {"feature": "Monthly price (1–5 staff)", "xero": "From £7/mo (Starter plan)", "sage": "From £8/mo (Sage Payroll Essential)"},
        {"feature": "Monthly price (10+ staff)", "xero": "£15–£29/mo (Standard/Premium)", "sage": "£18–£36/mo depending on employees"},
        {"feature": "Free trial", "xero": "30 days", "sage": "3 months free (promotional)"},
        {"feature": "HMRC RTI submissions", "xero": "Yes", "sage": "Yes"},
        {"feature": "Auto-enrolment pension", "xero": "Yes (NEST, The Peoples Pension etc.)", "sage": "Yes (NEST, multiple providers)"},
        {"feature": "Accounting integration", "xero": "Native (Xero accounting)", "sage": "Native (Sage Accounting)"},
        {"feature": "Self-service employee portal", "xero": "Yes (via Xero Me app)", "sage": "Yes (Sage Employee Self Service)"},
        {"feature": "Payslip distribution", "xero": "Email / app", "sage": "Email / portal"},
        {"feature": "CIS subcontractor support", "xero": "Yes", "sage": "Yes"},
        {"feature": "Multi-company payroll", "xero": "Separate Xero account per company", "sage": "Yes (Sage 50 Payroll)"},
    ]
    page = {
        "badge": "Software comparison",
        "h1": "Xero vs Sage Payroll UK (2025/26)",
        "intro": "Xero and Sage are two of the most widely used payroll software platforms for UK small and medium businesses. Both handle HMRC RTI submissions, auto-enrolment pension, and PAYE calculations. The main differences are in ecosystem (Xero suits businesses already using Xero accounting; Sage suits those already on Sage), pricing structure, and the level of payroll complexity each handles out of the box. Xero Payroll is generally preferred for businesses wanting a modern, app-driven experience. Sage is often preferred by accountants and larger businesses needing more granular payroll controls or CIS management.",
        "bullets": [
            "Both handle HMRC RTI, auto-enrolment pension, PAYE, NI and CIS (Construction Industry Scheme).",
            "Xero Payroll is bundled with Xero accounting — best for businesses already using Xero for bookkeeping.",
            "Sage Payroll (including Sage 50 Payroll) has more feature depth for complex payroll — preferred by many UK accountants.",
            "Xero pricing is subscription-based (from ~£7/mo). Sage pricing varies by employee count.",
            "Both integrate with major pension providers including NEST, The Peoples Pension, and Smart Pension.",
            "Neither calculates employer NI for you at offer stage — use the employer cost calculator first.",
        ],
        "primary_cta": {"label": "Calculate employer cost before choosing software", "url": "/calculator"},
        "secondary_cta": {"label": "Compare all payroll software", "url": "/payroll-software-uk"},
        "faq_items": [
            {"q": "Is Xero or Sage better for payroll in the UK?", "a": "It depends on your existing accounting software and business complexity. Xero Payroll is the better choice if you already use Xero for accounting — the integration is seamless and the app experience is modern. Sage is often preferred by accountants and businesses needing more detailed payroll reporting, cost centre coding, or CIS subcontractor management. For businesses with fewer than 10 employees looking for simplicity, Xero is generally easier to use."},
            {"q": "Can I run payroll on Xero without having Xero accounting?", "a": "Technically yes — Xero Payroll can be run without the full Xero accounting subscription, but it is designed to work best within the Xero ecosystem. If you use a different accounting platform (QuickBooks, Sage Accounting, Xero), you would typically use that provider's payroll module to avoid manual journal entries."},
            {"q": "Does Sage or Xero support Employment Allowance?", "a": "Both Sage and Xero support Employment Allowance for eligible employers. You declare eligibility in the payroll settings and the software automatically offsets employer NI against the £10,500 annual allowance across the year. Both systems flag when the allowance is exhausted."},
        ],
    }
    page = _apply_year_deep(page)
    calc = calculate_employer_cost(salary=35000, pension_rate=3, overheads=0, allowance=0)
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            {"page": page, "sample_calc": calc, "faq_items": page["faq_items"], "comparison_rows": comparisons, "tools_block": _TOOLS_BLOCK_DEFAULT},
            title="Xero vs Sage Payroll UK (2025/26) — Which Is Best for Your Business?",
            description="Xero vs Sage Payroll UK comparison. Both handle HMRC RTI, auto-enrolment and PAYE. See pricing, features and which suits your business for 2025/26 payroll.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Payroll software", "url": f"{SITE_URL}/payroll-software-uk"},
                {"name": "Xero vs Sage", "url": f"{SITE_URL}/xero-vs-sage-payroll"},
            ],
        ),
    )


@app.route("/xero-vs-quickbooks-payroll")
@app.route("/xero-vs-quickbooks-uk")
def xero_vs_quickbooks():
    comparisons = [
        {"feature": "Monthly price (1–5 staff)", "xero": "From £7/mo (Starter)", "qb": "From £6/mo (Simple Start with Payroll)"},
        {"feature": "Monthly price (10+ staff)", "xero": "£15–£29/mo", "qb": "£22–£35/mo depending on plan"},
        {"feature": "Free trial", "xero": "30 days", "qb": "30 days"},
        {"feature": "HMRC RTI", "xero": "Yes", "qb": "Yes"},
        {"feature": "Auto-enrolment pension", "xero": "Yes", "qb": "Yes"},
        {"feature": "Accounting integration", "xero": "Native (Xero)", "qb": "Native (QuickBooks)"},
        {"feature": "Payslip distribution", "xero": "Email / Xero Me app", "qb": "Email / QuickBooks portal"},
        {"feature": "CIS support", "xero": "Yes", "qb": "Yes (QuickBooks Payroll Advanced)"},
        {"feature": "Pensions provider integration", "xero": "NEST, Peoples Pension, Smart Pension", "qb": "NEST, Peoples Pension"},
        {"feature": "Best for", "xero": "Xero accounting users, app-first teams", "qb": "QuickBooks accounting users, US-headquartered businesses"},
    ]
    page = {
        "badge": "Software comparison",
        "h1": "Xero vs QuickBooks Payroll UK (2025/26)",
        "intro": "Xero and QuickBooks are the two dominant cloud accounting and payroll platforms for UK small businesses. Both handle HMRC RTI submissions, auto-enrolment pension, and PAYE. The choice usually comes down to which accounting platform you already use: if you run your books on Xero, use Xero Payroll; if you are on QuickBooks, use QuickBooks Payroll. Switching accounting platforms to use a different payroll system is generally not worth the disruption for most small businesses.",
        "bullets": [
            "Both handle HMRC RTI, PAYE, NI, auto-enrolment pension and payslip distribution.",
            "Xero Payroll integrates natively with Xero accounting — journal entries post automatically.",
            "QuickBooks Payroll integrates natively with QuickBooks — preferred by QuickBooks accounting users.",
            "Both are cloud-based and accessible from any device — no desktop software required.",
            "Both integrate with NEST and The Peoples Pension for auto-enrolment.",
            "Neither replaces calculating your employer cost at offer stage — do that first at /calculator.",
        ],
        "primary_cta": {"label": "Calculate employer cost before choosing software", "url": "/calculator"},
        "secondary_cta": {"label": "Compare all payroll software", "url": "/payroll-software-uk"},
        "faq_items": [
            {"q": "Is Xero or QuickBooks better for payroll in the UK?", "a": "For most small UK businesses, the better choice is whichever accounting platform you already use. Xero Payroll is better if you run your accounts on Xero — the native integration means payroll journals post automatically. QuickBooks Payroll is better if you are already on QuickBooks. Both provide HMRC-compliant payroll for UK businesses, and the day-to-day functionality is similar for businesses with under 20 employees."},
            {"q": "Can I use Xero Payroll without Xero accounting?", "a": "Xero Payroll can technically be purchased without the full Xero accounting subscription, but most of its value comes from the native accounting integration. Running payroll on Xero while using a different bookkeeping tool would require manual journal entries, which eliminates the main efficiency benefit."},
            {"q": "Which is cheaper — Xero or QuickBooks payroll?", "a": "Pricing is comparable at small headcounts. QuickBooks has marginally lower entry pricing for micro-businesses, while Xero may be slightly cheaper at 10–20 employee headcounts depending on the plan. Both offer promotional pricing and free trials. Compare current pricing on each provider's website, as rates change frequently."},
        ],
    }
    page = _apply_year_deep(page)
    calc = calculate_employer_cost(salary=35000, pension_rate=3, overheads=0, allowance=0)
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            {"page": page, "sample_calc": calc, "faq_items": page["faq_items"], "comparison_rows": comparisons, "tools_block": _TOOLS_BLOCK_DEFAULT},
            title="Xero vs QuickBooks Payroll UK (2025/26) — Which Is Right for Your Business?",
            description="Xero vs QuickBooks Payroll UK. Both handle HMRC RTI, auto-enrolment and PAYE. Choose based on your accounting platform. Full 2025/26 comparison with pricing and features.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Payroll software", "url": f"{SITE_URL}/payroll-software-uk"},
                {"name": "Xero vs QuickBooks", "url": f"{SITE_URL}/xero-vs-quickbooks-payroll"},
            ],
        ),
    )


@app.route("/best-payroll-software-1-employee")
@app.route("/best-payroll-software-one-employee")
@app.route("/payroll-software-for-1-employee-uk")
def payroll_1_employee():
    page = {
        "badge": "Single employee payroll",
        "h1": "Best payroll software for 1 employee UK (2025/26)",
        "intro": "Running payroll for a single employee in the UK requires HMRC RTI submissions, PAYE calculations, auto-enrolment pension handling, and payslip generation. You have three main options: HMRC's free Basic PAYE Tools (functional but limited), a low-cost cloud payroll platform like Xero, QuickBooks or FreeAgent, or a standalone payroll-specific tool like Sage Payroll. For a single employee, HMRC Basic PAYE Tools is free and HMRC-compliant, but most small business owners prefer paid software for its payslip quality, pension provider integration, and accountant access.",
        "bullets": [
            "HMRC Basic PAYE Tools: free, HMRC-compliant, handles RTI — but limited payslips, no pension auto-enrolment integration.",
            "Xero Payroll (Starter): from ~£7/mo — best for Xero accounting users, includes app-based payslips and NEST integration.",
            "QuickBooks Payroll: from ~£6/mo — best for QuickBooks accounting users, full HMRC RTI and pension support.",
            "FreeAgent: from £3.50/mo (NatWest/RBS customers may get free access) — good for freelancers and micro-businesses.",
            "All paid options include auto-enrolment pension handling — critical once your employee earns above £10,000/year.",
            "Your first employee's total cost is more than just salary — see the employer cost calculator before making offers.",
        ],
        "primary_cta": {"label": "Calculate total cost of your first employee", "url": "/first-employee-cost-uk"},
        "secondary_cta": {"label": "Compare all payroll software", "url": "/payroll-software-uk"},
        "faq_items": [
            {"q": "Do I need payroll software for one employee?", "a": "You are not required to use commercial payroll software — HMRC's free Basic PAYE Tools handles RTI submissions for up to 9 employees. However, most employers with even one employee find that a paid cloud platform (Xero, QuickBooks, FreeAgent) is worth the monthly cost for better payslips, automatic pension provider integration, and accountant-friendly access. From around £6–£7 per month for a single employee, the administrative benefit usually outweighs the cost."},
            {"q": "Does my single employee need auto-enrolment pension?", "a": "Yes, if they are aged 22–66 and earn more than £10,000 per year. You are legally required to automatically enrol them into a qualifying pension scheme and contribute at least 3% of their qualifying earnings (between £6,240 and £50,270). HMRC Basic PAYE Tools does not manage pension provider submissions — paid payroll software handles this automatically."},
            {"q": "What does it cost to employ one person in the UK?", "a": "Beyond the salary, you pay employer NI (15% on earnings above £5,000 in 2025/26) and minimum pension (3% on qualifying earnings). At a £30,000 salary, the total employer cost is approximately £34,464 per year — £4,464 above headline salary. Use the employer cost calculator for any specific salary."},
        ],
    }
    page = _apply_year_deep(page)
    calc = calculate_employer_cost(salary=30000, pension_rate=3, overheads=0, allowance=10500)
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            {"page": page, "sample_calc": calc, "faq_items": page["faq_items"], "tools_block": _TOOLS_BLOCK_DEFAULT},
            title="Best Payroll Software for 1 Employee UK (2025/26) — Free and Paid Options",
            description="Best payroll software for one employee in the UK. HMRC Basic PAYE Tools (free) vs Xero, QuickBooks and FreeAgent. RTI, pension, payslips — what you need for a single employee.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Payroll software", "url": f"{SITE_URL}/payroll-software-uk"},
                {"name": "Best for 1 employee", "url": f"{SITE_URL}/best-payroll-software-1-employee"},
            ],
        ),
    )


@app.route("/apprenticeship-levy-calculator")
@app.route("/apprenticeship-levy-uk")
@app.route("/how-to-calculate-apprenticeship-levy")
def apprenticeship_levy():
    # Worked examples at common payroll sizes
    examples = []
    for annual_payroll in [2500000, 5000000, 10000000, 25000000]:
        levy_due = max(0, annual_payroll * 0.005 - 15000)
        monthly = round(levy_due / 12)
        examples.append({
            "payroll": annual_payroll,
            "levy_gross": round(annual_payroll * 0.005),
            "allowance": 15000,
            "levy_due": round(levy_due),
            "monthly": monthly,
        })
    page = {
        "badge": "Apprenticeship Levy · 2025/26",
        "h1": "Apprenticeship Levy calculator UK (2025/26)",
        "intro": "The Apprenticeship Levy applies to UK employers with an annual wage bill above £3 million. The levy rate is 0.5% of total annual payroll, with a £15,000 annual allowance that effectively sets the threshold at £3 million. Employers below £3 million pay nothing. Above that level, the levy is paid monthly through PAYE alongside employer NI. The funds paid into the Digital Apprenticeship Service (DAS) account can only be used to fund apprenticeship training and assessment — they cannot be withdrawn as cash. Use the calculator below to estimate your levy liability at any payroll level.",
        "bullets": [
            "Levy rate: 0.5% of total annual wage bill above the £15,000 allowance.",
            "Threshold: businesses with annual payroll above £3 million pay the levy.",
            "Allowance: all employers receive a £15,000 annual allowance (£1,250/month).",
            "At £3m payroll: levy due = (£3,000,000 × 0.5%) − £15,000 = £0.",
            "At £5m payroll: levy due = (£5,000,000 × 0.5%) − £15,000 = £10,000/year.",
            "At £10m payroll: levy due = (£10,000,000 × 0.5%) − £15,000 = £35,000/year.",
            "Funds expire: unspent DAS funds expire 24 months after entering the account.",
        ],
        "primary_cta": {"label": "Calculate employer NI and payroll cost", "url": "/calculator"},
        "secondary_cta": {"label": "Team payroll cost planner", "url": "/team-cost-planner"},
        "faq_items": [
            {"q": "What is the Apprenticeship Levy?", "a": "The Apprenticeship Levy is a payroll tax applied to UK employers with an annual wage bill above £3 million. It is charged at 0.5% of the total wage bill above a £15,000 annual allowance. The funds are paid into a Digital Apprenticeship Service (DAS) account and can only be used to pay for apprenticeship training and End-Point Assessment. Businesses that do not use their levy funds lose them after 24 months."},
            {"q": "Who has to pay the Apprenticeship Levy?", "a": "All UK employers with a total annual wage bill above approximately £3 million. This includes all sectors — public sector organisations (including NHS trusts, local authorities, and universities) pay the levy as well as private sector businesses. Employers can check their liability by multiplying total annual payroll by 0.5% and subtracting the £15,000 allowance."},
            {"q": "Can I transfer my Apprenticeship Levy funds to other businesses?", "a": "Yes. Since 2019, levy-paying employers can transfer up to 25% of their annual levy funds to other employers, including smaller businesses in their supply chain. From April 2024, the transfer limit increased to 50%. This allows large employers to support apprenticeship training in their supply chain or among smaller partner businesses."},
            {"q": "What happens to unused Apprenticeship Levy funds?", "a": "Unspent levy funds expire 24 months after they entered your DAS account. If you pay levy but do not use it to fund apprenticeship training, the funds are effectively forfeited. Employers with large DAS balances and no apprenticeship programme should either start one or use levy transfer to support other employers."},
            {"q": "Does the Apprenticeship Levy apply to part-time employees?", "a": "Yes. The levy is calculated on total annual wage bill — the sum of all employee gross wages including part-time, full-time, and any taxable benefits in kind. There is no adjustment or exclusion for part-time workers. The calculation is straightforward: total gross wage bill × 0.5% − £15,000 = annual levy due."},
        ],
    }
    page = _apply_year_deep(page)
    calc = calculate_employer_cost(salary=35000, pension_rate=3, overheads=0, allowance=0)
    return render_template(
        "intent_landing_page.html",
        **with_meta(
            {"page": page, "sample_calc": calc, "faq_items": page["faq_items"], "levy_examples": examples, "tools_block": _TOOLS_BLOCK_DEFAULT},
            title="Apprenticeship Levy Calculator UK 2025/26 — 0.5% Above £3m Payroll",
            description="Calculate Apprenticeship Levy liability for 2025/26. Rate: 0.5% on payroll above £3m (£15,000 annual allowance). Monthly levy amounts for £3m–£25m payrolls. UK employers explained.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Calculators", "url": f"{SITE_URL}/calculators"},
                {"name": "Apprenticeship Levy", "url": f"{SITE_URL}/apprenticeship-levy-calculator"},
            ],
        ),
    )


@app.route("/<path:slug>")
def fallback_tools(slug: str):
    if slug.endswith("-calculator"):
        ctx = with_meta(
            {
                "page": {
                    "title": slug.replace("-", " ").title(),
                    "description": "Calculator page",
                    "content": [
                        "This calculator is coming soon. In the meantime, use the full employer cost calculator for live 2025/26 outputs.",
                        "You can calculate employer NI, pension and total hiring cost for any UK salary using the calculator below.",
                    ],
                },
                "slug": slug,
                "meta_robots": "noindex,follow",
            },
            title=f"{slug.replace('-', ' ').title()} | EmployerCalculator.co.uk",
            description="Employer calculator page.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Calculators", "url": f"{SITE_URL}/calculators"},
            ],
        )
        return render_template("static_page.html", **ctx)
    abort(404)


@app.errorhandler(404)
def page_not_found(e):
    context = {}
    return render_template(
        "404.html",
        **with_meta(
            context,
            title="Page not found | EmployerCalculator.co.uk",
            description="The page you are looking for does not exist. Try the employer NI calculator or browse all tools.",
            breadcrumbs=[{"name": "Home", "url": f"{SITE_URL}/"}],
        ),
    ), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), debug=False)
