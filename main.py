"""EmployerCalculator.co.uk Flask application."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Dict, List

from dotenv import load_dotenv
from flask import Flask, abort, make_response, redirect, render_template, request, send_from_directory, url_for

from calculator import (
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
    38000, 39000, 40000, 42000, 44000, 45000, 46000, 48000, 50000, 52000,
    55000, 58000, 60000, 65000, 70000, 75000, 80000, 85000, 90000, 95000,
    100000, 110000, 120000, 130000, 140000, 150000, 175000, 200000,
]

TOOL_CARDS = [
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
]

GUIDES: Dict[str, Dict] = {
    "employer-ni-changes-2025": {
        "title": "Employer NI increase April 2025: what changed and what it costs",
        "description": "Employer NI 2025/26 explained: rate rise to 15%, threshold cut to £5,000, and practical cost impact by salary band with worked examples.",
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
        "title": "Auto-enrolment pension costs for employers explained (2025/26)",
        "description": "How employer pension contributions are calculated, what qualifying earnings mean in practice, and how to budget accurately for auto-enrolment costs in 2025/26.",
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
        "title": "Redundancy process and costs: employer guide",
        "description": "A practical employer guide to redundancy process, statutory pay, notice and risk control.",
        "topic": "Redundancy",
        "sections": [
            {
                "heading": "Process discipline matters",
                "paragraphs": [
                    "Redundancy planning should start with role rationale, selection methodology and a consultation timetable. Documentation quality is as important as arithmetic.",
                    "Cost modelling should include statutory redundancy pay, notice pay, accrued holiday, pension interactions and professional support where needed.",
                    "A rushed process can create legal exposure that exceeds the direct payroll savings sought by the exercise.",
                ],
            },
            {
                "heading": "Core cost components",
                "paragraphs": [
                    "The baseline cost usually includes statutory redundancy entitlement for eligible employees, plus notice obligations under statute or contract.",
                    "Employers may also need to account for payment in lieu of notice, untaken holiday, and any agreed enhanced terms.",
                    "Treat these as scenario ranges during planning. Actual outcomes depend on service length, contracts, consultation outcomes and settlement choices.",
                ],
            },
            {
                "heading": "Reducing operational risk",
                "paragraphs": [
                    "Use a checklist covering consultation records, role pooling decisions, scoring evidence and communications history.",
                    "Ensure managers are briefed before meetings. Inconsistent messaging can weaken process integrity.",
                    "Where uncertainty is high, take legal advice early. Calculator outputs are useful for planning but are not substitutes for legal review.",
                ],
            },
        ],
    },
    "employment-rights-act-2025": {
        "title": "Employment Rights Act 2025: what employers need to know",
        "description": "Operational implications of Employment Rights Act 2025 reforms for UK employers.",
        "topic": "Legislation",
        "sections": [
            {
                "heading": "Why this matters for employers",
                "paragraphs": [
                    "Employment law reforms alter hiring, contracts, probation management and dismissal risk. For employers, implementation readiness is usually a process challenge rather than a single policy update.",
                    "Leadership teams should separate confirmed commencement dates from proposals and consultation items. Planning against unconfirmed assumptions can waste effort.",
                    "Maintain a dated change log and policy register so operational teams can see what has changed, when, and why.",
                ],
            },
            {
                "heading": "Practical implementation approach",
                "paragraphs": [
                    "Start with a gap review: contracts, handbooks, manager training and grievance workflows. Prioritise high-impact workflows such as recruitment, probation, and disciplinary steps.",
                    "Update template documentation centrally and set one deployment date for all managers. Fragmented rollout increases inconsistency and risk.",
                    "Track compliance ownership by function. HR, payroll, legal and line management each hold different controls.",
                ],
            },
            {
                "heading": "Cost and workforce planning impact",
                "paragraphs": [
                    "Some reforms increase administration time per employee lifecycle event. Budget should include that overhead, not just direct pay.",
                    "When policy changes interact with payroll rules, review calculators and manager guidance together. Out-of-date tools create avoidable mistakes.",
                    "For strategic planning, combine legal-risk controls with clear cost models. This allows faster decision-making when hiring demand changes.",
                ],
            },
        ],
    },
}

STATIC_PAGES = {
    "methodology": {
        "title": "Methodology",
        "description": "How EmployerCalculator.co.uk calculations are performed and updated.",
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
        "title": "Sources",
        "description": "Official UK sources used for EmployerCalculator calculations and guidance.",
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
        "title": "Employer Total Cost Calculator UK (2025/26) | EmployerCalculator.co.uk",
        "description": "Employer total cost calculator UK page for 2025/26. Calculate salary, employer NI, pension and overhead impact with monthly and annual totals.",
        "h1": "Employer total cost calculator (UK, 2025/26)",
        "badge": "Calculator intent",
        "intro": "Use this employer total cost calculator UK page when you need the full annual and monthly cost of one employee. It combines gross salary, employer NI at 15%, auto-enrolment pension, Employment Allowance impact, and optional overhead assumptions.",
        "bullets": [
            "Model the true cost above headline salary for UK hiring decisions.",
            "Switch between minimum pension assumptions and your internal overhead baseline.",
            "Use the live calculator for any salary, not just preset examples.",
        ],
        "primary_cta": {"label": "Open full employer total cost calculator", "url": "/calculator"},
        "faq_items": [
            {"q": "What does total employer cost include?", "a": "Total employer cost includes gross salary, employer NI, employer pension, and any per-employee overhead assumptions such as equipment or software."},
            {"q": "Is this UK-specific?", "a": "Yes. This page and calculator use UK 2025/26 assumptions, including employer NI at 15% above the £5,000 secondary threshold and auto-enrolment pension minimums."},
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
        "title": "NI Change Calculator (Employer, 2025/26) | EmployerCalculator.co.uk",
        "description": "NI change calculator for employers. Compare 2025/26 employer NI outcomes with pre-April 2025 assumptions and view cost impact by salary.",
        "h1": "NI change calculator for UK employers",
        "badge": "NI change intent",
        "intro": "This NI change calculator intent page explains and quantifies the employer NI rule changes effective from 6 April 2025: rate increase to 15% and secondary threshold reduction to £5,000.",
        "bullets": [
            "Compare 2025/26 employer NI against 2024/25 assumptions.",
            "See why threshold reduction and rate increase compound total cost.",
            "Use role-by-role modelling instead of single average salary assumptions.",
        ],
        "primary_cta": {"label": "Run NI change comparison", "url": "/calculator"},
        "faq_items": [
            {"q": "What changed in April 2025 for employer NI?", "a": "Employer NI rose from 13.8% to 15%, and the secondary threshold fell from £9,100 to £5,000, both effective from 6 April 2025."},
            {"q": "Does Employment Allowance remove the NI increase?", "a": "It can offset part or all of employer NI for eligible smaller employers, but it does not change the underlying NI rate or threshold rules."},
        ],
    },
    "/employer-ni-calculator-2025-26": {
        "title": "Employer NI Calculator 2025/26 | EmployerCalculator.co.uk",
        "description": "Employer NI calculator 2025/26 page for UK payroll planning. Check employer NI due, allowance impact and full employer cost links.",
        "h1": "Employer NI calculator 2025/26 (UK)",
        "badge": "NI intent",
        "intro": "Use this employer NI calculator 2025/26 page for employer-side National Insurance estimates and quick access to salary-by-salary NI and total-cost calculators.",
        "bullets": [
            "Apply 15% employer NI above the £5,000 secondary threshold.",
            "Model with or without Employment Allowance where relevant.",
            "Move from NI-only estimate to full cost including pension and overheads.",
        ],
        "primary_cta": {"label": "Open employer NI calculator", "url": "/calculator"},
        "faq_items": [
            {"q": "Is this only for employer NI?", "a": "This page is NI-focused, but links to the full employer cost calculator so you can include pension and overhead assumptions."},
            {"q": "Is there an upper cap on employer NI?", "a": "No. Employer NI is charged at 15% above threshold with no upper earnings cap under standard rules."},
        ],
    },
}


def gbp(value: float) -> str:
    return f"£{value:,.0f}"


def pct(value: float) -> str:
    return f"{value:.1f}%"


def request_path() -> str:
    return request.path if request.path.startswith("/") else "/"


def with_meta(context: Dict, title: str, description: str, breadcrumbs: List[Dict]) -> Dict:
    canonical = f"{SITE_URL}{request_path()}"
    context.update(
        {
            "title": title,
            "meta_description": description,
            "canonical_url": canonical,
            "site_url": SITE_URL,
            "canonical_host": CANONICAL_HOST,
            "ga_measurement_id": GA_MEASUREMENT_ID,
            "breadcrumbs": breadcrumbs,
            "tax_year": TAX_YEAR,
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
    }
    return render_template(
        "landing.html",
        **with_meta(
            context,
            title="Employer Cost Calculator UK (2025/26) — Employer NI & Total Cost",
            description="Employer cost calculator UK for 2025/26. Calculate employer NI at 15%, pension and total cost to employer with monthly and annual breakdowns.",
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
    }
    return render_template(
        "calculator.html",
        **with_meta(
            context,
            title="Employer Total Cost Calculator UK (2025/26) — Salary, NI, Pension & Overheads",
            description="Total cost to employer calculator UK for 2025/26. Model salary, employer NI, auto-enrolment pension and overheads with NI change comparison versus 2024/25.",
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
            title=f"Cost of Employing Someone on £{amount:,} (2025/26) — NI, Pension & Total",
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
    }

    return render_template(
        "employer_ni_page.html",
        **with_meta(
            context,
            title=f"Employer NI on £{amount:,} Salary (2025/26) — National Insurance Calculation",
            description=f"Employer National Insurance on a £{amount:,} salary is {gbp(ni_current.gross_ni)} per year in 2025/26 ({gbp(monthly(ni_current.gross_ni))} per month). Calculated at 15% above the £5,000 threshold. Includes 2024/25 comparison.",
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
            title="Employer guides for UK payroll and HR costs (2025/26)",
            description="Practical guides for UK employers on employer NI, hiring costs, Employment Allowance, pensions and redundancy planning.",
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
    context = {
        "guide": guide,
        "slug": slug,
        "related_guides": related,
        "faq_items": default_faq(),
        "show_cross_links": True,
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
        ],
    }
    return render_template(
        "employer_ni_index.html",
        **with_meta(
            context,
            title="Employer NI Calculator UK (2025/26) by Salary — Monthly & Annual NI",
            description="Employer NI calculator UK for 2025/26. Check annual and monthly NI at 15% above £5,000 and compare directly with 2024/25 assumptions.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Employer NI by salary", "url": f"{SITE_URL}/employer-ni"},
            ],
        ),
    )


@app.route("/cost-of-employing")
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
            title="Total Cost to Employer Calculator UK (2025/26) by Salary",
            description="Total cost to employer calculator UK pages for 2025/26. See salary, employer NI, pension and monthly total employer cost by salary band.",
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
            title="Contact",
            description="Contact details for EmployerCalculator.co.uk.",
            breadcrumbs=[
                {"name": "Home", "url": f"{SITE_URL}/"},
                {"name": "Contact", "url": f"{SITE_URL}/contact"},
            ],
        ),
    )


@app.route("/methodology")
@app.route("/editorial-standards")
@app.route("/sources")
@app.route("/about")
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


@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Allow: /\n"
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
        f"Sitemap: {SITE_URL}/sitemap.xml\n"
    )
    response = make_response(body)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response


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
        (f"{SITE_URL}/cost-of-employing", "0.8", "weekly"),
        (f"{SITE_URL}/employer-ni", "0.8", "weekly"),
        (f"{SITE_URL}/guides", "0.8", "weekly"),
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
    return {"status": "ok", "site": "employercalculator", "tax_year": TAX_YEAR}


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
