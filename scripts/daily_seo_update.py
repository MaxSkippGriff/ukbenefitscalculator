#!/usr/bin/env python3
"""
Daily SEO update script for EmployerCalculator.
Generates new short HR/employer cost guides and adds them as JSON.
Never touches main.py logic — only writes to data/seo_extras.json.
"""

import json
import os
import re
import sys
from datetime import date

from openai import OpenAI

CLIENT = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
EXTRAS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "seo_extras.json")

SYSTEM = """You write SEO content for EmployerCalculator.co.uk, a UK employer cost and payroll calculator
used by small business owners, HR teams, and accountants.

Write like a senior payroll professional who knows HMRC rules cold. Not like an AI assistant.
Banned phrases: "in today's dynamic environment", "streamline your processes", "leverage", "robust",
"empower your workforce", "best practices", "key takeaways". Never pad. Never start with "Understanding X is crucial".

You must cite real, current UK figures. For 2025/26:
- Employer NI: 15% above secondary threshold of £5,000/year (up from 13.8%/£9,100 before April 2025)
- Employment Allowance: £10,500/year (up from £5,000) — for employers with a NI bill under £100,000
- National Living Wage: £12.21/hour (25+), £10.00 (18-20), £7.55 (16-17), £7.55 (apprentices)
- Auto-enrolment minimum: 8% total (3% employer, 5% employee) on qualifying earnings £6,240–£50,270
- Statutory Sick Pay: £116.75/week for up to 28 weeks
- Statutory Maternity Pay: 90% for 6 weeks, then £184.03 or 90% (lower) for 33 weeks
- Redundancy pay: 0.5 week's pay/year (under 22), 1 week (22-40), 1.5 weeks (41+), cap £700/week
- P11D: benefits reported annually by 6 July; Class 1A NI at 13.8% (15% from April 2025) due 19 July

Reference real legislation: Employment Rights Act 1996/2025, Finance Act 2024, PAYE regulations 2003,
Working Time Regulations 1998, Transfer of Undertakings (Protection of Employment) Regulations 2006.

A guide is strong if: the first sentence gives a specific pound figure or %, a worked example is included,
and the reader can act on it without looking anything else up.

Always respond with valid JSON only — no markdown, no commentary."""

GUIDE_PROMPT = """Generate a new short guide for EmployerCalculator.co.uk.
Choose a topic with real search volume that isn't covered by these existing guide slugs:

{existing_slugs}

Today's date: {today}

Good topics: employer NI on benefits in kind, P11D deadlines and penalties, salary sacrifice pension
calculations, IR35 off-payroll rules for small businesses, apprenticeship levy threshold and spending,
TUPE transfer obligations, settlement agreements and tax, rolling up holiday pay (illegal), zero-hours
worker rights post-2025 Employment Rights Act, statutory redundancy worked examples, childcare vouchers
vs tax-free childcare comparison, payrolling of benefits, car benefit percentages and CO2 bands,
season ticket loans, cycle to work scheme limits.

Return a JSON object with exactly:
{{
  "slug": "kebab-case-url-slug",
  "title": "Guide title (under 60 chars, include a specific rate or rule)",
  "description": "Meta description (under 155 chars, must include a specific pound/percentage figure)",
  "topic": "Short label (e.g. 'Employer NI', 'P11D', 'Holiday Pay')",
  "sections": [
    {{
      "heading": "Section 1 heading (specific, not 'Introduction')",
      "paragraphs": [
        "Opening sentence with a specific figure. 2-3 sentences explaining the rule with a worked example.",
        "Optional second para — edge case or exception worth knowing."
      ]
    }},
    {{
      "heading": "Section 2 heading",
      "paragraphs": [
        "2-3 sentences with a calculation or deadline.",
        "Optional para."
      ]
    }},
    {{
      "heading": "Section 3 heading",
      "paragraphs": [
        "Practical tip or common mistake. 2-3 sentences."
      ]
    }}
  ],
  "faq": [
    {{"q": "Specific question an employer would Google?", "a": "Direct answer with a figure. 2 sentences."}},
    {{"q": "Second question?", "a": "Direct answer."}},
    {{"q": "Third question?", "a": "Direct answer."}}
  ]
}}"""


def load_extras():
    with open(EXTRAS_FILE) as f:
        return json.load(f)


def save_extras(data):
    with open(EXTRAS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def call_claude(prompt: str) -> str:
    response = CLIENT.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=4000,
        messages=[
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content.strip()


def extract_json(text: str):
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
    return json.loads(text.strip())


def validate_guide(guide: dict) -> bool:
    required = {"slug", "title", "description", "topic", "sections"}
    if not required.issubset(guide.keys()):
        return False
    if not isinstance(guide["sections"], list) or len(guide["sections"]) < 2:
        return False
    for section in guide["sections"]:
        if "heading" not in section or "paragraphs" not in section:
            return False
    if len(guide["title"]) > 70 or len(guide["description"]) > 165:
        return False
    return True


# Core GUIDES slugs from main.py (hardcoded to avoid importing the whole app)
EXISTING_CORE_SLUGS = [
    "employer-ni-changes-2025",
    "employer-ni-budget-october-2024",
    "employment-allowance-2025",
    "holiday-pay-calculation-guide",
]


def main():
    print(f"EmployerCalculator daily SEO update — {date.today()}")
    extras = load_extras()

    if "guides" not in extras:
        extras["guides"] = {}
    if "_log" not in extras:
        extras["_log"] = []

    all_slugs = EXISTING_CORE_SLUGS + list(extras["guides"].keys())

    print("\nGenerating new guide...")
    try:
        raw = call_claude(GUIDE_PROMPT.format(
            existing_slugs="\n".join(all_slugs),
            today=date.today().isoformat(),
        ))
        guide = extract_json(raw)

        if not validate_guide(guide):
            print(f"Guide validation failed: {guide.get('slug', '?')}")
            sys.exit(1)

        if guide["slug"] in all_slugs:
            print(f"Duplicate slug: {guide['slug']} — skipping")
            sys.exit(1)

        extras["guides"][guide["slug"]] = guide
        print(f"  + Added guide: {guide['slug']} — {guide['title']}")

    except Exception as e:
        print(f"Error generating guide: {e}")
        sys.exit(1)

    extras["_log"].append({
        "date": date.today().isoformat(),
        "guide_added": guide["slug"],
    })
    extras["_log"] = extras["_log"][-60:]

    save_extras(extras)
    print(f"\n✓ Done. Total extra guides: {len(extras['guides'])}")


if __name__ == "__main__":
    main()
