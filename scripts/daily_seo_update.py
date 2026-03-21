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

import anthropic

CLIENT = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
EXTRAS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "seo_extras.json")

SYSTEM = """You are an SEO content writer for EmployerCalculator.co.uk, a UK employer cost calculator.
Write expert, concise content about UK employer costs, HR compliance, and employment law.
UK English. Be specific with HMRC rates, thresholds, and legislation references.
Always respond with valid JSON only — no markdown, no commentary."""

GUIDE_PROMPT = """Generate a new short guide for EmployerCalculator.co.uk about one of these UK employer topics.
Choose a topic that would get search traffic and isn't a duplicate of the existing guide slugs below.

Existing guide slugs (avoid duplicates):
{existing_slugs}

Today's date: {today}

Pick ONE topic from: employer NI, pension auto-enrolment, holiday pay, redundancy, maternity pay,
TUPE, zero-hours contracts, IR35, payroll compliance, employment allowance, salary sacrifice,
P11D benefits, apprenticeship levy, or related UK employer cost topics.

Return a JSON object with:
{{
  "slug": "kebab-case-url-slug",
  "title": "Guide title (under 60 chars)",
  "description": "Meta description (under 155 chars, include a specific rate or threshold)",
  "topic": "Short topic label (e.g. 'Employer NI', 'Holiday Pay')",
  "sections": [
    {{
      "heading": "Section 1 heading",
      "paragraphs": ["Para 1 text (2-3 sentences, specific facts).", "Para 2 text (optional)."]
    }},
    {{
      "heading": "Section 2 heading",
      "paragraphs": ["Para 1 text.", "Para 2 text."]
    }},
    {{
      "heading": "Section 3 heading",
      "paragraphs": ["Para 1 text.", "Para 2 text."]
    }}
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
    response = CLIENT.messages.create(
        model="claude-opus-4-6",
        max_tokens=3000,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text.strip()


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
