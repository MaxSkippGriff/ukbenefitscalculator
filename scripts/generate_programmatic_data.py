#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "static" / "programmatic-catalog.json"


def generate_salary_values() -> list[int]:
    return list(range(20_000, 200_001, 1_000))


def generate_salary_intent_values() -> list[int]:
    return [
        25_000, 30_000, 35_000, 40_000, 45_000, 50_000, 55_000, 60_000,
        70_000, 80_000, 90_000, 100_000, 125_000, 150_000, 175_000, 200_000,
    ]


def generate_day_rate_values() -> list[int]:
    return list(range(100, 1_501, 25))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate AfterTaxSalary programmatic catalog.")
    parser.add_argument("--write", action="store_true", help="Write generated catalog to static/programmatic-catalog.json")
    args = parser.parse_args()

    payload = {
        "salary_seo_values": generate_salary_values(),
        "salary_intent_values": generate_salary_intent_values(),
        "day_rate_values": generate_day_rate_values(),
        "regions": ["england", "scotland", "wales", "northern-ireland"],
    }

    print("AfterTaxSalary programmatic data report")
    print(f"salary_pages={len(payload['salary_seo_values'])}")
    print(f"salary_intent_pages={len(payload['salary_intent_values'])}")
    print(f"day_rate_pages={len(payload['day_rate_values'])}")
    print(f"salary_min_max={payload['salary_seo_values'][0]}..{payload['salary_seo_values'][-1]}")
    print(f"day_rate_min_max={payload['day_rate_values'][0]}..{payload['day_rate_values'][-1]}")

    if args.write:
        OUTPUT_PATH.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"updated={OUTPUT_PATH}")


if __name__ == "__main__":
    main()
