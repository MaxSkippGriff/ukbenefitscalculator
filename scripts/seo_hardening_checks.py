#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import app


def assert_redirect(base_url: str, path: str, expected: str) -> None:
    client = app.test_client()
    resp = client.get(path, base_url=base_url, follow_redirects=False)
    assert resp.status_code in (301, 308), f"{base_url}{path} did not redirect"
    location = resp.headers.get("Location")
    expected_rel = expected.replace("https://aftertaxsalary.co.uk", "")
    assert location in (expected, expected_rel), f"unexpected redirect: {location}"


def run() -> None:
    client = app.test_client()

    # Alias redirects should resolve to canonical paths.
    assert_redirect("https://employercalculator.co.uk", "/employer-ni-calculator", "/calculator")
    assert_redirect("https://employercalculator.co.uk", "/auto-enrollment-payroll-costs", "/auto-enrolment-payroll-costs")

    # Schema guardrails.
    calc_html = client.get("/calculator", base_url="https://employercalculator.co.uk").get_data(as_text=True)
    assert '"@type": "BreadcrumbList"' in calc_html

    print("employercalculator SEO hardening checks passed")


if __name__ == "__main__":
    run()
