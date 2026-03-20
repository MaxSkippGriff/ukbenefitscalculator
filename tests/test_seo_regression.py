from __future__ import annotations

import re
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import app


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def _canonical_href(html: str) -> str:
    match = re.search(r'<link rel="canonical" href="([^"]+)"', html)
    assert match, "canonical link missing"
    return match.group(1)


def test_redirects(client):
    calc_alias = client.get("/employer-ni-calculator", base_url="https://employercalculator.co.uk", follow_redirects=False)
    assert calc_alias.status_code in (301, 308)
    assert calc_alias.headers["Location"] == "/calculator"

    auto_enrollment_alias = client.get("/auto-enrollment-payroll-costs", base_url="https://employercalculator.co.uk", follow_redirects=False)
    assert auto_enrollment_alias.status_code in (301, 308)
    assert auto_enrollment_alias.headers["Location"] == "/auto-enrolment-payroll-costs"


def test_canonicals(client):
    home_html = client.get("/", base_url="https://employercalculator.co.uk").get_data(as_text=True)
    assert _canonical_href(home_html) == "https://employercalculator.co.uk/"

    calc_html = client.get("/calculator", base_url="https://employercalculator.co.uk").get_data(as_text=True)
    assert _canonical_href(calc_html) == "https://employercalculator.co.uk/calculator"

    intent_html = client.get("/employer-total-cost-calculator", base_url="https://employercalculator.co.uk").get_data(as_text=True)
    assert _canonical_href(intent_html) == "https://employercalculator.co.uk/employer-total-cost-calculator"


def test_intent_pages_and_schema(client):
    pages = [
        "/employer-total-cost-calculator",
        "/employer-cost-calculator-uk",
        "/total-cost-to-employer-calculator-uk",
        "/auto-enrolment-payroll-costs",
        "/ni-change-calculator",
        "/employer-ni-calculator-2025-26",
    ]
    for path in pages:
        html = client.get(path, base_url="https://employercalculator.co.uk").get_data(as_text=True)
        assert "<h1>" in html
        assert '"@type":"FAQPage"' in html or '"@type": "FAQPage"' in html


def test_sitemap_and_robots(client):
    robots = client.get("/robots.txt", base_url="https://employercalculator.co.uk")
    assert robots.status_code == 200
    robots_txt = robots.get_data(as_text=True)
    assert "Sitemap: https://employercalculator.co.uk/sitemap.xml" in robots_txt
    assert "Allow: /employer-total-cost-calculator" in robots_txt

    sitemap = client.get("/sitemap.xml", base_url="https://employercalculator.co.uk")
    assert sitemap.status_code == 200
    xml = sitemap.get_data(as_text=True)
    root = ET.fromstring(xml)
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = [node.text for node in root.findall(".//sm:loc", ns) if node.text]
    assert any(url.endswith("/calculator") for url in locs)
    assert any(url.endswith("/employer-total-cost-calculator") for url in locs)
    assert any(url.endswith("/auto-enrolment-payroll-costs") for url in locs)
    assert not any("?" in url for url in locs)


def test_status_endpoints_and_schema(client):
    assert client.get("/health", base_url="https://employercalculator.co.uk").status_code == 200
    assert client.get("/healthz", base_url="https://employercalculator.co.uk").status_code == 200
    assert client.get("/calculators", base_url="https://employercalculator.co.uk").status_code == 200

    calc_html = client.get("/calculator", base_url="https://employercalculator.co.uk").get_data(as_text=True)
    assert '"@type":"BreadcrumbList"' in calc_html or '"@type": "BreadcrumbList"' in calc_html
