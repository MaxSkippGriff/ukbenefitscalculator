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
    alias = client.get("/benefits-calculator-uk", base_url="https://ukbenefitscalculator.co.uk", follow_redirects=False)
    assert alias.status_code in (301, 308)
    assert alias.headers["Location"] == "/"

    uc_alias = client.get("/universal-credit-estimator", base_url="https://ukbenefitscalculator.co.uk", follow_redirects=False)
    assert uc_alias.status_code in (301, 308)
    assert uc_alias.headers["Location"] == "/universal-credit-calculator"


def test_canonicals(client):
    home_html = client.get("/", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert _canonical_href(home_html) == "https://ukbenefitscalculator.co.uk/"

    calc_html = client.get("/universal-credit-calculator", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert _canonical_href(calc_html) == "https://ukbenefitscalculator.co.uk/universal-credit-calculator"

    guide_html = client.get("/guides/what-benefits-can-i-claim", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert _canonical_href(guide_html) == "https://ukbenefitscalculator.co.uk/guides/what-benefits-can-i-claim"


def test_core_pages_and_schema(client):
    pages = [
        "/universal-credit-calculator",
        "/child-benefit-calculator",
        "/hicbc-calculator",
        "/pension-credit-calculator",
        "/pip-eligibility-checker",
        "/guides/universal-credit-explained",
    ]
    for path in pages:
        html = client.get(path, base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
        assert "<h1" in html
        assert '"@type": "FAQPage"' in html or '"@type":"FAQPage"' in html or path.startswith("/guides/")


def test_sitemap_and_robots(client):
    robots = client.get("/robots.txt", base_url="https://ukbenefitscalculator.co.uk")
    assert robots.status_code == 200
    robots_txt = robots.get_data(as_text=True)
    assert "Sitemap: https://ukbenefitscalculator.co.uk/sitemap.xml" in robots_txt
    assert "Allow: /universal-credit-calculator" in robots_txt

    sitemap = client.get("/sitemap.xml", base_url="https://ukbenefitscalculator.co.uk")
    assert sitemap.status_code == 200
    xml = sitemap.get_data(as_text=True)
    root = ET.fromstring(xml)
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = [node.text for node in root.findall(".//sm:loc", ns) if node.text]
    assert any(url.endswith("/universal-credit-calculator") for url in locs)
    assert any(url.endswith("/child-benefit-calculator") for url in locs)
    assert any(url.endswith("/guides/what-benefits-can-i-claim") for url in locs)
    assert not any("?" in url for url in locs)


def test_status_endpoints_and_indexes(client):
    assert client.get("/health", base_url="https://ukbenefitscalculator.co.uk").status_code == 200
    assert client.get("/healthz", base_url="https://ukbenefitscalculator.co.uk").status_code == 200
    assert client.get("/calculators", base_url="https://ukbenefitscalculator.co.uk").status_code == 200
    assert client.get("/guides", base_url="https://ukbenefitscalculator.co.uk").status_code == 200


def test_query_aligned_copy_present(client):
    home_html = client.get("/", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert "Free UK Benefits Calculator 2026/27" in home_html
    assert "free UK benefits checker" in home_html or "free UK benefits calculator" in home_html
    assert "2025/26" not in home_html

    uc_html = client.get("/universal-credit-calculator", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert "£16,000" in uc_html
    assert "tariff income" in uc_html
    assert "Capital rules to know" in uc_html
    assert ">per month<" in uc_html

    savings_html = client.get("/guides/how-savings-affect-benefits", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert "capital disregards" in savings_html
    assert "ISA" in savings_html or "ISAs" in savings_html

    pip_html = client.get("/pip-eligibility-checker", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert "weekly, monthly and annual" in pip_html

    cb_html = client.get("/child-benefit-calculator", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert "1, 2 or more children" in cb_html
    assert "2026/27 rates used" in cb_html
    assert ">per week<" in cb_html

    hicbc_html = client.get("/hicbc-calculator", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert "HICBC threshold" in hicbc_html
    assert ">per year<" in hicbc_html

    wf_html = client.get("/situations/benefits-for-working-families", base_url="https://ukbenefitscalculator.co.uk").get_data(as_text=True)
    assert "working family" in wf_html.lower()
