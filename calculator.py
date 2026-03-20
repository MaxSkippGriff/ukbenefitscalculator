"""EmployerCalculator.co.uk deterministic calculation engine for 2025/26."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

TAX_YEAR = "2025/26"

# 2025/26 employer NI
EMPLOYER_NI_RATE_2025 = 0.15
SECONDARY_THRESHOLD_2025 = 5_000
EMPLOYMENT_ALLOWANCE_2025 = 10_500

# 2024/25 comparison
EMPLOYER_NI_RATE_2024 = 0.138
SECONDARY_THRESHOLD_2024 = 9_100
EMPLOYMENT_ALLOWANCE_2024 = 5_000

# Relief categories
UPPER_SECONDARY_THRESHOLD = 50_270

# Pension
QUALIFYING_EARNINGS_LOWER = 6_240
QUALIFYING_EARNINGS_UPPER = 50_270
MIN_EMPLOYER_PENSION_RATE = 3.0
MIN_TOTAL_PENSION_RATE = 8.0


@dataclass(frozen=True)
class EmployerNIBreakdown:
    salary: float
    niable_earnings: float
    gross_ni: float
    allowance_used: float
    ni_due: float
    threshold: float
    rate: float
    relief_type: str
    upper_secondary_threshold: float
    lower_band_earnings: float
    upper_band_earnings: float


@dataclass(frozen=True)
class EmployerCostResult:
    salary: float
    employer_ni: EmployerNIBreakdown
    pension_rate: float
    pension_contribution: float
    overheads: float
    total_cost: float
    cost_above_salary: float
    cost_above_salary_pct: float
    monthly_total: float
    weekly_total: float


def _round(value: float) -> float:
    return round(float(value), 2)


def _qualifying_earnings(salary: float) -> float:
    capped = min(float(salary), QUALIFYING_EARNINGS_UPPER)
    return max(0.0, capped - QUALIFYING_EARNINGS_LOWER)


def employer_pension_contribution(salary: float, pension_rate: float = MIN_EMPLOYER_PENSION_RATE) -> float:
    qe = _qualifying_earnings(salary)
    return _round(qe * (float(pension_rate) / 100.0))


def employer_ni_2025(
    salary: float,
    allowance: float = 0.0,
    under_21: bool = False,
    apprentice_under_25: bool = False,
) -> EmployerNIBreakdown:
    salary = float(salary)
    relief_applies = under_21 or apprentice_under_25
    relief_type = "standard"

    if relief_applies:
        relief_type = "under_21" if under_21 else "apprentice_under_25"
        lower_band_earnings = min(salary, UPPER_SECONDARY_THRESHOLD)
        upper_band_earnings = max(0.0, salary - UPPER_SECONDARY_THRESHOLD)
        gross_ni = upper_band_earnings * EMPLOYER_NI_RATE_2025
        niable = upper_band_earnings
        threshold = UPPER_SECONDARY_THRESHOLD
    else:
        lower_band_earnings = min(salary, SECONDARY_THRESHOLD_2025)
        upper_band_earnings = max(0.0, salary - SECONDARY_THRESHOLD_2025)
        gross_ni = upper_band_earnings * EMPLOYER_NI_RATE_2025
        niable = upper_band_earnings
        threshold = SECONDARY_THRESHOLD_2025

    allowance_used = min(max(0.0, float(allowance)), gross_ni)
    ni_due = max(0.0, gross_ni - allowance_used)

    return EmployerNIBreakdown(
        salary=_round(salary),
        niable_earnings=_round(niable),
        gross_ni=_round(gross_ni),
        allowance_used=_round(allowance_used),
        ni_due=_round(ni_due),
        threshold=_round(threshold),
        rate=EMPLOYER_NI_RATE_2025,
        relief_type=relief_type,
        upper_secondary_threshold=UPPER_SECONDARY_THRESHOLD,
        lower_band_earnings=_round(lower_band_earnings),
        upper_band_earnings=_round(upper_band_earnings),
    )


def employer_ni_2024(salary: float, allowance: float = 0.0) -> Dict[str, float]:
    salary = float(salary)
    niable = max(0.0, salary - SECONDARY_THRESHOLD_2024)
    gross_ni = niable * EMPLOYER_NI_RATE_2024
    allowance_used = min(max(0.0, float(allowance)), gross_ni)
    ni_due = max(0.0, gross_ni - allowance_used)
    return {
        "salary": _round(salary),
        "niable_earnings": _round(niable),
        "gross_ni": _round(gross_ni),
        "allowance_used": _round(allowance_used),
        "ni_due": _round(ni_due),
        "threshold": SECONDARY_THRESHOLD_2024,
        "rate": EMPLOYER_NI_RATE_2024,
    }


def calculate_employer_cost(
    salary: float,
    pension_rate: float = MIN_EMPLOYER_PENSION_RATE,
    overheads: float = 0.0,
    allowance: float = 0.0,
    under_21: bool = False,
    apprentice_under_25: bool = False,
) -> EmployerCostResult:
    salary = float(salary)
    pension = employer_pension_contribution(salary, pension_rate)
    ni = employer_ni_2025(
        salary=salary,
        allowance=allowance,
        under_21=under_21,
        apprentice_under_25=apprentice_under_25,
    )
    overheads = max(0.0, float(overheads))

    total = salary + ni.ni_due + pension + overheads
    above = total - salary
    pct = (above / salary) * 100.0 if salary > 0 else 0.0

    return EmployerCostResult(
        salary=_round(salary),
        employer_ni=ni,
        pension_rate=_round(pension_rate),
        pension_contribution=_round(pension),
        overheads=_round(overheads),
        total_cost=_round(total),
        cost_above_salary=_round(above),
        cost_above_salary_pct=_round(pct),
        monthly_total=_round(total / 12.0),
        weekly_total=_round(total / 52.0),
    )


def monthly(value: float) -> float:
    return _round(float(value) / 12.0)


def weekly(value: float) -> float:
    return _round(float(value) / 52.0)


def salary_neighbours(amounts: List[int], salary: int, window: int = 2) -> List[int]:
    if salary not in amounts:
        return []
    idx = amounts.index(salary)
    start = max(0, idx - window)
    end = min(len(amounts), idx + window + 1)
    return [a for a in amounts[start:end] if a != salary]


def change_2025_vs_2024(salary: float) -> Dict[str, float]:
    current = employer_ni_2025(salary=salary, allowance=0.0)
    previous = employer_ni_2024(salary=salary, allowance=0.0)
    delta = current.gross_ni - previous["gross_ni"]
    pct = (delta / previous["gross_ni"] * 100.0) if previous["gross_ni"] > 0 else 0.0
    return {
        "salary": _round(salary),
        "ni_2025": current.gross_ni,
        "ni_2024": previous["gross_ni"],
        "increase": _round(delta),
        "increase_pct": _round(pct),
    }
