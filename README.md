# UKBenefitsCalculator.co.uk

Independent UK benefits calculator and support guide platform built on Flask and Jinja.

## Local development

```bash
pip install -r requirements.txt
cp .env.example .env
python3 main.py
pytest -q
```

Open `http://localhost:8080`.

## Core routes

- `/` homepage and category hub
- `/calculators` calculator index
- `/guides` guide index
- `/universal-credit-calculator`
- `/child-benefit-calculator`
- `/hicbc-calculator`
- `/pension-credit-calculator`
- `/pip-eligibility-checker`
- `/council-tax-reduction-calculator`
- `/housing-benefit-calculator`
- `/benefit-cap-calculator`
- `/ssp-calculator`
- `/maternity-pay-comparison`
- `/esa-calculator`
- `/jsa-calculator`
- `/working-tax-credit-calculator`
- `/child-tax-credit-calculator`
- `/tax-free-childcare-calculator`
- `/sure-start-maternity-grant-checker`
- `/healthy-start-checker`
- `/free-school-meals-checker`
- `/winter-fuel-payment-checker`
- `/cold-weather-payment-checker`
- `/sitemap.xml`
- `/robots.txt`
- `/health`

## Notes

- Keeps the existing favicon/image asset set from the source project.
- Keeps the ad and analytics plumbing from the source project.
- Built as an independent estimator site, not an official government service.
