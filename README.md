# AfterTaxSalary.co.uk

UK take-home salary calculator for the 2025/26 tax year. Flask app ready for Google Cloud Run.

## Local development

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env

# Run the dev server
python main.py
# Open http://localhost:8080

# SEO hardening checks
python3 scripts/seo_hardening_checks.py
pytest -q

# Programmatic catalog generation
python3 scripts/generate_programmatic_data.py
python3 scripts/generate_programmatic_data.py --write
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `FLASK_SECRET_KEY` | Yes | random | Secret for signed cookies |
| `CANONICAL_HOST` | Yes | `aftertaxsalary.co.uk` | Canonical host used for redirects/canonicals |
| `CANONICAL_SCHEME` | No | `https` | Canonical scheme used in generated URLs |
| `FORCE_HTTPS` | No | `false` | Force http->https redirect (enable only after cert is live) |
| `ALLOW_WWW_UNTIL_HTTPS` | No | `true` when `FORCE_HTTPS=false` | Allow both apex and www during cert provisioning |
| `REDIRECT_WWW_TO_APEX` | No | `true` in prod when canonical is apex | 301 redirect `www.*` to apex canonical host |
| `ENV` | No | `prod` | Set `dev` to enable `/debug/headers` without token |
| `DEBUG_TOKEN` | No | empty | Query token for `/debug/headers` when not in `ENV=dev` |
| `RUN_APP_URL` | No | empty | Optional URL used by `scripts/check_domain_ready.sh` for run.app redirect checks |
| `PORT` | No | `8080` | Server port (Cloud Run sets this) |
| `ENABLE_PRO` | No | `false` | Enable Stripe Pro features |
| `STRIPE_SECRET_KEY` | If Pro | — | Stripe secret key |
| `STRIPE_PUBLISHABLE_KEY` | If Pro | — | Stripe publishable key |
| `STRIPE_WEBHOOK_SECRET` | If Pro | — | Stripe webhook signing secret |
| `STRIPE_PRICE_ID_PRO_ONEOFF` | If Pro | — | Stripe Price ID for Pro unlock |
| `ENABLE_ADS` | No | `false` | Show AdSense ad placements |
| `ENABLE_SEO_DEBUG` | No | `false` | Enable `GET /__seo` debug summary endpoint |

## Cloud Run deployment

```bash
# Build and deploy
gcloud builds submit --tag gcr.io/PROJECT_ID/aftertaxsalary
gcloud run deploy takehome-salary \
  --image gcr.io/PROJECT_ID/aftertaxsalary \
  --region europe-west2 \
  --allow-unauthenticated \
  --set-env-vars="CANONICAL_HOST=aftertaxsalary.co.uk,CANONICAL_SCHEME=https,FORCE_HTTPS=true,FLASK_SECRET_KEY=your-secret"
```

## DNS / certificate note

If your custom domain uses CAA records, allow Google Trust Services for Cloud Run certificates:

`CAA 0 issue "pki.goog"`

## Fixing Cloud Run CertificatePending

1. Run the readiness script:

```bash
scripts/check_domain_ready.sh
```

2. If CAA records exist and do not include Google Trust Services, add:

```dns
CAA 0 issue "pki.goog"
```

3. If using Cloudflare during provisioning:
- Set DNS records to **DNS only** (grey cloud), not proxied.
- Disable **Always Use HTTPS** and **Automatic HTTPS Rewrites** temporarily.
- Do not redirect `/.well-known/acme-challenge/*` while certificate issuance is pending.

4. In Cloud Run domain mappings, temporarily keep only one hostname mapped (recommend apex: `aftertaxsalary.co.uk`).
- Remove the second mapping (`www`) while certificate is pending.
- After apex certificate becomes ACTIVE, re-add `www` mapping.
- If `openssl` shows no certificate on apex, keep only apex mapping and wait. Do **not** recreate mappings repeatedly.

5. Keep `FORCE_HTTPS=false` until `https://aftertaxsalary.co.uk` returns 200.
6. After certificate is active, set `FORCE_HTTPS=true` and (optionally) set `ALLOW_WWW_UNTIL_HTTPS=false`, then deploy.

### Manual verification commands

```bash
# DNS checks
dig +short aftertaxsalary.co.uk A
dig +short aftertaxsalary.co.uk AAAA
dig +short www.aftertaxsalary.co.uk CNAME
dig +short aftertaxsalary.co.uk CAA

# HTTP checks (during pending cert)
curl -I http://aftertaxsalary.co.uk/health
curl -I http://aftertaxsalary.co.uk/.well-known/acme-challenge/test

# TLS cert check
openssl s_client -connect aftertaxsalary.co.uk:443 -servername aftertaxsalary.co.uk </dev/null | head -n 30

# Expectation:
# - /.well-known/acme-challenge/* should NOT redirect to https while pending
# - HSTS should be absent while pending
# - Once cert ACTIVE, set FORCE_HTTPS=true and re-enable strict canonical https.
# - openssl should show a certificate chain; if it says "no peer certificate available", cert is not attached at edge yet.
```

## Routes

| Route | Description |
|---|---|
| `/` | Landing page |
| `/calculator` | Interactive calculator with charts |
| `/salary/<salary>/<region>` | SEO salary pages for England/Scotland/Wales/Northern Ireland |
| `/salary/<salary>-after-tax` | Salary intent pages |
| `/day-rate` | Day-rate hub |
| `/day-rate/<rate>-after-tax` | Day-rate intent pages |
| `/student-loans` | Student loan hub alias |
| `/pension-salary-sacrifice` | Pension hub alias |
| `/tax-codes-explained` | Tax-code hub alias |
| `/regions` | rUK vs Scotland comparison |
| `/privacy`, `/terms`, `/disclaimer` | Legal pages |
| `/api/takehome?salary=N&region=rUK` | JSON API |
| `/sitemap.xml` | XML sitemap (187 URLs) |
| `/robots.txt` | Robots file |
| `/pro` | Pro pricing page (if enabled) |
| `/compare` | Compare two salaries (Pro) |
| `/bonus-tax` | Bonus tax calculator (Pro) |
| `/export/pdf?salary=N` | PDF export (Pro, requires weasyprint) |
| `/health` | Health check |
| `/healthz` | Health check alias |
| `/__seo` | SEO debug summary (only when `ENABLE_SEO_DEBUG=true`) |

## Tax calculation sources

- [HMRC Income Tax Rates](https://www.gov.uk/income-tax-rates)
- [Scottish Income Tax](https://www.gov.uk/scottish-income-tax)
- [National Insurance Rates](https://www.gov.uk/national-insurance-rates-letters)
- [Student Loan Repayments](https://www.gov.uk/repaying-your-student-loan)

## Post-deploy verification commands

```bash
curl -I http://aftertaxsalary.co.uk/
curl -I https://www.aftertaxsalary.co.uk/
curl -I http://www.aftertaxsalary.co.uk/
curl -I "https://aftertaxsalary.co.uk/?salary=35000&region=england&loan=none&pension=0&sacrifice=0&taxcode=1257L&ni=A"
```
