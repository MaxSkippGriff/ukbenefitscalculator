#!/usr/bin/env bash
set -u

DOMAIN="${DOMAIN:-aftertaxsalary.co.uk}"
WWW_DOMAIN="${WWW_DOMAIN:-www.${DOMAIN}}"
CANONICAL_HOST="${CANONICAL_HOST:-${DOMAIN}}"
FORCE_HTTPS="${FORCE_HTTPS:-false}"
RUN_APP_URL="${RUN_APP_URL:-}"

failures=0

log() { printf "\n== %s ==\n" "$1"; }
fail() { printf "[FAIL] %s\n" "$1"; failures=$((failures+1)); }
pass() { printf "[OK] %s\n" "$1"; }
warn() { printf "[WARN] %s\n" "$1"; }

header_value() {
  local key="$1"
  awk -v k="${key}:" 'BEGIN{IGNORECASE=1} index(tolower($0), tolower(k))==1{sub(/\r$/,"",$0); sub(/^[^:]*:[[:space:]]*/,"",$0); print; exit}'
}

status_code() {
  awk 'toupper($1) ~ /^HTTP\/[0-9.]+$/ {print $2; exit}'
}

log "DNS"
A_REC=$(dig +short "${DOMAIN}" A)
AAAA_REC=$(dig +short "${DOMAIN}" AAAA)
CNAME_REC=$(dig +short "${WWW_DOMAIN}" CNAME)
CAA_REC=$(dig +short "${DOMAIN}" CAA)

echo "A records:"; echo "${A_REC:-<none>}"
echo "AAAA records:"; echo "${AAAA_REC:-<none>}"
echo "CNAME records for ${WWW_DOMAIN}:"; echo "${CNAME_REC:-<none>}"
echo "CAA records:"; echo "${CAA_REC:-<none>}"

if [[ -n "${CAA_REC}" ]]; then
  if echo "${CAA_REC}" | grep -qi 'pki\.goog'; then
    pass "CAA permits pki.goog"
  else
    fail "CAA exists but does not include pki.goog"
  fi
else
  pass "No CAA records found"
fi

log "HTTP/HTTPS reachability"
HTTP_HEALTH=$(curl -sS -I --max-time 15 "http://${DOMAIN}/health" || true)
HTTPS_HEALTH=$(curl -sS -I --max-time 15 "https://${DOMAIN}/health" || true)
HTTP_WELL=$(curl -sS -I --max-time 15 "http://${DOMAIN}/.well-known/acme-challenge/test" || true)
HTTPS_WELL=$(curl -sS -I --max-time 15 "https://${DOMAIN}/.well-known/acme-challenge/test" || true)

echo "http://${DOMAIN}/health"; echo "${HTTP_HEALTH:-<request failed>}"
echo "https://${DOMAIN}/health"; echo "${HTTPS_HEALTH:-<request failed>}"
echo "http://${DOMAIN}/.well-known/acme-challenge/test"; echo "${HTTP_WELL:-<request failed>}"
echo "https://${DOMAIN}/.well-known/acme-challenge/test"; echo "${HTTPS_WELL:-<request failed>}"

log "TLS certificate probe (openssl)"
OPENSSL_OUT=$(openssl s_client -connect "${DOMAIN}:443" -servername "${DOMAIN}" </dev/null 2>&1 || true)
echo "${OPENSSL_OUT}" | head -n 30
if echo "${OPENSSL_OUT}" | grep -qi "no peer certificate available"; then
  fail "No peer certificate presented on ${DOMAIN}:443. Domain mapping certificate is not attached at edge yet."
elif echo "${OPENSSL_OUT}" | grep -qi "Certificate chain"; then
  pass "Certificate chain is present on ${DOMAIN}:443"
else
  warn "Could not confirm certificate chain from openssl output"
fi

HTTP_WELL_STATUS=$(echo "${HTTP_WELL}" | status_code)
HTTP_WELL_LOC=$(echo "${HTTP_WELL}" | header_value "Location")
HTTPS_HEALTH_STATUS=$(echo "${HTTPS_HEALTH}" | status_code)
HTTPS_WELL_STATUS=$(echo "${HTTPS_WELL}" | status_code)
HTTPS_REACHABLE=false
if [[ "${HTTPS_HEALTH_STATUS:-}" =~ ^(200|404)$ || "${HTTPS_WELL_STATUS:-}" =~ ^(200|404)$ ]]; then
  HTTPS_REACHABLE=true
fi
if [[ "${HTTP_WELL_STATUS:-}" =~ ^30[1278]$ ]]; then
  if [[ -z "${HTTP_WELL_LOC}" ]]; then
    fail "/.well-known returned redirect status without Location"
  else
    loc_host=$(echo "${HTTP_WELL_LOC}" | sed -E 's#^[a-zA-Z]+://([^/]+).*$#\1#')
    loc_scheme=$(echo "${HTTP_WELL_LOC}" | sed -E 's#^([a-zA-Z]+)://.*#\1#')
    if [[ "${loc_scheme}" == "https" ]]; then
      if [[ "${HTTPS_REACHABLE}" == "true" ]]; then
        pass "HTTP /.well-known redirects to HTTPS and HTTPS is reachable"
      else
        fail "Google Frontend is forcing HTTP->HTTPS before cert is active. Fix by simplifying domain mappings: temporarily map only apex OR only www until cert becomes ACTIVE, then add the other host."
      fi
    elif [[ "${loc_host}" != "${DOMAIN}" || "${loc_scheme}" != "http" ]]; then
      fail "Unexpected redirect for /.well-known on HTTP: ${HTTP_WELL_LOC}"
    else
      pass "Redirect for /.well-known stays on same host/scheme"
    fi
  fi
else
  pass "HTTP /.well-known did not force redirect"
fi

log "Run.app redirect"
if [[ -n "${RUN_APP_URL}" ]]; then
  RUN_HDR=$(curl -sS -I --max-time 15 "${RUN_APP_URL}" || true)
  echo "${RUN_APP_URL}"; echo "${RUN_HDR:-<request failed>}"
  RUN_LOC=$(echo "${RUN_HDR}" | header_value "Location")
  if [[ -n "${RUN_LOC}" && "${RUN_LOC}" == https://${CANONICAL_HOST}* ]]; then
    pass "run.app redirects to canonical host"
  else
    fail "run.app redirect missing or not canonical"
  fi
else
  warn "RUN_APP_URL not set; skipping run.app redirect check"
fi

log "HSTS check"
FORCE_HTTPS_LC=$(echo "${FORCE_HTTPS}" | tr '[:upper:]' '[:lower:]')
if [[ "${FORCE_HTTPS_LC}" == "false" ]]; then
  HSTS_HTTP=$(echo "${HTTP_HEALTH}" | header_value "Strict-Transport-Security")
  HSTS_HTTPS=$(echo "${HTTPS_HEALTH}" | header_value "Strict-Transport-Security")
  if [[ -n "${HSTS_HTTP}" || -n "${HSTS_HTTPS}" ]]; then
    fail "HSTS header present while FORCE_HTTPS=false"
  else
    pass "No HSTS header while FORCE_HTTPS=false"
  fi
else
  warn "FORCE_HTTPS=true; HSTS absence is not enforced by this script"
fi

if [[ ${failures} -gt 0 ]]; then
  printf "\nResult: %d check(s) failed\n" "${failures}"
  exit 1
fi

printf "\nResult: all checks passed\n"
exit 0
