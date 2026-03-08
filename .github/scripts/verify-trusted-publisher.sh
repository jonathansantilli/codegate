#!/usr/bin/env bash
set -euo pipefail

NPM_PACKAGE_NAME="${NPM_PACKAGE_NAME:-$(node -e "const fs=require('node:fs');const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));process.stdout.write(pkg.name);")}"

if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" || -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
  echo "::error::Missing GitHub OIDC environment variables. Ensure workflow permissions include 'id-token: write'."
  exit 1
fi

OIDC_RESPONSE="$(
  curl --silent --show-error --fail \
    --header "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=npm:registry.npmjs.org"
)"

OIDC_TOKEN="$(
  printf '%s' "${OIDC_RESPONSE}" | node -e "let data='';process.stdin.on('data',(chunk)=>{data+=chunk;});process.stdin.on('end',()=>{const value=JSON.parse(data).value;if(!value){process.exit(2);}process.stdout.write(value);});"
)"

if [[ -z "${OIDC_TOKEN}" ]]; then
  echo "::error::Failed to obtain GitHub OIDC token for npm audience."
  exit 1
fi

RESPONSE_FILE="$(mktemp)"
HTTP_STATUS="$(
  curl --silent --show-error \
    --output "${RESPONSE_FILE}" \
    --write-out "%{http_code}" \
    --request POST \
    --header "Authorization: Bearer ${OIDC_TOKEN}" \
    "https://registry.npmjs.org/-/npm/v1/oidc/token/exchange/package/${NPM_PACKAGE_NAME}"
)"

if [[ "${HTTP_STATUS}" != "201" ]]; then
  echo "::error::npm trusted publishing preflight failed for package '${NPM_PACKAGE_NAME}' (status ${HTTP_STATUS})."
  cat "${RESPONSE_FILE}"
  rm -f "${RESPONSE_FILE}"
  exit 1
fi

NPM_EXCHANGE_TOKEN="$(
  node -e "const fs=require('node:fs');const payload=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));if(!payload.token){process.exit(2);}process.stdout.write(payload.token);" "${RESPONSE_FILE}"
)"

if [[ -z "${NPM_EXCHANGE_TOKEN}" ]]; then
  echo "::error::Trusted publishing exchange succeeded but no npm token was returned."
  rm -f "${RESPONSE_FILE}"
  exit 1
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "NODE_AUTH_TOKEN=${NPM_EXCHANGE_TOKEN}"
    echo "NPM_TOKEN=${NPM_EXCHANGE_TOKEN}"
  } >>"${GITHUB_ENV}"
fi

npm config set "//registry.npmjs.org/:_authToken" "${NPM_EXCHANGE_TOKEN}"

rm -f "${RESPONSE_FILE}"
echo "npm trusted publishing preflight succeeded for '${NPM_PACKAGE_NAME}' and injected a short-lived publish token."
