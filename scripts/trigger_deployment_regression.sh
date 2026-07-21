#!/bin/sh
set -eu

# Authenticated deployment hook for Railway/GitLab. It never prints the secret.
: "${AGENTFORGE_BASE_URL:?set AGENTFORGE_BASE_URL to the deployed platform URL}"
: "${DEPLOY_WEBHOOK_SECRET:?set DEPLOY_WEBHOOK_SECRET to the platform webhook secret}"
: "${DEPLOYMENT_ID:?set DEPLOYMENT_ID to an immutable deployment identifier}"
: "${TARGET_VERSION:?set TARGET_VERSION to the deployed target version}"

case "$AGENTFORGE_BASE_URL" in
    https://*|http://127.0.0.1:*|http://localhost:*) ;;
    *)
        echo "AGENTFORGE_BASE_URL must use HTTPS (HTTP is allowed only for localhost)" >&2
        exit 2
        ;;
esac

CURL_MAX_TIME_SECONDS="${CURL_MAX_TIME_SECONDS:-30}"
case "$CURL_MAX_TIME_SECONDS" in
    ''|*[!0-9]*)
        echo "CURL_MAX_TIME_SECONDS must be a positive integer" >&2
        exit 2
        ;;
esac

payload="$({
    DEPLOYMENT_ID="$DEPLOYMENT_ID" \
        TARGET_VERSION="$TARGET_VERSION" \
        CURL_MAX_TIME_SECONDS="$CURL_MAX_TIME_SECONDS" \
        python3 -c '
import json
import os

max_time = int(os.environ["CURL_MAX_TIME_SECONDS"])
if not 1 <= max_time <= 300:
    raise SystemExit("CURL_MAX_TIME_SECONDS must be between 1 and 300")

print(json.dumps({
    "deployment_id": os.environ["DEPLOYMENT_ID"],
    "target_version": os.environ["TARGET_VERSION"],
    "target_alias": "deployed",
}, separators=(",", ":")))
'
})"

curl --fail-with-body --silent --show-error \
    --request POST \
    --connect-timeout 10 \
    --max-time "$CURL_MAX_TIME_SECONDS" \
    --retry 2 \
    --retry-connrefused \
    --header "Content-Type: application/json" \
    --header "X-AgentForge-Webhook-Secret: $DEPLOY_WEBHOOK_SECRET" \
    --data-binary "$payload" \
    "${AGENTFORGE_BASE_URL%/}/api/v1/hooks/target-deployed"
