#!/usr/bin/env bash
# Shared configuration for all Fineract API scripts.
# Sourced by seed and scenario scripts via:
#   source "$(dirname "$0")/../Scripts/config.sh"

BASE_URL="https://localhost:8443/fineract-provider/api/v1"
AUTH="Basic $(echo -n 'mifos:password' | base64)"
TENANT="default"

# Common curl options:
#   -k  : accept self-signed certificate
#   -s  : silent (no progress bar)
#   -S  : still show errors
CURL_OPTS="-k -s -S"

# Helper function for authenticated API calls
fineract_api() {
    local method="$1"
    local endpoint="$2"
    local data="$3"

    if [ -n "$data" ]; then
        curl $CURL_OPTS -X "$method" \
            "$BASE_URL$endpoint" \
            -H "Authorization: $AUTH" \
            -H "Fineract-Platform-TenantId: $TENANT" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl $CURL_OPTS -X "$method" \
            "$BASE_URL$endpoint" \
            -H "Authorization: $AUTH" \
            -H "Fineract-Platform-TenantId: $TENANT" \
            -H "Content-Type: application/json"
    fi
}