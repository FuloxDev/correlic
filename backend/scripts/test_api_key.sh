#!/bin/bash
# Test API key directly against backend

set -e

API_KEY="${1:?usage: $0 <api-key>}"
BACKEND_URL="${2:-https://localhost:8080}"

echo "Testing API key: ${API_KEY:0:20}..."
echo "Backend URL: $BACKEND_URL"
echo ""

# Test with curl (skip TLS verification for localhost)
echo "Testing /orgs/me endpoint (no prefix)..."
echo "---"
RESPONSE=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" "$BACKEND_URL/orgs/me" \
  -H "Authorization: $API_KEY" 2>&1)

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

echo "HTTP Status: $HTTP_STATUS"
echo "Response Body:"
echo "$BODY"
echo ""

if [ "$HTTP_STATUS" = "200" ]; then
  echo "✅ SUCCESS: API key is valid!"
elif [ "$HTTP_STATUS" = "401" ]; then
  echo "❌ FAILED: Backend returned 401 Unauthorized"
  echo "   This means the backend doesn't recognize this API key."
elif [ "$HTTP_STATUS" = "000" ] || [ -z "$HTTP_STATUS" ]; then
  echo "❌ ERROR: Could not connect to backend"
  echo "   Is the backend running? Check: ps aux | grep 'cmd/api'"
  echo "   Or try: go run ./cmd/api"
else
  echo "❌ Unexpected status: $HTTP_STATUS"
fi

echo ""
echo "---"
echo ""

# Also test with explicit Bearer prefix
echo "Testing with 'Bearer' prefix..."
echo "---"
RESPONSE2=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" "$BACKEND_URL/orgs/me" \
  -H "Authorization: Bearer $API_KEY" 2>&1)

HTTP_STATUS2=$(echo "$RESPONSE2" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY2=$(echo "$RESPONSE2" | sed '/HTTP_STATUS:/d')

echo "HTTP Status: $HTTP_STATUS2"
echo "Response Body:"
echo "$BODY2"
echo ""
