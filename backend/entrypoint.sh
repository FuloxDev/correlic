#!/bin/bash
set -e

MODE="${1:-both}"

# Run migrations before starting services (skip for admin/migrate commands)
if [ "$MODE" = "api" ] || [ "$MODE" = "telemetry" ] || [ "$MODE" = "both" ]; then
  echo "Running database migrations..."
  /app/admin migrate up 2>&1 || echo "Migration warning (may already be up to date)"
fi

case "$MODE" in
  api)
    echo "Starting API plane on :8080..."
    exec /app/api
    ;;
  telemetry)
    echo "Starting Telemetry plane on :8081..."
    exec /app/telemetry
    ;;
  migrate)
    echo "Running database migrations..."
    exec /app/admin migrate up
    ;;
  admin)
    shift
    exec /app/admin "$@"
    ;;
  both)
    echo "Starting API plane on :8080 and Telemetry plane on :8081..."
    /app/api &
    API_PID=$!
    /app/telemetry &
    TEL_PID=$!

    # Wait for either to exit
    wait -n $API_PID $TEL_PID
    EXIT_CODE=$?

    # Kill the other
    kill $API_PID $TEL_PID 2>/dev/null || true
    exit $EXIT_CODE
    ;;
  *)
    echo "Usage: entrypoint.sh [api|telemetry|both|migrate|admin]"
    exit 1
    ;;
esac
