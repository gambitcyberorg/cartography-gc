#!/bin/sh
set -e

# Parse all args. AWS credentials are exported as env vars for boto3.
# Everything else is forwarded directly to cartography.
CARTOGRAPHY_ARGS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --aws-access-key-id)
      export AWS_ACCESS_KEY_ID="$2"; shift 2 ;;
    --aws-secret-access-key)
      export AWS_SECRET_ACCESS_KEY="$2"; shift 2 ;;
    --aws-default-region)
      export AWS_DEFAULT_REGION="$2"; shift 2 ;;
    --es-password)
      export ES_PASSWORD="$2"
      CARTOGRAPHY_ARGS="$CARTOGRAPHY_ARGS --es-password-env-var ES_PASSWORD"; shift 2 ;;
    *)
      CARTOGRAPHY_ARGS="$CARTOGRAPHY_ARGS $1"; shift ;;
  esac
done

exec cartography $CARTOGRAPHY_ARGS
