#!/bin/sh
# Run Moyai's existing-product mode on this machine with OIDC sign-in through the
# local Keycloak realm: the documented local rehearsal, not a deployment.
set -eu

directory=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
root=$(CDPATH= cd -P "$directory/../.." && pwd)
state="$directory/.local"
environment="$state/local-product.env"
python="$root/.venv/bin/python"

fail() { printf '%s\n' "$1" >&2; exit 1; }
usage() {
    printf '%s\n' \
        'Usage: sh local-product.sh up      start Keycloak, PostgreSQL and S3, then prepare both schemas' \
        '       sh local-product.sh dev     serve Moyai on MOYAI_PUBLIC_URL (foreground)' \
        '       sh local-product.sh down    stop the services and keep their data' \
        '       sh local-product.sh reset   stop the services and delete local data'
}

action=${1:-help}
case "$action" in help|--help|-h) usage; exit 0 ;; esac
[ "$#" -eq 1 ] || { usage; exit 1; }
[ -x "$python" ] || fail "Run 'uv sync --frozen' in $root first."
if docker compose version >/dev/null 2>&1; then
    compose() { docker compose --project-directory "$directory" --env-file /dev/null --profile product "$@"; }
elif podman compose version >/dev/null 2>&1; then
    compose() { podman compose --project-directory "$directory" --env-file /dev/null --profile product "$@"; }
else
    fail 'Install Docker Compose or Podman with a Compose provider.'
fi

load() {
    mkdir -p "$state"
    if [ ! -f "$environment" ]; then
        key=$("$python" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
        sed "s|^ENCRYPTION_KEY=\$|ENCRYPTION_KEY=$key|" "$directory/local-product.env.example" > "$environment"
        chmod 600 "$environment"
        printf 'Created %s\n' "$environment"
    fi
    set -a
    . "$environment"
    set +a
    # Keep the source checkout authoritative and never read a stray .env.
    export DATA_DIR="$state/data" PYTHONPATH="$root"
    cd "$state"
}

# Run inside the shared environment, so a missing bucket or schema is created once.
prepare() {
    "$python" - <<'EOF'
import os
import time

import boto3
import httpx
import psycopg
from botocore.config import Config
from botocore.exceptions import ClientError

deadline = time.monotonic() + 120
while True:
    try:
        httpx.get(os.environ["OIDC_ISSUER"] + "/.well-known/openid-configuration", timeout=5).raise_for_status()
        with psycopg.connect(os.environ["MOYAI_DATABASE_URL"], autocommit=True) as connection:
            connection.execute(f'CREATE SCHEMA IF NOT EXISTS "{os.environ["MOYAI_DATABASE_SCHEMA"]}"')
        s3 = boto3.client(
            "s3", endpoint_url=os.environ["OBJECT_STORAGE_ENDPOINT"], region_name=os.environ["OBJECT_STORAGE_REGION"],
            aws_access_key_id=os.environ["OBJECT_STORAGE_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["OBJECT_STORAGE_SECRET_ACCESS_KEY"],
            config=Config(s3={"addressing_style": "path"}),
        )
        try:
            s3.create_bucket(Bucket=os.environ["OBJECT_STORAGE_BUCKET"])
        except ClientError as error:
            if error.response["Error"]["Code"] not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                raise
        break
    except (httpx.HTTPError, psycopg.OperationalError, ConnectionError) as error:
        if time.monotonic() > deadline:
            raise SystemExit(f"Local services did not become ready: {type(error).__name__}")
        time.sleep(2)
EOF
}

case "$action" in
    up)
        load
        compose up -d
        prepare
        MOYAI_DATABASE_INITIALIZE=true "$python" -m app.schema_migrations --apply
        "$python" -m moyai.product_start provision --apply
        "$python" -m moyai.product_start verify
        printf '%s\n' "Ready. Run 'sh local-product.sh dev', then open $MOYAI_PUBLIC_URL" \
            'Keycloak users: admin / moyai-local-admin, member / moyai-local-member'
        ;;
    dev)
        load
        [ -f "$root/native/src/moyai/static/index.html" ] || (cd "$root" && npm run build)
        exec "$root/.venv/bin/moyai" dev --host 127.0.0.1 --port "$MOYAI_LOCAL_PORT"
        ;;
    down)
        load
        compose down
        ;;
    reset)
        load
        compose down --volumes
        rm -rf "$state/data"
        printf 'Removed local data; %s is kept.\n' "$environment"
        ;;
    *) usage; exit 1 ;;
esac
