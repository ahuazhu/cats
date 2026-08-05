#!/usr/bin/env bash
# Reconcile the control plane's database credential against its authority.
#
# Why this exists (ADR-0029, issue #77). The deployment composes the control
# plane's DSNs from the RDS managed master secret, so a deploy can no longer
# carry a stale password forward. That leaves one window open: RDS rotates on a
# schedule, and if the Pod restarts for any other reason before the next deploy
# -- OOM, eviction, node drain -- it reads a Secret nobody has refreshed and
# crash-loops. PostgreSQL only authenticates on connect, so nothing notices
# until that restart.
#
# The order below is the whole design and must not be rearranged:
#
#   read the authority -> compose -> CONNECT -> patch only on success
#
# Patching without connecting first would make the worst failure a silent one:
# a wrong password written into the Secret, with the bill arriving at the next
# restart. Connecting first means a composition bug fails here, loudly, while
# the running Pod is untouched.
set -euo pipefail

: "${CATS_POSTGRES_SECRET_ARN:?the RDS managed master secret ARN}"
: "${CATS_RUNTIME_SECRET_NAME:=cats-runtime}"
: "${CATS_REFRESH_MODE:=report}"
: "${CATS_POSTGRES_CA_FILE:=/etc/cats/rds-ca.pem}"
: "${CATS_DSN_KEYS:=CATS_POSTGRES_URL CATS_USAGE_POSTGRES_URL}"

case "$CATS_REFRESH_MODE" in
  report|patch) ;;
  *)
    echo "CATS_REFRESH_MODE must be report or patch, not '$CATS_REFRESH_MODE'" >&2
    exit 1
    ;;
esac

api=https://kubernetes.default.svc
service_account=/var/run/secrets/kubernetes.io/serviceaccount
token="$(cat "$service_account/token")"
namespace="$(cat "$service_account/namespace")"
secret_url="$api/api/v1/namespaces/$namespace/secrets/$CATS_RUNTIME_SECRET_NAME"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
umask 077

kube() {
  curl --silent --show-error --fail \
    --cacert "$service_account/ca.crt" \
    --header "Authorization: Bearer $token" \
    "$@"
}

# 1. The authority.
aws secretsmanager get-secret-value \
  --secret-id "$CATS_POSTGRES_SECRET_ARN" \
  --query SecretString \
  --output text >"$work/authority.json"

# 2. The live Secret, for everything the password is not: user, host, port,
#    database, sslmode, and any other query parameter.
kube "$secret_url" >"$work/live.json"
python3 -c '
import base64, json, sys
data = json.load(open(sys.argv[1]))["data"]
json.dump({k: base64.b64decode(v).decode() for k, v in data.items()}, open(sys.argv[2], "w"))
' "$work/live.json" "$work/live-decoded.json"

# 3. Compose. Shared with the deployment so the two cannot drift.
# shellcheck disable=SC2086
python3 /usr/local/bin/swap-dsn-password.py \
  "$work/live-decoded.json" \
  "$work/authority.json" \
  $CATS_DSN_KEYS >"$work/rotated.json"

# 4. Prove each composed DSN actually authenticates, before anything is written.
#    A failure here is the good outcome of a bad composition: loud, and with the
#    running Pod still holding a credential that works.
for key in $CATS_DSN_KEYS; do
  dsn="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$work/rotated.json" "$key")"
  if ! PGSSLROOTCERT="$CATS_POSTGRES_CA_FILE" PGCONNECT_TIMEOUT=10 \
       psql "$dsn" --quiet --no-align --tuples-only --command 'SELECT 1' >/dev/null 2>"$work/psql.err"; then
    echo "refusing to patch: the composed $key does not authenticate" >&2
    # The DSN carries the password; report the server's words, never the DSN.
    sed -e 's/postgres\(ql\)\?:\/\/[^ ]*/[dsn redacted]/g' "$work/psql.err" >&2
    exit 1
  fi
done

# 5. Is there anything to do?
if python3 -c '
import json, sys
live = json.load(open(sys.argv[1]))
rotated = json.load(open(sys.argv[2]))
sys.exit(0 if all(live.get(k) == v for k, v in rotated.items()) else 1)
' "$work/live-decoded.json" "$work/rotated.json"; then
  echo "credential already matches the authority; nothing to do"
  exit 0
fi

changed="$(python3 -c '
import json, sys
live = json.load(open(sys.argv[1]))
rotated = json.load(open(sys.argv[2]))
print(" ".join(sorted(k for k, v in rotated.items() if live.get(k) != v)))
' "$work/live-decoded.json" "$work/rotated.json")"

if [ "$CATS_REFRESH_MODE" = report ]; then
  echo "would patch $CATS_RUNTIME_SECRET_NAME: $changed (mode=report, connect verified)"
  exit 0
fi

# 6. Patch, and only the keys that changed. A strategic merge on a Secret's
#    data map leaves every other key alone, so this cannot disturb the WorkOS,
#    Stripe or auth values that share it.
python3 -c '
import base64, json, sys
rotated = json.load(open(sys.argv[1]))
patch = {"data": {k: base64.b64encode(v.encode()).decode() for k, v in rotated.items()}}
json.dump(patch, open(sys.argv[2], "w"))
' "$work/rotated.json" "$work/patch.json"

kube --request PATCH \
  --header 'Content-Type: application/strategic-merge-patch+json' \
  --data @"$work/patch.json" \
  "$secret_url" >/dev/null

echo "patched $CATS_RUNTIME_SECRET_NAME: $changed (connect verified before writing)"
