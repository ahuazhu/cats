#!/usr/bin/env bash
# Render the PostgreSQL DSN that cats-noded -- and every cats-blockd it spawns
# -- reads at connect time.
#
# Why this exists. The password used to live in /etc/cats/worker.env, written
# once and never revisited. RDS rotates the managed master password underneath
# a running fleet, and PostgreSQL authenticates on connect, so the copy went
# stale in silence: established connections kept serving while every new one
# failed. The symptom was "creating a Cat fails", which looks like a component
# bug rather than a credential.
#
# There is exactly one authority for this password. Read it from there, at
# every worker start and on a timer in between, so a rotation costs nothing.
set -euo pipefail

output=${CATS_POSTGRES_URL_FILE:-/run/cats/postgres-url}

[[ -n ${CATS_POSTGRES_SCHEMA:-} ]] || {
  echo "render-postgres-url needs CATS_POSTGRES_SCHEMA" >&2
  exit 1
}
[[ $CATS_POSTGRES_SCHEMA =~ ^cats_[a-z0-9_]+$ && ${#CATS_POSTGRES_SCHEMA} -le 63 ]] || {
  echo "CATS_POSTGRES_SCHEMA must be one lowercase cats_* PostgreSQL identifier" >&2
  exit 1
}

if [[ -n ${CATS_POSTGRES_SECRET_ARN:-} ]]; then
  for required in aws jq; do
    command -v "$required" >/dev/null 2>&1 || {
      echo "render-postgres-url needs $required on PATH" >&2
      exit 1
    }
  done
  for required in CATS_POSTGRES_HOST CATS_POSTGRES_DATABASE; do
    [[ -n ${!required:-} ]] || {
      echo "render-postgres-url needs $required alongside CATS_POSTGRES_SECRET_ARN" >&2
      exit 1
    }
  done

  # The managed secret is a JSON document holding username and password. Both
  # go into the userinfo component, so both are percent-encoded: a generated
  # password routinely contains characters that would otherwise terminate it.
  secret=$(
    aws secretsmanager get-secret-value \
      --secret-id "$CATS_POSTGRES_SECRET_ARN" \
      --query SecretString \
      --output text
  )
  username=$(jq -er '.username | @uri' <<<"$secret")
  password=$(jq -er '.password | @uri' <<<"$secret")
  unset secret

  dsn="postgresql://${username}:${password}@${CATS_POSTGRES_HOST}:${CATS_POSTGRES_PORT:-5432}/${CATS_POSTGRES_DATABASE}?sslmode=${CATS_POSTGRES_SSLMODE:-require}&options=-csearch_path%3D${CATS_POSTGRES_SCHEMA}"
elif [[ -n ${CATS_POSTGRES_URL:-} ]]; then
  # Development, and any host not yet pointed at the managed secret. The DSN is
  # whatever the environment file says; nothing here rotates. Still require
  # the exact reviewed search_path so this compatibility path cannot silently
  # reconnect noded/blockd to public.
  dsn=$CATS_POSTGRES_URL
  query=${dsn#*\?}
  [[ $query != "$dsn" ]] || {
    echo "CATS_POSTGRES_URL lacks the required search_path option" >&2
    exit 1
  }
  option_count=0
  IFS='&' read -r -a query_parameters <<<"$query"
  for parameter in "${query_parameters[@]}"; do
    if [[ $parameter == options=* ]]; then
      ((option_count += 1))
      [[ $parameter == "options=-csearch_path%3D${CATS_POSTGRES_SCHEMA}" ]] || {
        echo "CATS_POSTGRES_URL has a non-canonical PostgreSQL options value" >&2
        exit 1
      }
    fi
  done
  [[ $option_count -eq 1 ]] || {
    echo "CATS_POSTGRES_URL must have exactly one search_path option" >&2
    exit 1
  }
else
  echo "set CATS_POSTGRES_SECRET_ARN (production) or CATS_POSTGRES_URL (development)" >&2
  exit 1
fi

# Write through a temporary file in the same directory and rename. A reader --
# cats-blockd resolving its DSN mid-flight -- then sees the old file or the new
# one, never a half-written line.
install -d -m 0700 "$(dirname "$output")"
umask 077
temporary=$(mktemp "${output}.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
printf '%s\n' "$dsn" >"$temporary"
chmod 0600 "$temporary"
mv -f -- "$temporary" "$output"
trap - EXIT
