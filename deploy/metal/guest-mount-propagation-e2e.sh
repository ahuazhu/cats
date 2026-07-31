#!/usr/bin/env bash
# Run inside a real Cats Guest after PostgreSQL 17 has been installed.
#
# This reproduces the image replacement pattern used by container-image
# unpackers without requiring a container runtime:
#   1. build two minimal PostgreSQL chroot roots;
#   2. recursively bind the Guest /dev into both roots;
#   3. start and stop PostgreSQL in the old root as uid/gid 70;
#   4. lazily unmount the old root from deepest to shallowest;
#   5. prove the Guest and replacement root still have usable POSIX shm;
#   6. start and stop PostgreSQL in the replacement root.
#
# The mount producer and PostgreSQL processes are real. A shared Guest mount
# tree makes the old-root unmount propagate to /dev/shm and the replacement
# peer, so this script fails with PostgreSQL's shm_open Permission denied.
set -euo pipefail

test_root=/var/tmp/cats-mount-propagation-e2e
old_root=$test_root/root-old
new_root=$test_root/root-new
postgres_bin_dir=/usr/lib/postgresql/17/bin
postgres_share_dir=/usr/share/postgresql/17
postgres_uid=70
postgres_gid=70
postgres_port=55432
failures=0

say() {
  printf '%s\n' "$*"
}

unmount_tree() {
  local root=$1
  local mounts mounted

  mounts=$(
    findmnt -Rrn -o TARGET "$root" 2>/dev/null |
      awk '{ depth = gsub("/", "/"); print depth, $0 }' |
      sort -k1,1nr |
      cut -d' ' -f2-
  )
  for mounted in $mounts; do
    printf 'umount -l %s: ' "$mounted"
    if umount -l "$mounted"; then
      echo "ok"
    elif findmnt -n "$mounted" >/dev/null 2>&1; then
      echo "failed" >&2
      return 1
    else
      # A shared parent can propagate a preceding unmount and remove another
      # enumerated target before this loop reaches it. Keep going so the test
      # can capture the resulting Guest and replacement-root damage.
      echo "already unmounted"
    fi
  done
}

cleanup() {
  unmount_tree "$old_root/dev" || true
  unmount_tree "$new_root/dev" || true
  rm -rf "$test_root"
}
trap cleanup EXIT

copy_runtime_dependencies() {
  local root=$1
  local binary dependency

  for binary in \
    /bin/sh \
    "$postgres_bin_dir/initdb" \
    "$postgres_bin_dir/pg_ctl" \
    "$postgres_bin_dir/postgres"; do
    while IFS= read -r dependency; do
      [[ -n $dependency ]] || continue
      install -D -m 0755 /dev/null "$root$dependency"
      cp -L "$dependency" "$root$dependency"
    done < <(
      ldd "$binary" |
        awk '$2 == "=>" && $3 ~ /^\// { print $3 }
             $1 ~ /^\// { print $1 }'
    )
  done

  # glibc may load this NSS module after startup, so it is not necessarily in
  # ldd output even though getpwuid(70) inside the chroot needs it.
  if [[ -e /lib/x86_64-linux-gnu/libnss_files.so.2 ]]; then
    install -D -m 0755 /dev/null \
      "$root/lib/x86_64-linux-gnu/libnss_files.so.2"
    cp -L /lib/x86_64-linux-gnu/libnss_files.so.2 \
      "$root/lib/x86_64-linux-gnu/libnss_files.so.2"
  fi
}

prepare_chroot() {
  local root=$1
  local binary

  mkdir -p \
    "$root/dev" \
    "$root/etc" \
    "$root/tmp" \
    "$root/usr/lib/postgresql/17" \
    "$root/usr/share/postgresql" \
    "$root/var/lib/postgresql/data"
  chmod 1777 "$root/tmp"

  cp -a /usr/lib/postgresql/17/. "$root/usr/lib/postgresql/17/"
  cp -a "$postgres_share_dir" "$root/usr/share/postgresql/17"
  for binary in /bin/sh; do
    install -D -m 0755 "$binary" "$root$binary"
  done
  copy_runtime_dependencies "$root"

  printf 'paperboy:x:%s:%s:Paperboy PostgreSQL:/var/lib/postgresql:/bin/sh\n' \
    "$postgres_uid" "$postgres_gid" > "$root/etc/passwd"
  printf 'paperboy:x:%s:\n' "$postgres_gid" > "$root/etc/group"
  chown -R "$postgres_uid:$postgres_gid" "$root/var/lib/postgresql"
}

run_as_postgres() {
  local root=$1
  shift
  HOME=/var/lib/postgresql \
    chroot --userspec="$postgres_uid:$postgres_gid" "$root" "$@"
}

init_cluster() {
  local root=$1

  run_as_postgres "$root" "$postgres_bin_dir/initdb" \
    -D /var/lib/postgresql/data \
    --auth=trust \
    --locale=C \
    --no-sync \
    --no-instructions
}

start_cluster() {
  local root=$1

  run_as_postgres "$root" "$postgres_bin_dir/pg_ctl" \
    -D /var/lib/postgresql/data \
    -l /tmp/postgresql.log \
    -o "-k /tmp -p $postgres_port -c listen_addresses='' -c shared_buffers=16MB -c max_connections=10 -c fsync=off -c full_page_writes=off -c synchronous_commit=off -c jit=off" \
    -t 30 \
    -w start
}

stop_cluster() {
  local root=$1

  run_as_postgres "$root" "$postgres_bin_dir/pg_ctl" \
    -D /var/lib/postgresql/data \
    -t 30 \
    -w \
    -m fast stop
}

show_mount() {
  local target=$1

  if ! findmnt -n -o TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION "$target"; then
    printf 'UNMOUNTED %s\n' "$target"
  fi
}

require_private_mount() {
  local target=$1
  local propagation

  propagation=$(findmnt -n -o PROPAGATION "$target")
  if [[ $propagation != private ]]; then
    printf '%s propagation is %s, expected private\n' \
      "$target" "$propagation" >&2
    return 1
  fi
}

record_failure() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

[[ $EUID -eq 0 ]] || {
  echo "run as root inside the Guest" >&2
  exit 1
}
for required in findmnt mount umount stat setpriv chroot ldd awk sort cut; do
  command -v "$required" >/dev/null || {
    echo "missing required command: $required" >&2
    exit 1
  }
done
for required in initdb pg_ctl postgres; do
  [[ -x $postgres_bin_dir/$required ]] || {
    echo "PostgreSQL 17 is not installed: $postgres_bin_dir/$required" >&2
    exit 1
  }
done

cleanup
mkdir -p "$test_root"

say "=== Guest baseline before chroot operations ==="
printf 'pid1='
cat /proc/1/comm
for target in / /dev /dev/shm; do
  show_mount "$target"
done
stat -c '%a %u:%g %n' / /dev /dev/shm

prepare_chroot "$old_root"
prepare_chroot "$new_root"
mount --rbind /dev "$old_root/dev"
mount --rbind /dev "$new_root/dev"

say "=== Recursive bind peers ==="
for target in \
  /dev \
  /dev/shm \
  "$old_root/dev" \
  "$old_root/dev/shm" \
  "$new_root/dev" \
  "$new_root/dev/shm"; do
  show_mount "$target"
done

init_cluster "$old_root"
init_cluster "$new_root"

say "=== PostgreSQL 17 old-root start/stop as uid:gid 70:70 ==="
run_as_postgres "$old_root" "$postgres_bin_dir/postgres" --version
start_cluster "$old_root"
stop_cluster "$old_root"

say "=== Deepest-first lazy unmount of old root ==="
findmnt -Rrn -o TARGET "$old_root/dev" |
  awk '{ depth = gsub("/", "/"); print depth, $0 }' |
  sort -k1,1nr |
  cut -d' ' -f2-
unmount_tree "$old_root/dev"

say "=== State after old-root unmount ==="
for target in \
  /dev \
  /dev/shm \
  "$old_root/dev" \
  "$old_root/dev/shm" \
  "$new_root/dev" \
  "$new_root/dev/shm"; do
  show_mount "$target"
done
stat -c '%a %u:%g %n' \
  /dev \
  /dev/shm \
  "$new_root/dev" \
  "$new_root/dev/shm"

for target in / /dev /dev/shm; do
  require_private_mount "$target" ||
    record_failure "$target did not retain private propagation"
done
[[ $(stat -c '%a %u:%g' /dev/shm) == "1777 0:0" ]] ||
  record_failure "Guest /dev/shm is not mode 1777 and root-owned"
[[ $(stat -c '%a %u:%g' "$new_root/dev/shm") == "1777 0:0" ]] ||
  record_failure "replacement-root /dev/shm is not mode 1777 and root-owned"

if ! setpriv \
  --reuid="$postgres_uid" \
  --regid="$postgres_gid" \
  --clear-groups \
  sh -c 'name=/dev/shm/cats-posix-shm-file-$$; : > "$name"; rm "$name"'; then
  record_failure "uid 70 cannot create an object in Guest /dev/shm"
fi

say "=== PostgreSQL 17 replacement-root restart as uid:gid 70:70 ==="
if ! start_cluster "$new_root"; then
  cat "$new_root/tmp/postgresql.log" >&2 || true
  record_failure "PostgreSQL 17 could not create POSIX shared memory and restart"
else
  stop_cluster "$new_root"
fi

if (( failures > 0 )); then
  printf 'guest mount propagation e2e: %d failure(s)\n' "$failures" >&2
  exit 1
fi

say "PASS: recursive unmount stayed private, uid 70 retained POSIX shm access, and PostgreSQL 17 restarted"
