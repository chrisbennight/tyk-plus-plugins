#!/bin/bash
# Publishes into one policy store as several members of its group, each with
# a different primary group and umask, and checks that every member can
# publish and roll back and that every published set stays readable by the
# store's group. Run as root in a Debian-based Go image from the repository
# root; it creates its own users.
set -euo pipefail

fail() { echo "FAILED: $*" >&2; exit 1; }

# The module builds inside the Tyk workspace, which supplies some checksums;
# built on its own, Go records the missing ones in this container only.
build=$(mktemp -d)
cp -R plugins/mcp-pdp "$build/"
(cd "$build/mcp-pdp" && CGO_ENABLED=0 go build -mod=mod -o /usr/local/bin/cedar-policy ./cmd/cedar-policy)

groupadd policy
for user in alice bob reader; do
  groupadd "${user}_own"
  useradd -m -g "${user}_own" -G policy "$user"
done

store=/srv/policy
mkdir -p "$store"
chgrp policy "$store"
chmod 2770 "$store"

# as USER UMASK COMMAND... runs a command as USER with that umask.
as() {
  local user=$1 mask=$2
  shift 2
  su "$user" -s /bin/bash -c "umask $mask; $(printf '%q ' "$@")"
}

source_dir() {
  local dir
  dir=$(mktemp -d)
  printf '%s\n' "$1" > "$dir/rules.cedar"
  echo '{}' > "$dir/approved_tools.json"
  echo '[]' > "$dir/checks.json"
  chmod -R a+rX "$dir"
  echo "$dir"
}

first=$(source_dir '// first')
second=$(source_dir '// second')

# The first publisher's restrictive umask must not lock anyone else out.
set_a=$(as alice 077 cedar-policy promote -store "$store" -label first "$first") || fail "alice could not publish into a new store"
set_b=$(as bob 0177 cedar-policy promote -store "$store" -label second "$second") || fail "bob could not publish after alice"
active_is() { grep -q "\"set\": \"$1\"" "$store/active" || fail "active does not name $1 after $2"; }
active_is "$set_b" "bob's publish"

# A member that never published, such as the gateway's user, can read every
# file as each publisher wrote it.
readable() {
  for set in "$set_a" "$set_b"; do
    for file in manifest.json rules.cedar approved_tools.json approved_instructions.json checks.json; do
      as reader 022 cat "$store/sets/$set/$file" >/dev/null || fail "reader cannot read $file in set $set $1"
    done
  done
  as reader 022 cat "$store/active" >/dev/null || fail "reader cannot read the active pointer $1"
}
readable "as first published"

# Each member can switch to a set the other published.
as bob 022 cedar-policy activate -store "$store" "$set_a" >/dev/null || fail "bob could not switch to alice's set"
active_is "$set_a" "bob switched to alice's set"
as alice 077 cedar-policy activate -store "$store" "$set_b" >/dev/null || fail "alice could not switch to bob's set"
active_is "$set_b" "alice switched to bob's set"

# A member can repair a damaged set another member published.
rm "$store/sets/$set_a/rules.cedar"
[ "$(as bob 022 cedar-policy promote -store "$store" "$first")" = "$set_a" ] || fail "bob could not repair alice's set"
grep -q '"label": "first"' "$store/sets/$set_a/manifest.json" || fail "the repaired set lost its label"

# Everything published belongs to the store's group and stays readable.
wrong=$(find "$store" ! -group policy -printf '%p %g\n')
[ -z "$wrong" ] || fail "published outside the store's group: $wrong"
readable "after the repair"

echo "Verified that group members with different umasks can publish, roll back and repair a shared store."
