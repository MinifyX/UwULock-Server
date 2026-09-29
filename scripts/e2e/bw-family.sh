#!/usr/bin/env bash
# The family family.mjs made, with Bitwarden's official CLI: the owner makes an item in the
# family's collection and moves a personal one in (`bw create item` with organizationId and
# collectionIds, `bw move`); the member's CLI opens all of them — the one the web vault moved in
# too — with Bitwarden's own crypto.
#
#   scripts/e2e/bw-family.sh <server url> <owner email> <owner password> <member email> <member password>
#
# Needs `bw` on the PATH, `jq`, and — for a certificate from a test CA — NODE_EXTRA_CA_CERTS.
set -euo pipefail

server=$1 owner=$2 owner_password=$3 member=$4 member_password=$5
dirs=()
trap 'rm -rf "${dirs[@]}"' EXIT

step() { printf '== %s\n' "$*"; }
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

# log_in <email> <password>: a CLI of its own for that account.
log_in() {
  BITWARDENCLI_APPDATA_DIR=$(mktemp -d)
  dirs+=("$BITWARDENCLI_APPDATA_DIR")
  export BITWARDENCLI_APPDATA_DIR
  bw config server "$server" >/dev/null
  BW_SESSION=$(bw login "$1" "$2" --raw) || fail "bw login $1"
  export BW_SESSION
  bw sync >/dev/null
}

step "the owner: the family and its collection"
log_in "$owner" "$owner_password"
org=$(bw list organizations | jq -r '.[] | select(.name == "Katzen") | .id')
[ -n "$org" ] || fail "the family"
collection=$(bw list org-collections --organizationid "$org" | jq -r '.[] | select(.name == "Allgemein") | .id')
[ -n "$collection" ] || fail "its collection"

step "an item made in the collection, and a personal one moved in"
bw get template item | jq -c --arg org "$org" --arg col "$collection" '
  .name = "Vom CLI" | .organizationId = $org | .collectionIds = [$col] | .notes = null |
  .login = {username: "cli", password: "aus-dem-cli", totp: null, uris: []}' |
  bw encode | bw create item >/dev/null || fail "an item of the family"
mine=$(bw get template item | jq -c '.name = "Zum Verschieben" | .notes = null |
  .login = {username: "mine", password: "verschoben", totp: null, uris: []}' |
  bw encode | bw create item | jq -r .id)
jq -cn --arg col "$collection" '[$col]' | bw encode | bw move "$mine" "$org" >/dev/null || fail "bw move"
bw sync >/dev/null
[ "$(bw list items --organizationid "$org" | jq length)" = 3 ] || fail "three items in the family"

step "the member's CLI opens all of them"
log_in "$member" "$member_password"
items=$(bw list items --organizationid "$org")
[ "$(jq length <<<"$items")" = 3 ] || fail "the member sees three items"
password_of() { jq -r --arg name "$1" '.[] | select(.name == $name) | .login.password' <<<"$items"; }
[ "$(password_of Streaming)" = 'Miau-2026!' ] || fail "the item the web vault moved in"
[ "$(password_of 'Vom CLI')" = aus-dem-cli ] || fail "the item made in the collection"
[ "$(password_of 'Zum Verschieben')" = verschoben ] || fail "the item bw move moved in"

echo "Bitwarden's CLI with a family: made, moved, read by the member: all good"
