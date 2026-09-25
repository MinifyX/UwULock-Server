#!/usr/bin/env bash
# The official Bitwarden CLI against a running UwULock Server: log in, make a folder and items,
# change one, move it to the trash and back, sync, log out and in again, and check what comes
# back is what went in. Every step is a Bitwarden client talking to this server, with
# Bitwarden's own crypto.
#
#   scripts/e2e/bw-cli.sh <server url> <email> <password>
#
# Needs `bw` on the PATH (npm install -g @bitwarden/cli), `jq`, and — for a certificate from a
# test CA — NODE_EXTRA_CA_CERTS pointing at that CA.
set -euo pipefail

server=$1 email=$2 password=$3
export BITWARDENCLI_APPDATA_DIR
BITWARDENCLI_APPDATA_DIR=$(mktemp -d)
trap 'rm -rf "$BITWARDENCLI_APPDATA_DIR"' EXIT

step() { printf '== %s\n' "$*"; }
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

bw config server "$server" >/dev/null
step "log in"
BW_SESSION=$(bw login "$email" "$password" --raw) || fail "bw login"
export BW_SESSION
bw sync >/dev/null
# The account may have items from an earlier run: count from here.
before=$(bw list items | jq length)

step "a folder and two items"
folder=$(bw get template folder | jq -c '.name = "Arbeit"' | bw encode | bw create folder | jq -r .id)
item=$(bw get template item | jq -c --arg folder "$folder" '
  .name = "Router" | .folderId = $folder | .notes = "im Keller" |
  .login = {username: "admin", password: "hunter2", totp: "JBSWY3DPEHPK3PXP",
            uris: [{uri: "https://router.example.com", match: null}]}' |
  bw encode | bw create item | jq -r .id)
bw get template item | jq -c '.type = 2 | .name = "Notiz" | .notes = "geheim" | .secureNote = {type: 0} | .login = null' |
  bw encode | bw create item >/dev/null

step "what came back is what went in"
bw sync >/dev/null
[ "$(bw list items | jq length)" = $((before + 2)) ] || fail "two items"
got=$(bw get item "$item")
[ "$(jq -r .login.password <<<"$got")" = hunter2 ] || fail "the password"
[ "$(jq -r .notes <<<"$got")" = "im Keller" ] || fail "the notes"
[ "$(jq -r .folderId <<<"$got")" = "$folder" ] || fail "the folder"
[ "$(bw get totp "$item" | wc -c)" -ge 6 ] || fail "a TOTP code"

step "change it"
jq -c '.login.password = "correct-horse" | .favorite = true' <<<"$got" | bw encode | bw edit item "$item" >/dev/null
bw sync >/dev/null
[ "$(bw get password "$item")" = correct-horse ] || fail "the changed password"

step "trash and back"
bw delete item "$item" >/dev/null
bw sync >/dev/null
[ "$(bw list items | jq length)" = $((before + 1)) ] || fail "one item left outside the trash"
bw restore item "$item" >/dev/null
bw sync >/dev/null
[ "$(bw list items | jq length)" = $((before + 2)) ] || fail "restored"

step "log out, log in again, everything still opens"
bw logout >/dev/null
BW_SESSION=$(bw login "$email" "$password" --raw) || fail "second login"
export BW_SESSION
[ "$(bw get password "$item")" = correct-horse ] || fail "after logging in again"
bw list folders | jq -e --arg id "$folder" '.[] | select(.id == $id) | .name == "Arbeit"' >/dev/null || fail "the folder name"

step "a wrong password is refused"
bw logout >/dev/null
if bw login "$email" "not the password" --raw >/dev/null 2>&1; then fail "a wrong password logged in"; fi

echo "bw CLI: all good"
