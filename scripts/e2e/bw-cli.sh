#!/usr/bin/env bash
# The official Bitwarden CLI against a running UwULock Server: log in, make a folder and items,
# change one, move it to the trash and back, sync, log out and in again, and check what comes
# back is what went in. Every step is a Bitwarden client talking to this server, with
# Bitwarden's own crypto.
#
#   scripts/e2e/bw-cli.sh <server url> <email> <password> [api key file]
#
# With an API key file (client_id and client_secret on two lines, as features.mjs writes it),
# the CLI also logs in with the key.
#
# Needs `bw` on the PATH (npm install -g @bitwarden/cli), `jq`, and — for a certificate from a
# test CA — NODE_EXTRA_CA_CERTS pointing at that CA.
set -euo pipefail

server=$1 email=$2 password=$3 api_key_file=${4:-}
export BITWARDENCLI_APPDATA_DIR
BITWARDENCLI_APPDATA_DIR=$(mktemp -d)
files=$(mktemp -d)
trap 'rm -rf "$BITWARDENCLI_APPDATA_DIR" "$files"' EXIT

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

step "an attachment, up and down again"
printf 'Anhang vom CLI ✧\n' > "$files/anhang.txt"
bw create attachment --file "$files/anhang.txt" --itemid "$item" >/dev/null || fail "creating an attachment"
bw sync >/dev/null
bw get attachment anhang.txt --itemid "$item" --output "$files/zurück.txt" >/dev/null || fail "getting it"
cmp -s "$files/anhang.txt" "$files/zurück.txt" || fail "the attachment came back different"

step "a Send, and receiving it"
url=$(bw send -n "CLI-Send" "Grüße vom CLI" | jq -r .accessUrl) || fail "creating a Send"
[ "$(bw receive "$url")" = "Grüße vom CLI" ] || fail "receiving the Send"
url=$(bw send -n "Mit Passwort" --password "miau" "Nur mit Passwort" | jq -r .accessUrl) || fail "a Send with a password"
# The wrong one first: after the right one the CLI keeps the Send's token for a while.
if bw receive --password falsch "$url" >/dev/null 2>&1; then fail "a wrong Send password opened it"; fi
[ "$(bw receive --password miau "$url")" = "Nur mit Passwort" ] || fail "receiving it with the password"

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

if [ -n "$api_key_file" ]; then
  step "log in with the API key, then unlock"
  { read -r BW_CLIENTID; read -r BW_CLIENTSECRET; } < "$api_key_file"
  export BW_CLIENTID BW_CLIENTSECRET
  bw login --apikey >/dev/null || fail "bw login --apikey"
  BW_SESSION=$(bw unlock "$password" --raw) || fail "bw unlock after the API key"
  export BW_SESSION
  [ "$(bw get password "$item")" = correct-horse ] || fail "the vault after the API key"
  bw logout >/dev/null
fi

echo "bw CLI: all good"
