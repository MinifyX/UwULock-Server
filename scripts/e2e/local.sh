#!/usr/bin/env bash
# The browser tests on this machine: a server of the last `cargo build` (with the web vault
# built into it) on a free port of its own, an admin account, then the scripts named.
#
#   scripts/e2e/local.sh web operations     # web.mjs with its invitation, then operations.mjs
#   scripts/e2e/local.sh operations         # an account registered without a browser first
#   scripts/e2e/local.sh family             # a family in the browser, then with Bitwarden's CLI
#
# Plain http on localhost, which browsers count as secure: the tests that need WebAuthn
# (features.mjs) need the test certificate of CI instead. Screenshots go to target/e2e-shots.
#
# Where the machine's own Chromium lacks libraries, E2E_DOCKER=1 runs the scripts in
# Playwright's image (with the host's network, so they reach the server here).
set -euo pipefail

cd "$(dirname "$0")/../.."
binary=${UWULOCK_BINARY:-target/debug/uwulock-server}
[ -x "$binary" ] || { echo "no $binary: cargo build -p uwulock-server first"; exit 1; }
[ -d scripts/e2e/node_modules ] || (cd scripts/e2e && pnpm install --frozen-lockfile)

# A port nobody has now: the kernel picks it.
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
work=$(mktemp -d)
trap 'kill "$server" 2>/dev/null || true; rm -rf "$work"' EXIT
mkdir -p "$work/data" "$work/offsite" target/e2e-shots

export UWULOCK_DATA=$work/data UWULOCK_LISTEN=127.0.0.1:$port UWULOCK_PUBLIC=http://localhost:$port
export UWULOCK_TLS=off UWULOCK_UPDATE_CHECK=off UWULOCK_LOGIN_ATTEMPTS=200
origin=$UWULOCK_PUBLIC email=nyu@example.com password='correct horse battery staple'

link=$("$binary" invite --admin "$email" | tail -1)
"$binary" serve >"$work/server.log" 2>&1 &
server=$!
for _ in $(seq 1 50); do curl -sf "$origin/alive" >/dev/null && break; sleep 0.2; done

node_() {
  if [ -n "${E2E_DOCKER:-}" ]; then
    docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:$PWD" -w "$PWD" \
      -e CHROMIUM=/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell \
      mcr.microsoft.com/playwright:v1.63.0-noble node "$@"
  else
    node "$@"
  fi
}

# What the server said, when a test failed.
trap 'tail -n 40 "$work/server.log"' ERR

registered=false
for test in "$@"; do
  case $test in
    web) node_ scripts/e2e/web.mjs "$link" target/e2e-shots; registered=true ;;
    *)
      if ! $registered; then
        node scripts/e2e/register.mjs "$origin" "$link" "$email" "$password"
        registered=true
      fi
      case $test in
        operations) node_ scripts/e2e/operations.mjs "$origin" "$email" "$password" "$work/offsite" target/e2e-shots ;;
        sso) node_ scripts/e2e/sso.mjs "$origin" "$email" "$password" target/e2e-shots ;;
        family)
          node_ scripts/e2e/family.mjs "$origin" "$email" "$password" target/e2e-shots
          PATH=$PWD/scripts/e2e/node_modules/.bin:$PATH \
            scripts/e2e/bw-family.sh "$origin" "$email" "$password" mio@example.com 'mio horse battery staple'
          ;;
        *) node_ "scripts/e2e/$test.mjs" "$origin" "$email" "$password" ;;
      esac
      ;;
  esac
done
