#!/usr/bin/env bash
# The tests, quietly: one line per step, and only when something fails, what failed. The full
# output of the last run of each step stays in target/test-logs/ for a closer look.
#
#   scripts/test.sh                  the Rust workspace: unit and integration tests
#   scripts/test.sh ciphers          only tests whose names contain "ciphers"
#   scripts/test.sh -p uwulock-api   one crate; anything else goes to `cargo test` as it is
#   scripts/test.sh --all            also rustfmt, clippy, the web vault's WebAssembly tests and
#                                    its format, lint (with the i18n check), types and tests
#
# On a shared machine, set CARGO_BUILD_JOBS first.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
logs=target/test-logs
mkdir -p "$logs"

all=false
args=()
for arg in "$@"; do
  case "$arg" in
    --all) all=true ;;
    *) args+=("$arg") ;;
  esac
done

failed=0
# How many lines of a failure to show; the rest is in the log.
show=${TEST_SH_LINES:-120}

# Seconds with a fraction where bash has them (5 and newer), whole ones elsewhere.
now() { local t=${EPOCHREALTIME:-$(date +%s)}; echo "${t/,/.}"; }
took() { awk -v from="$1" -v to="$(now)" 'BEGIN { printf "%.1fs", to - from }'; }

# step <name> <log> <command…>: run it, print one line, and on failure the head of what it said.
step() {
  local name=$1 log=$logs/$2.log start
  shift 2
  start=$(now)
  if "$@" >"$log" 2>&1; then
    printf 'ok    %-22s %s\n' "$name" "$(took "$start")"
  else
    printf 'FAIL  %-22s %s  (full output: %s)\n' "$name" "$(took "$start")" "$log"
    grep -v '^\s*$' "$log" | head -n "$show" | sed 's/^/      /'
    failed=1
  fi
}

# pnpm from inside web/, where it picks the version web/package.json asks for.
# shellcheck disable=SC2329 # called through step
in_web() { (cd web && "$@"); }

rust_tests() {
  local log=$logs/cargo-test.log start scope=(--workspace)
  for arg in ${args[@]+"${args[@]}"}; do
    case "$arg" in -p | --package | -p* | --package=*) scope=() ;; esac
  done
  start=$(now)
  # The odd expansions keep an empty array from counting as unset in older bash.
  cargo test -q --locked --no-fail-fast ${scope[@]+"${scope[@]}"} ${args[@]+"${args[@]}"} >"$log" 2>&1
  local status=$?
  # Every test binary ends with a line like
  # "test result: ok. 124 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.76s".
  local counts
  counts=$(awk '/^test result:/ { p += $4; f += $6; i += $8 } END { printf "%d passed, %d failed, %d ignored", p, f, i }' "$log")
  if [ "$status" -eq 0 ]; then
    printf 'ok    %-22s %s  %s\n' "rust tests" "$(took "$start")" "$counts"
    return
  fi
  failed=1
  printf 'FAIL  %-22s %s  %s  (full output: %s)\n' "rust tests" "$(took "$start")" "$counts" "$log"
  if grep -q '^failures:$' "$log"; then
    # What the failing tests printed, and their names — without the dots of the passing ones.
    awk '/^failures:$/ { on = 1 } /^test result:/ { on = 0 } on' "$log" | head -n "$show" | sed 's/^/      /'
  else
    # It did not build: the compiler's errors.
    grep -E -A14 '^error' "$log" | head -n "$show" | sed 's/^/      /'
  fi
}

if $all; then
  step "rustfmt" rustfmt cargo fmt --all --check
  step "clippy" clippy cargo clippy -q --workspace --all-targets --locked -- -D warnings
fi

rust_tests

if $all; then
  if [ -d web/node_modules ]; then
    step "web wasm tests" web-wasm cargo test -q --locked --manifest-path web/wasm/Cargo.toml
    # The page's types include the WebAssembly's; built once, then again only by `pnpm wasm`.
    [ -f web/src/wasm/pkg/core.js ] || step "web wasm build" web-wasm-build in_web pnpm run --silent wasm
    step "web format" web-format in_web pnpm run --silent format:check
    step "web lint + i18n" web-lint in_web pnpm run --silent lint
    step "web types" web-types in_web pnpm run --silent typecheck
    step "web tests" web-tests in_web pnpm exec vitest run --reporter=dot
  else
    echo "skip  web                    no web/node_modules: run pnpm install in web/ first"
  fi
fi

exit "$failed"
