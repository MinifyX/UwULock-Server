#!/usr/bin/env bash
# UwULock Server, from an empty machine to a running password server.
#
#   curl -fsSLO https://github.com/MinifyX/UwULock-Server/releases/latest/download/install.sh
#   sudo bash install.sh
#
# It installs Docker when it is missing, asks how your clients reach this machine, sets up
# /opt/uwulock and starts the server. Every answer is a flag as well, so it can run without
# questions:
#
#   sudo bash install.sh --domain vault.example.com --yes
#   sudo bash install.sh --behind-proxy https://vault.example.com --yes
#   sudo bash install.sh --behind-proxy https://vault.example.com --proxy-network proxy --yes
#
#   --dir DIR              where UwULock Server lives (default /opt/uwulock)
#   --domain NAME          the server gets its own certificate from Let's Encrypt for NAME. NAME
#                          has to point to this machine, and port 443 has to reach it.
#   --acme-email ADDRESS   where Let's Encrypt writes when a certificate is about to run out
#   --acme-staging         Let's Encrypt's test CA, for trying things out (browsers won't trust it)
#   --behind-proxy URL     a reverse proxy in front does TLS and answers on URL, like
#                          https://vault.example.com; the server then listens on 127.0.0.1 only
#   --proxy-network NET    the proxy runs as a container on this machine, in the Docker network
#                          NET: the server joins NET instead of taking a port here, and the proxy
#                          reaches it at http://uwulock:8443
#   --proxy-ip ADDRESS     a fixed IPv4 address for the server in NET, needed in ipvlan and
#                          macvlan networks; the proxy then reaches it at http://ADDRESS:8443
#   --admin ADDRESS        invite ADDRESS as the first admin: the link to register with is shown at
#                          the end (and mailed, once the server can send mail)
#   --bind X               where it listens here: a port, or address:port (default 443 with
#                          --domain, 127.0.0.1:8443 behind a proxy)
#   --version TAG          latest (default), beta, edge, or an exact version like 0.1.0
#   --no-update-check      the server never asks GitHub whether there is a newer release
#   --no-docker-install    stop instead of installing Docker when it is missing
#   --from-checkout        take compose.yaml and the rest from the repository this script is in
#   --no-pull              start the image already on this machine (for trying a build)
#   --yes                  ask nothing; whatever is not passed keeps its default
#   --help
#
# The whole way, with a reverse proxy, backups and updates: docs/deployment.md.
set -uo pipefail

repo=MinifyX/UwULock-Server
releases="https://github.com/$repo/releases"
service=uwulock
here="$(cd "$(dirname "$0")" && pwd)"

dir=/opt/uwulock
domain=""
acme_email=""
acme_directory=letsencrypt
proxy=""
proxy_network=""
proxy_ip=""
admin=""
bind=""
version=latest
update_check=on
docker_install=true
from_checkout=false
pull=true
ask=true

die() {
  printf '\n  (>_<) %s\n' "$1" >&2
  exit 1
}
step() { printf '  %s\n' "$1"; }
warn() { printf '  (>_<) %s\n' "$1" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="${2:?--dir needs a directory}"; shift 2 ;;
    --domain) domain="${2:?--domain needs a name}"; shift 2 ;;
    --acme-email) acme_email="${2:?--acme-email needs an address}"; shift 2 ;;
    --acme-staging) acme_directory=staging; shift ;;
    --behind-proxy) proxy="${2:?--behind-proxy needs the address the proxy answers on}"; shift 2 ;;
    --proxy-network) proxy_network="${2:?--proxy-network needs the name of a Docker network}"; shift 2 ;;
    --proxy-ip) proxy_ip="${2:?--proxy-ip needs an address}"; shift 2 ;;
    --admin) admin="${2:?--admin needs an e-mail address}"; shift 2 ;;
    --bind) bind="${2:?--bind needs a port}"; shift 2 ;;
    --version) version="${2:?--version needs a tag}"; shift 2 ;;
    --no-update-check) update_check=off; shift ;;
    --no-docker-install) docker_install=false; shift ;;
    --from-checkout) from_checkout=true; shift ;;
    --no-pull) pull=false; shift ;;
    --yes | -y) ask=false; shift ;;
    -h | --help)
      # Piped into bash, there is no file to read the help from.
      if [ -f "$0" ]; then sed -n '2,/^set /{/^#/p}' "$0" | sed 's/^# \{0,1\}//'; else
        printf 'Download it first to read the help: %s/latest/download/install.sh\n' "$releases"
      fi
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "please run this as root: sudo bash install.sh"

# ── small helpers ─────────────────────────────────────────────────────────────────────────────
# Whether there is a terminal to ask on. A device node that is there is not the same as one that
# answers, so this opens it rather than looking at it.
have_tty() { { : </dev/tty; } 2>/dev/null; }

askfor() {
  local prompt="$1" fallback="${2:-}" answer=""
  if ! $ask || ! have_tty; then
    printf '%s' "$fallback"
    return 0
  fi
  if [ -n "$fallback" ]; then
    read -r -p "  $prompt [$fallback]: " answer </dev/tty
  else
    read -r -p "  $prompt: " answer </dev/tty
  fi
  printf '%s' "${answer:-$fallback}"
}

yesno() {
  local prompt="$1" fallback="$2" answer=""
  if ! $ask || ! have_tty; then
    [ "$fallback" = y ] && return 0 || return 1
  fi
  read -r -p "  $prompt [$([ "$fallback" = y ] && echo 'Y/n' || echo 'y/N')]: " answer </dev/tty
  answer="${answer:-$fallback}"
  case "$answer" in [yYjJ]*) return 0 ;; *) return 1 ;; esac
}

fetch() {
  local url="$1" target="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsL --proto '=https' --tlsv1.2 -o "$target" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$target" "$url"
  else
    die "neither curl nor wget is here, so nothing can be downloaded"
  fi
}

# The newest release of any kind, beta included: GitHub's "latest" only knows stable ones.
newest_tag() {
  local list tag
  list=$(mktemp) || return 1
  if fetch "https://api.github.com/repos/$repo/releases?per_page=10" "$list"; then
    tag=$(grep -oE '"tag_name": *"v[0-9][A-Za-z0-9.-]*"' "$list" | head -1 |
      sed -E 's/.*"(v[^"]+)"$/\1/')
  fi
  rm -f "$list"
  printf '%s' "${tag:-}"
}

# Where the files for a tag are: that version's own release, the newest one of any kind for beta,
# and the newest stable one for everything else.
release_base() {
  local tag
  case "$1" in
    [0-9]*) printf '%s/download/v%s' "$releases" "$1" ;;
    beta)
      tag=$(newest_tag)
      if [ -n "$tag" ]; then printf '%s/download/%s' "$releases" "$tag"; else
        printf '%s/latest/download' "$releases"
      fi
      ;;
    *) printf '%s/latest/download' "$releases" ;;
  esac
}

# A release file and the checksum next to it; nothing is used unless the two agree. That keeps a
# broken download out. It does not keep out a release somebody replaced: the checksum comes from
# the same place, and trusting it is trusting the release, as with the image itself.
fetch_checked() {
  local name="$1" target="$2" base="$3" sums want have
  fetch "$base/$name" "$target" || return 1
  sums=$(mktemp) || return 1
  if ! fetch "$base/$name.sha256" "$sums"; then
    rm -f "$sums"
    return 1
  fi
  want=$(cut -d' ' -f1 <"$sums")
  have=$(sha256sum "$target" | cut -d' ' -f1)
  rm -f "$sums"
  [ -n "$want" ] && [ "$want" = "$have" ]
}

# The files come from the release — or, when asked for with --from-checkout, from the repository
# this script sits in. Never by guessing from the directory: piped into bash, "here" is wherever
# root happened to be, and whatever somebody left there would be installed as root.
take() {
  local name="$1" target="$2" asset="${3:-$1}"
  if $from_checkout; then
    [ -f "$here/$name" ] || die "--from-checkout, but there is no $name next to this script"
    install -m 0644 "$here/$name" "$target"
    step "$name from this checkout"
  else
    fetch_checked "$asset" "$target" "$files_from" ||
      die "$asset could not be downloaded, or its checksum did not match; nothing was started"
    step "$name from the $version release"
  fi
}

hash_of() { sha256sum "$1" | cut -d' ' -f1; }

# A value on its way into the .env has to be one line of plain characters. The answers are checked
# for that below already; this is the same check update.sh makes, so the two cannot drift apart.
plain_value() { case "${1:-}" in "" | *[!a-zA-Z0-9.:_/+@\[\]-]*) return 1 ;; *) return 0 ;; esac; }

# Writes one line of the .env, whether it is in there already, commented out, or missing.
set_env() {
  local key="$1" value="$2" file="$dir/.env" line found=false tmp="$dir/.env.tmp"
  plain_value "$value" || die "$key would become something odd, so nothing was written: $value"
  install -m 0600 /dev/null "$tmp"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="* | "#$key="*)
        if $found; then continue; fi
        printf '%s=%s\n' "$key" "$value" >>"$tmp"
        found=true
        ;;
      *) printf '%s\n' "$line" >>"$tmp" ;;
    esac
  done <"$file"
  $found || printf '%s=%s\n' "$key" "$value" >>"$tmp"
  cat "$tmp" >"$file"
  rm -f "$tmp"
}
trap 'rm -f "$dir/.env.tmp"' EXIT INT TERM

# A name a certificate can be issued for: letters, digits and dashes, with at least one dot.
valid_domain() {
  [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$ ]]
}

# A port, or an address:port, the way Compose wants it. The number has to be one a port can be.
valid_bind() {
  [[ "$1" =~ ^(\[[0-9a-fA-F:]+\]:|[0-9]{1,3}(\.[0-9]{1,3}){3}:)?[0-9]{1,5}$ ]] || return 1
  local port=$((10#${1##*:}))
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}
port_of() { printf '%s' "${1##*:}"; }
on_loopback() { case "$1" in 127.0.0.1:* | "[::1]:"*) return 0 ;; *) return 1 ;; esac; }

# A Docker network's name, the characters Docker allows in one.
valid_network() { [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]]; }

valid_ipv4() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  local part
  for part in ${1//./ }; do [ $((10#$part)) -le 255 ] || return 1; done
}

# ── the answers, checked before anything happens ──────────────────────────────────────────────
# Every one of them goes into the .env or a download address, so each is one line of plain
# characters: a line break in one would become a second setting that Compose reads as its own.
case "$version" in
  "" | *[!a-zA-Z0-9._-]*) die "a version is letters, digits, dots, dashes and underscores: $version" ;;
esac
[ -n "$domain" ] && [ -n "$proxy" ] && die "--domain or --behind-proxy, not both"
if [ -n "$domain" ]; then
  domain="${domain#https://}"
  domain="${domain%/}"
  valid_domain "$domain" || die "--domain wants a name like vault.example.com, not $domain"
fi
if [ -n "$acme_email" ]; then
  [[ "$acme_email" =~ ^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] ||
    die "--acme-email wants an address like admin@example.com, not $acme_email"
fi
if [ -n "$proxy" ]; then
  case "$proxy" in
    https://*) ;;
    *) die "--behind-proxy wants the https address the proxy answers on, like https://vault.example.com" ;;
  esac
  proxy="${proxy%/}"
  case "${proxy#https://}" in
    "" | */* | *[!a-zA-Z0-9.:_-]*) die "that address holds characters an address does not: $proxy" ;;
  esac
fi
if [ -n "$bind" ]; then
  valid_bind "$bind" || die "--bind wants a port from 1 to 65535, or an address:port, not $bind"
fi
# Behind a proxy the server believes the address the proxy passes on. Reachable past the proxy,
# anybody could pass on whatever address they like; Docker's ports get past ufw, too.
if [ -n "$proxy" ] && [ -n "$bind" ] && ! on_loopback "$bind"; then
  die "behind a proxy the server listens on this machine only: --bind 127.0.0.1:$(port_of "$bind")"
fi
if [ -n "$proxy_network" ]; then
  valid_network "$proxy_network" || die "--proxy-network wants the name of a Docker network, not $proxy_network"
  [ -n "$domain" ] && die "--proxy-network is for a proxy in front of the server, not with --domain"
  [ -n "$bind" ] && die "--proxy-network or --bind, not both: in the proxy's network the server takes no port here"
fi
if [ -n "$proxy_ip" ]; then
  [ -n "$proxy_network" ] || die "--proxy-ip is an address in the proxy's network: it needs --proxy-network too"
  valid_ipv4 "$proxy_ip" || die "--proxy-ip wants an IPv4 address like 192.0.2.10, not $proxy_ip"
fi
valid_email() { [[ "$1" =~ ^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; }
if [ -n "$admin" ]; then
  valid_email "$admin" || die "--admin wants an address like you@example.com, not $admin"
fi

# What is in the directory runs as root: Compose starts whatever compose.yaml and .env say. So it
# has to belong to root, or to the admin who ran sudo, and nobody else may write to it — nor to a
# directory above it, where somebody could swap it out. A directory anybody may write to is fine
# above it only with the sticky bit, which keeps them from renaming what is not theirs (/tmp, say).
# The same rules as update.sh's.
admin_uid="${SUDO_UID:-0}"
owned_right() {
  local owner mode
  owner=$(stat -c %u "$1" 2>/dev/null) && mode=$(stat -c %a "$1" 2>/dev/null) || return 1
  { [ "$owner" = 0 ] || [ "$owner" = "$admin_uid" ]; } || return 1
  if [ $((8#$mode & 8#022)) -ne 0 ]; then
    [ "${2:-}" = above ] || return 1
    [ $((8#$mode & 8#1000)) -ne 0 ] || return 1
  fi
}
# $1 and every directory above it.
trusted_path() {
  local above="$1"
  while [ "$above" != / ]; do
    above=$(dirname "$above")
    owned_right "$above" above || die "$above may be changed by someone other than root, and what is in $1 runs as root. Install into a directory only root may change, like /opt/uwulock."
  done
}
case "$dir" in
  /*) ;;
  *) dir="$PWD/$dir" ;;
esac
dir=$(realpath -m -- "$dir") || die "there is no way to $dir"
[ "$dir" != / ] || die "--dir / is not a directory to install into"
if [ -L "$dir" ]; then
  die "$dir is a link; install into the directory itself"
elif [ -e "$dir" ]; then
  [ -d "$dir" ] || die "$dir is not a directory"
  owned_right "$dir" || die "$dir may be changed by someone other than root. Make it root's and writable only by root: sudo chown root: $dir && sudo chmod go-w $dir"
fi
trusted_path "$dir"
if $from_checkout; then
  # What comes from the checkout is installed as root, so the same rules hold for it.
  owned_right "$here" || die "--from-checkout, but somebody other than root or you may change $here"
  for name in compose.yaml .env.example update.sh; do
    [ ! -e "$here/$name" ] && continue
    if [ -L "$here/$name" ] || ! owned_right "$here/$name"; then
      die "--from-checkout, but somebody other than root or you may change $here/$name"
    fi
  done
  trusted_path "$here"
fi

if $ask && ! have_tty; then
  die "there is no terminal to ask on. Pass --domain ... or --behind-proxy ..., and --yes."
fi
if ! $ask && [ -z "$domain" ] && [ -z "$proxy" ]; then
  die "without questions it needs --domain NAME or --behind-proxy URL"
fi

printf '\n  UwULock Server\n  ~~~~~~~~~~~~~~\n\n'

if [ -f "$dir/.env" ]; then
  die "$dir is set up already. A newer version? cd $dir && sudo bash update.sh"
fi

# ── Docker ────────────────────────────────────────────────────────────────────────────────────
# The one thing this needs that a fresh machine does not have. Docker's own script knows every
# common distribution and brings Compose along; the log stays behind when it goes wrong.
install_docker() {
  local script log
  script=$(mktemp)
  log=$(mktemp /tmp/uwulock-docker-XXXXXX.log)
  step "installing Docker with Docker's own script (a minute or two)"
  fetch https://get.docker.com "$script" || die "Docker's install script could not be downloaded"
  # Not from standard input: piped into bash, that is the rest of this script.
  if ! sh "$script" </dev/null >"$log" 2>&1; then
    tail -n 15 "$log" | sed 's/^/      /' >&2
    die "Docker did not install. All it said is in $log"
  fi
  rm -f "$script" "$log"
}

if ! command -v docker >/dev/null 2>&1; then
  $docker_install ||
    die "Docker is missing. How to get it: https://docs.docker.com/engine/install/"
  yesno "Docker is not installed. Install it now, from get.docker.com?" y ||
    die "stopped. Docker first, then this again: https://docs.docker.com/engine/install/"
  install_docker
fi

if ! docker compose version >/dev/null 2>&1; then
  # Docker from the distribution's own packages, without the compose plugin. The package has a
  # different name everywhere: Docker's own repository, Ubuntu, Debian.
  $docker_install || die "Docker Compose v2 is missing: https://docs.docker.com/compose/install/linux/"
  yesno "Docker Compose v2 is missing. Install it now?" y || die "stopped. Compose first, then this again."
  step "installing Docker Compose"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq </dev/null >/dev/null 2>&1
    for package in docker-compose-plugin docker-compose-v2 docker-compose; do
      apt-get install -y -qq "$package" </dev/null >/dev/null 2>&1 &&
        docker compose version >/dev/null 2>&1 && break
    done
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q docker-compose-plugin </dev/null >/dev/null 2>&1
  fi
  docker compose version >/dev/null 2>&1 ||
    die "Docker Compose v2 could not be installed: https://docs.docker.com/compose/install/linux/"
fi

if ! docker info >/dev/null 2>&1; then
  command -v systemctl >/dev/null 2>&1 && systemctl enable --now docker >/dev/null 2>&1
  docker info >/dev/null 2>&1 || die "Docker is installed but does not answer: systemctl start docker"
fi

# ── ports ─────────────────────────────────────────────────────────────────────────────────────
# Docker only finds out that it cannot have a port when everything else is done already, and
# then it is the start that fails, on a machine that looks installed. So we look first.
port_busy() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -Hltn "sport = :$port" 2>/dev/null | grep -q .
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{ print $4 }' | grep -qE "[:.]$port$"
  else
    return 1
  fi
}

# The first free port from there on, so what we suggest is one that works.
free_from() {
  local port="$1"
  while [ "$port" -lt 65535 ] && port_busy "$port"; do port=$((port + 1)); done
  printf '%s' "$port"
}

# ── how the clients reach it ──────────────────────────────────────────────────────────────────
# The Bitwarden apps and the browser extension only talk to a server with a certificate the
# system trusts. So either the server gets one itself, or something in front of it has one.
if [ -z "$domain" ] && [ -z "$proxy" ] && [ -n "$proxy_network" ]; then
  # A proxy's network was given, so it is the proxy.
  proxy=$(askfor "The https address the proxy answers on, like https://vault.example.com")
  proxy="${proxy%/}"
  case "$proxy" in https://*) ;; *) proxy="https://$proxy" ;; esac
  case "${proxy#https://}" in
    "" | */* | *[!a-zA-Z0-9.:_-]*) die "that is not an address: $proxy" ;;
  esac
elif [ -z "$domain" ] && [ -z "$proxy" ]; then
  cat <<'CHOICE'
  How do your clients reach this server? The Bitwarden apps and the browser extension need
  https with a real certificate, so one of two ways:

    1  This server gets its own certificate from Let's Encrypt.
       You need a name (like vault.example.com) that points to this machine, and port 443
       reachable from wherever your clients are.
    2  Behind a reverse proxy you already run (Caddy, nginx, Traefik, ...).
       The proxy has the certificate; the server listens on this machine only.

CHOICE
  default_way=1
  port_busy 443 && default_way=2
  way=$(askfor "1 or 2" "$default_way")
  case "$way" in
    1)
      domain=$(askfor "The name, like vault.example.com")
      domain="${domain#https://}"
      domain="${domain%/}"
      valid_domain "$domain" || die "that is not a name a certificate can be issued for: $domain"
      acme_email=$(askfor "An e-mail address for Let's Encrypt's warnings (optional, Enter for none)")
      if [ -n "$acme_email" ] && ! valid_email "$acme_email"; then
        die "that is not an e-mail address: $acme_email"
      fi
      ;;
    2)
      proxy=$(askfor "The https address the proxy answers on, like https://vault.example.com")
      proxy="${proxy%/}"
      case "$proxy" in https://*) ;; *) proxy="https://$proxy" ;; esac
      case "${proxy#https://}" in
        "" | */* | *[!a-zA-Z0-9.:_-]*) die "that is not an address: $proxy" ;;
      esac
      ;;
    *) die "1 or 2, not $way" ;;
  esac
fi

# A proxy that runs as a container reaches nothing on this machine's 127.0.0.1: that is its own.
# So the server joins the proxy's Docker network instead, and takes no port here at all.
if [ -n "$proxy" ] && [ -z "$proxy_network" ] && [ -z "$bind" ] && $ask && have_tty; then
  cat <<'NETWORK'

  Does the proxy run as a Docker container on this machine? Then it cannot reach the server on
  127.0.0.1, which inside its container is its own. The server joins the proxy's Docker network
  instead. The networks here:

NETWORK
  docker network ls --format '{{.Name}}  ({{.Driver}})' </dev/null 2>/dev/null |
    grep -vE '^(bridge|host|none)  ' | sed 's/^/    /'
  printf '\n'
  proxy_network=$(askfor "The proxy's network (Enter if the proxy does not run in Docker here)")
  if [ -n "$proxy_network" ]; then
    valid_network "$proxy_network" || die "that is not the name of a Docker network: $proxy_network"
  fi
fi

# Nobody registers without an invitation, so the first one goes to whoever runs the server.
if [ -z "$admin" ] && $ask && have_tty; then
  printf '\n'
  admin=$(askfor "Your e-mail address, to invite you as the first admin (Enter to do it later)")
  if [ -n "$admin" ]; then
    valid_email "$admin" || die "that is not an e-mail address: $admin"
  fi
fi

if [ -n "$proxy_network" ]; then
  network_driver=$(docker network inspect --format '{{.Driver}}' "$proxy_network" </dev/null 2>/dev/null) ||
    die "there is no Docker network $proxy_network here. docker network ls lists them"
  case "$network_driver" in
    host | null) die "$proxy_network is not a network a container can join by itself" ;;
  esac
  # Docker's own default network knows no names, and a container cannot join it from Compose.
  [ "$proxy_network" = bridge ] &&
    die "Docker's default network knows no names. Put the proxy in a network of its own: docker network create proxy"
  # In an ipvlan or macvlan network the proxy reaches the server at an address in your network, so
  # it has to be one that stays, and one no other machine uses.
  case "$network_driver" in
    ipvlan | macvlan)
      if [ -z "$proxy_ip" ]; then
        subnet=$(docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$proxy_network" </dev/null 2>/dev/null)
        proxy_ip=$(askfor "$proxy_network is a $network_driver network ($subnet). A free address in it for the server")
        [ -n "$proxy_ip" ] || die "$proxy_network is a $network_driver network: the server needs a fixed address in it, --proxy-ip ADDRESS"
      fi
      ;;
  esac
  if [ -n "$proxy_ip" ]; then
    valid_ipv4 "$proxy_ip" || die "that is not an IPv4 address: $proxy_ip"
    taken=$(docker network inspect --format '{{range .Containers}}{{.IPv4Address}} {{end}}' "$proxy_network" </dev/null 2>/dev/null)
    case " $taken" in *" $proxy_ip/"*) die "$proxy_ip is taken in $proxy_network already" ;; esac
  fi
  # The override takes compose.yaml's port away with !reset, which Compose knows since 2.24.
  compose_version=$(docker compose version --short </dev/null 2>/dev/null)
  compose_version="${compose_version#v}"
  IFS=. read -r compose_major compose_minor _ <<<"$compose_version"
  if [ "${compose_major:-0}" -lt 2 ] || { [ "$compose_major" -eq 2 ] && [ "${compose_minor:-0}" -lt 24 ]; }; then
    die "joining the proxy's network needs Docker Compose 2.24 or newer, and this is $compose_version"
  fi
  [ -e "$dir/compose.override.yaml" ] &&
    die "there is a $dir/compose.override.yaml already, and joining the proxy's network would write one"
fi

if [ -n "$domain" ]; then
  # Let's Encrypt knocks on port 443 of the name, and nowhere else.
  if [ -z "$bind" ]; then
    bind=443
    port_busy 443 &&
      die "port 443 is taken on this machine, and Let's Encrypt needs it. Stop what listens there, or put this server behind that one: --behind-proxy https://$domain"
  elif [ "$(port_of "$bind")" != 443 ]; then
    warn "--bind $bind: Let's Encrypt only knocks on port 443, so something has to pass 443 on to $bind"
  fi
  # Only a hint: behind NAT this machine does not know the address the world sees.
  if command -v getent >/dev/null 2>&1 && ! getent ahosts "$domain" >/dev/null 2>&1; then
    warn "$domain does not resolve yet. Let's Encrypt can only issue the certificate once it points here."
  fi
  public="https://$domain"
elif [ -n "$proxy_network" ]; then
  # No port here; this is only what the server falls back to if the override ever goes.
  bind=127.0.0.1:8443
  if [ -n "$proxy_ip" ]; then upstream="http://$proxy_ip:8443"; else upstream="http://$service:8443"; fi
  public="$proxy"
else
  if [ -z "$bind" ]; then
    bind=127.0.0.1:8443
    if port_busy 8443; then
      if ! $ask || ! have_tty; then
        die "port 8443 is taken on this machine. Say which one to use instead: --bind 127.0.0.1:<port>"
      fi
      warn "port 8443 is taken on this machine"
      answer=$(askfor "Which port should UwULock Server listen on instead?" "$(free_from 8444)")
      valid_bind "$answer" || die "that is not a port from 1 to 65535: $answer"
      bind="127.0.0.1:$(port_of "$answer")"
    fi
  elif port_busy "$(port_of "$bind")"; then
    warn "--bind points at $bind, and that one is taken as well"
  fi
  upstream="http://$bind"
  public="$proxy"
fi

# ── the files ─────────────────────────────────────────────────────────────────────────────────
printf '\n'
files_from=""
$from_checkout || files_from=$(release_base "$version")
step "setting up $dir"
install -d -m 0755 "$dir"
[ -L "$dir" ] && die "$dir became a link while installing"
owned_right "$dir" || die "$dir may be changed by someone other than root"
take compose.yaml "$dir/compose.yaml"
take .env.example "$dir/.env.example" env.example
take update.sh "$dir/update.sh"
chmod 0755 "$dir/update.sh"

install -m 0600 "$dir/.env.example" "$dir/.env"
set_env UWULOCK_PUBLIC "$public"
set_env UWULOCK_VERSION "$version"
set_env UWULOCK_BIND "$bind"
set_env UWULOCK_UPDATE_CHECK "$update_check"
if [ -n "$domain" ]; then
  set_env UWULOCK_TLS acme
  set_env UWULOCK_TRUST_FORWARDED off
  set_env UWULOCK_ACME_DIRECTORY "$acme_directory"
  [ -n "$acme_email" ] && set_env UWULOCK_ACME_EMAIL "$acme_email"
else
  set_env UWULOCK_TLS off
  set_env UWULOCK_TRUST_FORWARDED on
fi
step "wrote $dir/.env"

# Compose lays compose.override.yaml over compose.yaml by itself, and update.sh leaves it alone.
if [ -n "$proxy_network" ]; then
  {
    printf '# Written by install.sh: the reverse proxy runs as a container in the Docker network\n'
    printf '# %s, so the server joins that network and takes no port on this machine.\n' "$proxy_network"
    printf '# The proxy reaches it at %s.\n' "$upstream"
    printf 'services:\n  %s:\n    ports: !reset []\n    networks:\n' "$service"
    if [ -n "$proxy_ip" ]; then
      printf '      "%s":\n        ipv4_address: %s\n' "$proxy_network" "$proxy_ip"
    else
      printf '      "%s": {}\n' "$proxy_network"
    fi
    printf '\nnetworks:\n  "%s":\n    name: "%s"\n    external: true\n' "$proxy_network" "$proxy_network"
  } >"$dir/compose.override.yaml"
  chmod 0644 "$dir/compose.override.yaml"
  step "wrote $dir/compose.override.yaml: the server joins $proxy_network"
fi

# update.sh replaces a compose.yaml it knows it put here, and this is how it knows.
{
  printf '# Written by install.sh and update.sh: what they put here, so they know what they may replace.\n'
  printf 'compose %s\n' "$(hash_of "$dir/compose.yaml")"
} >"$dir/.uwulock-update"
chmod 0644 "$dir/.uwulock-update"

# ── the first start ───────────────────────────────────────────────────────────────────────────
cd "$dir" || die "cannot go into $dir"

# A first start that did not work leaves nothing that stops the next try: the container goes, and
# the answers move aside to .env.failed. The data volume stays, in case there is anything in it.
give_up() {
  docker compose logs --tail 20 "$service" </dev/null 2>/dev/null | sed 's/^/      /' >&2
  docker compose down </dev/null >/dev/null 2>&1
  mv -f "$dir/.env" "$dir/.env.failed"
  # Left behind, it would lay itself over the next try, whatever that one is told.
  [ -n "$proxy_network" ] && mv -f "$dir/compose.override.yaml" "$dir/compose.override.yaml.failed"
  die "$1
      Your answers are in $dir/.env.failed$([ -n "$proxy_network" ] && printf ' and compose.override.yaml.failed'). Once the cause is fixed, run install.sh again."
}

if $pull; then
  step "fetching the image"
  docker compose pull --quiet </dev/null || give_up "the image could not be fetched"
fi

step "starting UwULock Server"
docker compose up -d </dev/null || give_up "UwULock Server did not start"

if [ -n "$domain" ]; then
  printf '  waiting for the server and its certificate'
else
  printf '  waiting for the server'
fi
healthy=false
for _ in $(seq 1 90); do
  printf '.'
  sleep 2
  case "$(docker inspect --format '{{.State.Health.Status}}' "$service" 2>/dev/null)" in
    healthy)
      healthy=true
      break
      ;;
    unhealthy) break ;;
  esac
  # A server that keeps falling over is not going to be healthy by waiting.
  [ "$(docker inspect --format '{{.RestartCount}}' "$service" 2>/dev/null)" = 0 ] || break
done
printf '\n\n'

if ! $healthy; then
  if [ -n "$domain" ] && docker compose logs --no-color "$service" </dev/null 2>/dev/null | grep -q 'no certificate yet'; then
    give_up "Let's Encrypt did not issue a certificate for $domain. Check that $domain points to this machine and that port 443 reaches it from the internet"
  fi
  give_up "the server did not come up"
fi

cat <<DONE
  UwULock Server is running (=^･ω･^=)

  Server URL    $public
  Web vault     $public
  Admin portal  $public/admin

  The server URL is the address for UwULock and for the Bitwarden browser extension and apps
  ("self-hosted", server URL).

  Next version:   cd $dir && sudo bash update.sh

DONE

# The first admin's invitation: the link comes from the server itself, which also mails it once it
# can send mail. Without a mail server the link here is the only way in, so it is shown either way.
invite_hint="cd $dir && sudo docker compose exec uwulock uwulock-server invite --admin you@example.com"
if [ -n "$admin" ]; then
  if invitation=$(docker compose exec -T "$service" uwulock-server invite --admin "$admin" </dev/null 2>/dev/null); then
    link=$(printf '%s\n' "$invitation" | grep -E '^https?://' | tail -1)
    cat <<ADMIN
  Your invitation as the first admin, $admin — open it to create your account:

    $link

  It works for 7 days. A new one:  $invite_hint

ADMIN
  else
    warn "the invitation for $admin did not work. Make one yourself: $invite_hint"
  fi
else
  cat <<LATER
  Nobody can register without an invitation. Invite yourself as the first admin:

    $invite_hint

LATER
fi

if [ -n "$proxy" ]; then
  cat <<PROXY
  Your reverse proxy sends $proxy to $upstream now, with its own certificate
  for that name. Until it does, no client can reach the server. In Caddy:

    ${proxy#https://} {
        reverse_proxy $upstream
    }

  nginx and the rest: https://github.com/$repo/blob/main/docs/deployment.md#behind-a-reverse-proxy

PROXY
  if [ -n "$proxy_network" ]; then
    printf '  The server takes no port on this machine: only containers in %s reach it.\n\n' "$proxy_network"
  fi
fi
