#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary="$project_dir/dist/macos-arm64/NetworkPathExplorer"
if [ ! -x "$binary" ]; then
  printf '%s\n' "packaged binary is missing or not executable: $binary" >&2
  exit 1
fi

"$binary" >/dev/null 2>&1 &
agent_pid=$!
cleanup() {
  kill "$agent_pid" 2>/dev/null || true
  wait "$agent_pid" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

port=
attempt=0
while [ "$attempt" -lt 50 ]; do
  port=$(lsof -nP -a -p "$agent_pid" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 && $9 ~ /^127\.0\.0\.1:/ { sub(/^.*:/, "", $9); print $9; exit }')
  [ -n "$port" ] && break
  attempt=$((attempt + 1))
  sleep 0.1
done
if [ -z "$port" ]; then
  printf '%s\n' 'agent did not bind a loopback listener within five seconds' >&2
  exit 1
fi

capabilities=$(curl --fail --silent --show-error -H "Origin: http://127.0.0.1:$port" "http://127.0.0.1:$port/api/v1/capabilities")
printf '%s' "$capabilities" | grep -F '"platform":"macos"' >/dev/null
for capability in \
  '"network_overview":true' \
  '"egress_ip":true' \
  '"mihomo_manual_controller":true' \
  '"route_trace":true' \
  '"speed_tests":true' \
  '"speed_provider":"cloudflare"'
do
  printf '%s' "$capabilities" | grep -F "$capability" >/dev/null
done

page=$(curl --fail --silent --show-error "http://127.0.0.1:$port/")
printf '%s' "$page" | grep -F 'id="app"' >/dev/null
asset=$(printf '%s' "$page" | sed -n 's#.*src="\(/assets/[^" ]*\.js\)".*#\1#p' | head -n 1)
if [ -z "$asset" ]; then
  printf '%s\n' 'embedded JavaScript asset link is missing' >&2
  exit 1
fi
script=$(curl --fail --silent --show-error "http://127.0.0.1:$port$asset")
printf '%s' "$script" | grep -F '本机网络概览' >/dev/null
printf '%s' "$script" | grep -F 'Cloudflare 测速' >/dev/null
printf '%s\n' 'Smoke test passed: random loopback listener served capabilities and embedded network/speed labels.'
