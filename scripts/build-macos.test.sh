#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
project_dir="$test_dir/project"
bin_dir="$test_dir/bin"
mkdir -p "$project_dir/scripts" "$project_dir/dist/macos-arm64" "$bin_dir"
ln -s "$repo_dir/scripts/build-macos.sh" "$project_dir/scripts/build-macos.sh"

cat >"$bin_dir/npm" <<'EOF'
#!/bin/sh
exit "${FAKE_NPM_STATUS:-0}"
EOF

cat >"$bin_dir/rustup" <<'EOF'
#!/bin/sh
if [ "${FAKE_TARGET_INSTALLED:-yes}" = yes ]; then
  printf '%s\n' aarch64-apple-darwin
fi
EOF

cat >"$bin_dir/cargo" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$FAKE_CARGO_LOG"
if [ "$1" = build ]; then
  mkdir -p "$FAKE_PROJECT_DIR/target/aarch64-apple-darwin/release"
  printf '%s' target-aarch64 >"$FAKE_PROJECT_DIR/target/aarch64-apple-darwin/release/network-path-agent"
fi
EOF

chmod +x "$bin_dir/npm" "$bin_dir/rustup" "$bin_dir/cargo"
export PATH="$bin_dir:$PATH"
export FAKE_PROJECT_DIR="$project_dir"
export FAKE_CARGO_LOG="$test_dir/cargo.log"

destination="$project_dir/dist/macos-arm64/NetworkPathExplorer"
printf '%s' stale >"$destination"
if FAKE_NPM_STATUS=19 sh "$project_dir/scripts/build-macos.sh" >/dev/null 2>&1; then
  printf '%s\n' 'build unexpectedly succeeded after fake npm failure' >&2
  exit 1
fi
if [ -e "$destination" ]; then
  printf '%s\n' 'stale destination remained after a failed build' >&2
  exit 1
fi

FAKE_NPM_STATUS=0 FAKE_TARGET_INSTALLED=yes sh "$project_dir/scripts/build-macos.sh"
test "$(cat "$destination")" = target-aarch64
test -x "$destination"
grep -F 'build --manifest-path' "$FAKE_CARGO_LOG" | grep -F -- '--target aarch64-apple-darwin' >/dev/null

if FAKE_TARGET_INSTALLED=no sh "$project_dir/scripts/build-macos.sh" >"$test_dir/missing-target.log" 2>&1; then
  printf '%s\n' 'build unexpectedly succeeded without the Apple Silicon Rust target' >&2
  exit 1
fi
grep -F 'aarch64-apple-darwin Rust target is not installed' "$test_dir/missing-target.log" >/dev/null
