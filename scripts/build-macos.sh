#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
artifact_dir="$project_dir/dist/macos-arm64"
artifact="$artifact_dir/NetworkPathExplorer"
mkdir -p "$artifact_dir"
rm -f "$artifact"
if ! rustup target list --installed | grep -qx aarch64-apple-darwin; then
  printf '%s\n' 'aarch64-apple-darwin Rust target is not installed; run: rustup target add aarch64-apple-darwin' >&2
  exit 1
fi
npm --prefix "$project_dir/web" ci
npm --prefix "$project_dir/web" test
npm --prefix "$project_dir/web" run build
cargo test --manifest-path "$project_dir/Cargo.toml" -p network-path-agent
cargo build --manifest-path "$project_dir/Cargo.toml" -p network-path-agent --target aarch64-apple-darwin --release
temporary_artifact=$(mktemp "$artifact_dir/.NetworkPathExplorer.XXXXXX")
trap 'rm -f "$temporary_artifact"' EXIT HUP INT TERM
cp "$project_dir/target/aarch64-apple-darwin/release/network-path-agent" "$temporary_artifact"
chmod 755 "$temporary_artifact"
mv -f "$temporary_artifact" "$artifact"
trap - EXIT HUP INT TERM
