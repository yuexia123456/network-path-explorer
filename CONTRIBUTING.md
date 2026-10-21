# Contributing / 参与贡献

Network Path Explorer is an early-stage, local-first network diagnostic tool.
The current implementation targets macOS 13+ on Apple Silicon. Windows,
application/process diagnostics, and IP intelligence remain future work.

## Development

Use the Rust version in `rust-toolchain.toml` and Node.js 24.15 or newer.

```sh
npm --prefix web ci
npm --prefix web run build
cargo run -p network-path-agent
```

Before opening a pull request:

```sh
npm --prefix web test
npm --prefix web run build
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Build the web assets before Rust tests because the agent embeds those assets.
Keep frontend builds and Rust builds sequential to avoid stale embedded files.

## What makes a useful contribution

- Explain a concrete problem and its expected behavior.
- Keep changes focused and preserve request cancellation and shutdown cleanup.
- Distinguish system configuration, TUN interception, Mihomo decisions,
  logical proxy chains, route hops, egress observations, and speed-test paths.
- Preserve unknown states when evidence is missing. DIRECT does not mean domestic.
- Add meaningful regression coverage when changing behavior.
- Label fixture-based screenshots and test evidence as fixtures.

## Privacy in issues and pull requests

Do not post controller secrets, subscription URLs, session tokens, cookies,
signed media URLs, full browsing histories, or private IP addresses. Use
synthetic examples and reserved `.invalid` hostnames instead. The JSON export
intentionally excludes many details; review any screenshots separately.

Contributions are made under the MIT license. Third-party dependencies retain
their respective licenses.
