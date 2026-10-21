# Security policy

This is early-stage software, not a security audit or a guarantee about a
network provider's internal routing. No release is currently code-signed.

## Design boundaries

- The local agent binds a random loopback port and uses a per-launch session token.
- Local API routes validate host/origin and request boundaries.
- Mihomo controller access is read-only and restricted to local endpoints.
- Diagnostics do not read browser cookies or decrypt HTTPS traffic.
- URL targets are contacted during diagnostics. IP lookup and speed tests use
  third-party services as described in the application.
- Unknown, inaccessible, and inferred evidence must remain distinguishable.

## Reporting

If GitHub's **Report a vulnerability** feature is available in the repository,
use it for confidential reports. Otherwise open a minimal issue requesting a
private reporting channel without publishing exploit details, secrets, or
personal network data. No private-response deadline is promised.

Do not test against third-party systems without authorization. Synthetic
loopback servers and local fixtures are preferred for reproduction.
