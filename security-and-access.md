# VibeGuard --- Security, Privacy and Access

## Threat model

VibeGuard itself handles potentially sensitive source code. The scanner
must therefore be designed as a security-sensitive developer tool.

## Default security posture

-   local-first
-   no source upload by default
-   no telemetry by default
-   no secret values in logs
-   no automatic code modifications
-   no arbitrary network requests during static analysis unless
    explicitly enabled
-   least privilege
-   deterministic local scanning

## Secret handling

If a secret is detected:

``` text
API_KEY=sk_live_****************
```

Never print: - full API keys - tokens - passwords - private keys -
connection strings

Reports should show masked evidence and file/line location.

## AI privacy

AI analysis must be opt-in.

Before sending source-derived context to an external provider: - clearly
state what may be transmitted - redact secrets - minimize context - send
only relevant snippets - provide a local-only mode

## File access

By default scan: - project root - tracked/normal source files

Skip: - `.git` - `node_modules` - build outputs - caches - secrets -
large binaries

Allow explicit inclusion when needed.

Never execute arbitrary project code merely to inspect it.

## Safe analysis

MVP is a static/pre-production auditor. It should not: - launch
attacks - brute-force credentials - exploit production systems - scan
arbitrary external hosts - modify production infrastructure - delete
files - install unknown software

## Fix mode

Any future automatic fix must: 1. show exact proposed change, 2. create
a backup or git-compatible diff, 3. require explicit confirmation, 4.
never overwrite secrets, 5. allow rollback.

## Supply chain

-   pin dependencies where appropriate
-   verify package provenance where possible
-   minimize dependencies
-   use lockfiles
-   run dependency auditing in CI
-   protect release artifacts

## Reporting

Reports must distinguish: - detected - suspected - not checked -
unavailable

Never imply that a successful scan means the application is secure.

## Security disclaimer

VibeGuard is an automated audit assistant, not a guarantee of security
or a substitute for a professional penetration test.
