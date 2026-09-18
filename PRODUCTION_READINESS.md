# VibeGuard Production Readiness Engine Documentation

## 1. Overview

VibeGuard is a deterministic CLI security, reliability, and production-readiness auditor designed for applications built with traditional coding or AI/vibe-coding tools.

Phase 3 expands VibeGuard from security scanning into a comprehensive **DEVELOPMENT → SECURITY → RELIABILITY → PRODUCTION READINESS** system.

---

## 2. Readiness Dimensions & Status Methodology

VibeGuard evaluates application production readiness across 7 core dimensions:

1. **Security:** `READY` | `NEEDS_ATTENTION` | `NOT_READY`
2. **Reliability:** `GOOD` | `NEEDS_ATTENTION` | `LIMITED`
3. **Configuration:** `GOOD` | `NEEDS_ATTENTION` | `INSECURE`
4. **Dependencies:** `GOOD` | `REVIEW` | `OUTDATED`
5. **Deployment:** `GOOD` | `LIMITED` | `RISKY`
6. **Observability:** `GOOD` | `LIMITED` | `MISSING`
7. **Testing:** `GOOD` | `LIMITED` | `NONE`

---

## 3. What VibeGuard Detects

### Security & Data Safety
- Plaintext secrets (Stripe, AWS, GitHub, Slack, OpenAI, JWT, private keys)
- Hardcoded database credentials & connection strings
- SQL injections (concatenation, string formatting, f-strings)
- Command injections (`exec`, `spawn`, `eval`, `subprocess.Popen`)
- Path traversals (`fs.readFile`, `open` with unvalidated input)
- SSRF & user-controlled outbound HTTP requests
- Insecure CORS (`*` wildcards, dynamic header reflection)
- Missing authentication / authorization guards on sensitive endpoints
- Sensitive credential leakage in logs or responses

### Reliability & Resilience
- Synchronous blocking filesystem operations in HTTP request paths (`readFileSync`, `writeFileSync`)
- Missing request timeouts on `fetch()`, `axios`, `http` clients
- Swallowed exceptions and empty `catch` / `except pass` blocks
- Unhandled promise rejections
- Unbounded in-memory queues or caches

### Configuration & Deployment
- Production environment secrets committed to repository (`.env`, `.env.production`)
- Debug mode enabled (`NODE_ENV=development`, `DEBUG=True`)
- Localhost URLs configured in production settings
- Container running as root (`USER root` or omitted `USER` directive in Dockerfile)
- Floating base image tags (`:latest`)
- Copied `.env` files inside Docker container layers
- Missing container `HEALTHCHECK` directives
- Secrets printed in CI workflow logs
- Third-party GitHub Actions pinned to mutable release tags instead of commit SHAs

### Observability & Testing
- Missing health/readiness endpoints (`/healthz`, `/ready`)
- Missing graceful shutdown signal handling (`SIGTERM`, `SIGINT`)
- Unstructured console logging without JSON correlation tokens
- Absence of automated test files or missing test execution in CI/CD

---

## 4. What VibeGuard Does NOT Detect (Limitations)

- Dynamic runtime vulnerabilities occurring solely due to business logic state.
- Known CVE advisories without an integrated vulnerability feed ("Dependency advisory status not verified").
- False positives in intentionally obfuscated minified code (obfuscation is flagged as a risk).

---

## 5. Confidence Model

Findings are categorized by confidence levels:
- **HIGH:** Direct AST/regex source-to-sink flow or clear file configuration presence.
- **MEDIUM:** Recognized framework pattern without complete context graph trace.
- **LOW:** Heuristic indication requiring developer review.

Confidence is separate from severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

---

## 6. Suppressions & Baseline Support

### Baseline
```bash
vibeguard baseline create
vibeguard scan . --baseline .vibeguardignore
```

### Suppressions
- **`.vibeguardignore` file:** List specific rule IDs or fingerprints line-by-line.
- **Inline comment suppressions:**
  - `// vibeguard-ignore-line VBG-SECRET-001`
  - `/* vibeguard-ignore-file VBG-CONFIG-001 */`

Wildcard suppressions are strictly prohibited. Every suppression requires an explicit rule ID.

---

## 7. Exit Codes

- `0`: Clean scan — zero actionable findings exceeding policy failure threshold.
- `1`: Warnings/findings detected below policy threshold.
- `2`: Blocking findings detected (matching or exceeding `--fail-threshold`, default `HIGH`).
- `3`: Configuration or CLI error.
- `4`: Invalid CLI command syntax.

---

## 8. Safe Scanning Guarantees

VibeGuard operates under strict zero-execution guarantees:
1. Never executes target application code.
2. Never installs target project dependencies (`npm install`, `pip install`).
3. Never executes target package lifecycle scripts (`preinstall`, `postinstall`).
4. Never transmits repository code externally.
5. Operates 100% deterministically without external LLM API requirements.
