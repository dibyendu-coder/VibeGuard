# VibeGuard --- Build Phases

## Phase 0 --- Foundation

Goal: establish the product skeleton.

Build: - CLI package - `vibeguard scan` - config loader - project
discovery - terminal theme - logo/banner system - normalized Finding
model - test infrastructure - `.gitignore` handling - `--no-color` -
`--json`

Do NOT build AI yet.

Exit criteria:

``` bash
vibeguard scan .
```

runs successfully against fixture projects.

## Phase 1 --- Core audit engine

Implement: - secret detection - environment exposure checks - dependency
inventory - configuration checks - obvious dangerous API patterns -
unsafe logging - debug configuration - basic
authentication/authorization checks

Output: - categorized findings - severity/confidence - evidence - score

## Phase 2 --- Deep application understanding

Implement: - route discovery - data-flow/AST analysis - auth boundary
analysis - authorization/resource ownership heuristics - database
configuration analysis - framework-specific rules - attack-surface map

## Phase 3 --- Production readiness

Implement: - reliability checks - timeout/retry indicators - error
handling - headers/cookies - deployment configuration - health/readiness
checks - migration/configuration checks - privacy/logging audit

## Phase 4 --- AI reasoning layer

Add optional provider adapter.

Capabilities: - explain finding - summarize audit - correlate findings -
suggest remediation - answer questions about the evidence

Do not let AI become a required dependency for core scanning.

## Phase 5 --- Remediation

Implement:

``` bash
vibeguard fix VBG-...
```

First version should generate a proposed diff only.

Explicit approval required before writing.

## Phase 6 --- Reporting and CI

Implement: - Markdown - HTML - JSON schema - CI exit thresholds - GitHub
Actions example - scan comparison

## Phase 7 --- Polish

-   startup banner
-   animated but honest progress
-   compact layout
-   command autocomplete
-   `doctor`
-   `diff`
-   `map`
-   performance optimization
-   documentation
-   release packaging

## Phase 8 --- Security hardening

Before public release: - dependency audit - secret scanning of VibeGuard
itself - malicious fixture tests - path traversal tests - symlink
handling - parser crash tests - huge-file tests - terminal
escape-sequence tests - AI prompt-injection tests - report redaction
tests

## Definition of done

The MVP is complete only when: - core scan works offline - findings are
evidence-backed - tests cover rules - secrets are redacted - JSON is
stable - exit codes work - scan does not execute arbitrary application
code - documentation explains limitations
