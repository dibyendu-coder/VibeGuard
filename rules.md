# VibeGuard --- Engineering Rules

## Core rules

1.  Evidence before claims.
2.  Never invent a vulnerability.
3.  Every finding must have a stable rule ID.
4.  Every finding should include evidence.
5.  Separate severity from confidence.
6.  Do not expose secrets.
7.  Do not silently modify user code.
8.  Do not upload source code by default.
9.  AI is optional enrichment, not the source of truth.
10. Never execute untrusted project code just to analyze it.
11. Prefer false-positive reduction over impressive finding counts.
12. Respect `.gitignore` and configured exclusions.
13. Keep CLI output useful at 80 columns.
14. Provide plain/JSON output for automation.
15. Every rule must have tests.
16. Never claim "secure" or "production ready" absolutely.
17. Make every score explainable.
18. Preserve deterministic results when AI is disabled.
19. Gracefully degrade when an analyzer is unavailable.
20. Do not break the developer's terminal workflow.

## Rule IDs

Format:

``` text
VBG-<CATEGORY>-<NUMBER>
```

Examples:

``` text
VBG-SECRET-001
VBG-AUTH-001
VBG-API-001
VBG-DB-001
VBG-CONFIG-001
VBG-DEPENDENCY-001
```

## Severity

CRITICAL \> HIGH \> MEDIUM \> LOW \> INFO

## Confidence

HIGH \> MEDIUM \> LOW

Never use confidence as a replacement for severity.

## Finding quality

Bad:

``` text
Potential security issue.
```

Good:

``` text
VBG-AUTH-014 HIGH

No server-side ownership check was detected for a
resource identified by a user-controlled route parameter.

Evidence:
file.ts:42
```

## CLI safety

Interactive commands must never unexpectedly run destructive operations.

## Code quality

-   strict typing
-   small modules
-   dependency inversion for analyzers
-   unit tests for detection logic
-   integration tests for CLI
-   clear error handling
-   no swallowed exceptions

## Performance

Do not scan: - `.git` - `node_modules` - build/cache directories unless
explicitly requested.

Avoid loading entire repositories into memory.
