# VibeGuard --- System Architecture

## High-level architecture

``` text
                     VibeGuard CLI
                           |
                    CLI / Command Layer
                           |
                  Scan Orchestrator
                           |
        +------------------+------------------+
        |                  |                  |
 Project Discovery    Analysis Engine    Policy Engine
        |                  |                  |
        |        +---------+---------+        |
        |        |         |         |        |
        |      Rules      AST     Dependency  |
        |        |      Analysis    Audit      |
        |        +---------+---------+        |
        |                  |                  |
        +------------------+------------------+
                           |
                    Finding Normalizer
                           |
                    Correlation Engine
                           |
                    Risk / Score Engine
                           |
              +------------+------------+
              |            |            |
          Terminal        JSON         Report
```

## Components

### CLI layer

Responsible for: - argument parsing - command routing - configuration
loading - exit codes - TTY detection

### Discovery engine

Builds a project manifest: - languages - frameworks - package manager -
dependencies - source directories - API routes - auth indicators -
database indicators - deployment files - CI files

### Analysis engine

Runs independent analyzers: - secret analyzer - dependency analyzer -
AST analyzer - config analyzer - API analyzer - auth analyzer - database
analyzer - privacy/logging analyzer - production analyzer

Each analyzer returns normalized findings.

### Rule engine

Rules should be modular and versioned.

Example:

``` text
Rule ID: VBG-SECRET-001
Category: Secrets
Severity: CRITICAL
Confidence: HIGH
```

### Correlation engine

Combines related findings without duplicating them.

Example: - client-side admin check - privileged endpoint - missing
server-side authorization

may become one architectural finding with linked evidence.

### Risk engine

Calculates: - severity - confidence - exploitability indicators where
safely inferable - affected surface - score contribution

Scores must be deterministic and explainable.

### AI layer

Optional and isolated.

Allowed tasks: - explain evidence - summarize architecture - correlate
findings - suggest remediation - prioritize developer attention

AI must not silently create unsupported findings.

## Data flow

1.  Discover project.
2.  Create immutable scan context.
3.  Run analyzers.
4.  Normalize findings.
5.  Deduplicate/correlate.
6.  Calculate scores.
7.  Render output.
8.  Optionally persist a local scan snapshot for `diff`.

## Storage

MVP should use local files only:

``` text
.vibeguard/
  config.*
  scans/
  cache/
```

Never store raw secrets.

## Extensibility

Analyzers should implement a common interface:

``` text
Analyzer
  id
  supported_languages
  supported_frameworks
  analyze(context) -> findings[]
```

Rules should be independently testable.

## Failure isolation

One analyzer failing must not crash the entire scan unless the failure
makes the overall result invalid.

Example:

``` text
⚠ Dependency advisory source unavailable
  Continuing with local/static checks.
```
