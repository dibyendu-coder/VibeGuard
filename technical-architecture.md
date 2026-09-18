# VibeGuard --- Technical Architecture

## Recommended implementation

Use a language/runtime that is strong for CLI tooling and static
analysis. A practical MVP is **TypeScript + Node.js** because it
integrates naturally with JavaScript/TypeScript ecosystems and package
metadata.

Potential stack: - TypeScript - Node.js - Commander or equivalent CLI
parser - Tree-sitter or language-specific AST tooling - native
filesystem APIs - a terminal rendering library - Zod or equivalent
schema validation - Vitest/Jest for tests

Keep framework-specific dependencies behind adapters.

## Package structure

``` text
vibeguard/
├── apps/
│   └── cli/
├── packages/
│   ├── core/
│   ├── discovery/
│   ├── analyzers/
│   ├── rules/
│   ├── findings/
│   ├── scoring/
│   ├── reporter/
│   ├── ai/
│   └── config/
├── rules/
├── fixtures/
├── tests/
└── docs/
```

If a monorepo adds unnecessary complexity for the first implementation,
use a modular single package while preserving these boundaries.

## Core domain types

``` text
ProjectManifest
ScanContext
Finding
Evidence
Rule
Score
ScanResult
ScanPolicy
```

### Finding

``` text
id
title
category
severity
confidence
description
impact
evidence[]
remediation
references[]
fingerprint
```

## Rule execution

Rules should declare: - rule ID - version - supported file types -
prerequisites - severity - confidence model - detection function -
remediation metadata

## Performance

-   stream large files where possible
-   skip ignored directories
-   respect `.gitignore`
-   cache dependency parsing
-   run independent analyzers concurrently
-   provide scan timing
-   never make the UI wait on unnecessary AI calls

## Configuration

Support:

``` text
.vibeguardrc
vibeguard.config.json
```

Configuration should include: - ignored paths - enabled/disabled rules -
severity threshold - fail threshold - output format - AI settings -
privacy/telemetry settings

## Output modes

-   interactive terminal
-   plain terminal
-   JSON
-   Markdown
-   HTML

## AI adapter

Define an interface so providers can be swapped:

``` text
AIProvider
  explain(finding, context)
  summarize(scan)
  recommend(finding, context)
```

Do not hard-code one provider into the core scanner.

## Testing strategy

Every rule needs: - positive fixture - negative fixture - edge-case
fixture - expected severity - expected confidence - false-positive test

The CLI needs: - snapshot tests - exit-code tests - JSON schema tests -
narrow-terminal tests - no-color tests
