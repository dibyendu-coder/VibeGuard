# VibeGuard --- Product Requirements Document

## 1. Product

**VibeGuard** is a terminal-first pre-production auditor for
AI/vibe-coded applications. It analyzes a local codebase for security
weaknesses, configuration mistakes, reliability risks, dependency
issues, privacy concerns, and production-readiness gaps before the
developer deploys or delivers the application.

### Core promise

> **Find what could go wrong before you ship it.**

VibeGuard is not positioned as a generic AI code reviewer. Deterministic
scanners should establish evidence; an optional AI layer can correlate
findings, explain impact, prioritize risk, and suggest remediation.

## 2. Target users

-   Developers building with AI coding agents
-   Freelancers delivering AI-built applications to clients
-   Solo founders
-   Hackathon builders preparing a demo or deployment
-   Small engineering teams performing pre-production checks

## 3. Primary user journey

``` text
vibeguard scan .
       ↓
Discover project
       ↓
Identify framework / language / services
       ↓
Build application inventory + attack surface
       ↓
Run security / reliability / configuration / dependency rules
       ↓
Correlate findings
       ↓
Calculate scores
       ↓
Show prioritized terminal report
       ↓
Explain / remediate / export
```

## 4. MVP capabilities

### Project discovery

Detect common: - Node.js / TypeScript / JavaScript - Python - Next.js /
React / Express - FastAPI / Flask - Supabase / PostgreSQL - package
managers and lockfiles - Docker / CI configuration - environment files

Detection must be evidence-based and must not assume a framework simply
from a folder name.

### Security checks

MVP should include safe static checks for: - hardcoded secrets and
credentials - accidentally tracked `.env` files - dangerous
environment-variable exposure - insecure authentication patterns -
missing authorization checks in obvious resource routes -
client-side-only privilege checks - unsafe CORS configuration - insecure
cookie settings - obvious XSS sinks - SQL/query construction risks -
unsafe command/process execution - path traversal patterns - risky
file-upload handling - sensitive data in logs - debug/stack-trace
exposure - insecure database access policies where configuration is
locally inspectable

### Dependency checks

-   Parse lockfiles/package manifests.
-   Identify known vulnerable dependencies when an advisory source is
    configured.
-   Never claim a dependency is vulnerable without a source or rule.
-   Show package, installed version, severity, advisory
    identifier/source, and remediation.

### Production-readiness checks

-   missing/unsafe production configuration
-   debug mode
-   missing request limits/timeouts where detectable
-   weak error handling
-   missing security headers where relevant
-   missing health checks
-   missing graceful failure handling
-   client-side secrets
-   development URLs
-   incomplete deployment configuration
-   missing migration/configuration safeguards

### Findings

Each finding has: - stable ID - category - severity - confidence -
evidence - affected file(s) - affected symbol/line when available -
explanation - impact - remediation - references/rule source when
applicable

## 5. Risk model

Severity: - CRITICAL - HIGH - MEDIUM - LOW - INFO

Confidence: - HIGH - MEDIUM - LOW

A finding must never be escalated solely because an AI model "thinks" it
is dangerous. AI may enrich or prioritize evidence-backed findings.

## 6. Scoring

Expose separate scores: - Security - Reliability - Configuration -
Dependencies - Architecture - Production Readiness

Also expose an overall score.

Scores must be explainable: users should be able to see which findings
contributed to a score.

## 7. CLI commands

``` bash
vibeguard
vibeguard scan .
vibeguard scan . --deep
vibeguard scan . --security
vibeguard scan . --production
vibeguard explain VBG-AUTH-001
vibeguard fix VBG-AUTH-001
vibeguard report
vibeguard diff
vibeguard map
vibeguard doctor
vibeguard ci
```

MVP may implement only `scan`, `explain`, `report`, `doctor`, and
`--json`; other commands can be phased in.

## 8. Exit codes

-   `0` = no blocking findings
-   `1` = findings exist but below configured failure threshold
-   `2` = policy-blocking findings
-   `3` = scan/tool error
-   `4` = invalid CLI usage

Threshold must be configurable.

## 9. Non-goals for MVP

-   exploit execution
-   destructive penetration testing
-   autonomous changes without explicit approval
-   guaranteed security certification
-   replacing a professional penetration test
-   uploading source code by default
-   requiring an AI API for core scanning

## 10. Privacy

Default behavior: - scan locally - no source-code upload - no telemetry
unless explicitly enabled - redact secrets from reports - never print
full secret values - AI analysis must be opt-in

## 11. Success criteria

A new user should be able to install VibeGuard and run:

``` bash
vibeguard scan .
```

within minutes and receive: 1. a polished terminal audit, 2. actionable
prioritized findings, 3. evidence for every finding, 4. an explainable
production-readiness score, 5. machine-readable JSON output for
automation.

## 12. Product principle

**Evidence first. AI second. Developer control always.**
