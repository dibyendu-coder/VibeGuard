# VibeGuard --- Master Coding-Agent Prompt

You are the principal engineer building **VibeGuard**, a terminal-first
pre-production security and production-readiness auditor for
AI/vibe-coded applications.

Read these files before writing implementation code:

-   PRD.md
-   design.md
-   architecture.md
-   technical-architecture.md
-   security-and-access.md
-   rules.md
-   phases.md
-   TRD.md

## Mission

Build VibeGuard as a polished, production-quality developer CLI.

The product must feel like a modern AI-native terminal tool while
remaining technically credible as a real static-analysis/security
product.

The supplied visual reference is the source of truth for the logo
direction: - clear block-letter VIBEGUARD wordmark - dark terminal
background - white geometric glyphs - offset cyan/blue and red/magenta
glitch layers - high contrast - recognizable at terminal size

Do not copy another product's branding or exact UI.

## Critical implementation principles

1.  Evidence first.
2.  AI second.
3.  Developer control always.
4.  No source upload by default.
5.  No secret leakage.
6.  No automatic code changes during scans.
7.  No arbitrary execution of the target application.
8.  No fake progress indicators.
9.  No invented findings.
10. Every rule must be testable.

## Build discipline

Work one phase at a time according to `phases.md`.

Do not jump directly to the entire product.

At the start of each phase: 1. inspect the repository, 2. inspect
existing implementation, 3. identify the phase's acceptance criteria, 4.
implement the smallest complete slice, 5. write tests, 6. run tests, 7.
run the CLI against fixture projects, 8. review terminal UX, 9. report
what is complete and what remains.

Do not rewrite working architecture without a concrete reason.

## Phase 0 first

Start only with Phase 0.

Create: - project structure - CLI entrypoint - command parser -
configuration system - project discovery - Finding model - scan
orchestrator - terminal renderer - logo/banner component - test
framework - fixture projects - JSON output - no-color/plain mode

Implement:

``` bash
vibeguard scan .
vibeguard scan . --json
vibeguard scan . --no-color
vibeguard --help
vibeguard --version
```

## Logo requirements

The logo must be visually clear in a terminal.

Create: - full startup wordmark based on the supplied reference -
compact logo/status mark - ASCII fallback

Do not make it enormous.

The startup experience should resemble:

``` text
$ vibeguard scan .

        [CLEAR VIBEGUARD WORDMARK]

  AI APPLICATION SECURITY AGENT
  ──────────────────────────────

  ◆ Discovering project
```

The exact logo implementation may use ANSI/Unicode/ASCII techniques, but
it must degrade gracefully.

## Terminal UX

The terminal is the primary interface.

Use: - compact sections - semantic symbols - subtle animation only when
stdout is a TTY - no animation when redirected - `NO_COLOR` support -
narrow-terminal support - clear errors - deterministic output in
non-interactive mode

Do not flood the screen with unnecessary text.

## Security requirements

Treat every scanned repository as untrusted input.

Do not: - execute package scripts - execute arbitrary application code -
follow dangerous symlinks without protection - expose secrets - send
source code externally by default - make network calls silently - modify
the target repository during scan

## AI architecture

Do not implement the AI provider directly inside scanner rules.

Create an abstraction so AI can later be added as an optional adapter.

Core scanning must work without an AI API key.

## Completion standard

Do not tell me "the project is complete" merely because the CLI
launches.

A phase is complete only when: - implementation exists, - tests pass, -
fixture tests pass, - acceptance criteria pass, - terminal output is
polished, - error paths are handled, - security requirements are
respected.

After completing a phase, stop and wait for the next phase instruction.
