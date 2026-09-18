# VibeGuard --- Technical Requirements Document

## Functional requirements

### FR-001

The CLI SHALL accept a project path.

### FR-002

The scanner SHALL discover supported languages/frameworks.

### FR-003

The scanner SHALL analyze supported source/configuration files without
requiring application execution.

### FR-004

Each finding SHALL have a stable identifier.

### FR-005

Each finding SHALL expose severity and confidence separately.

### FR-006

Findings SHALL include evidence whenever technically possible.

### FR-007

Secrets SHALL be masked in all user-visible output.

### FR-008

The scanner SHALL support machine-readable JSON output.

### FR-009

The CLI SHALL return documented exit codes.

### FR-010

The scanner SHALL support configured ignore paths.

### FR-011

The scanner SHALL never modify source files during normal scan
operations.

### FR-012

AI analysis SHALL be optional.

### FR-013

The scanner SHALL distinguish unavailable checks from passed checks.

### FR-014

The scoring engine SHALL expose score contributions.

## Non-functional requirements

### NFR-001 Performance

A medium project should begin showing useful progress quickly and should
avoid unnecessary full-repository loading.

### NFR-002 Reliability

An individual analyzer failure must not terminate unrelated analyzers.

### NFR-003 Privacy

Source code must remain local unless the user explicitly enables an
external AI/service integration.

### NFR-004 Portability

Support major developer environments where the runtime is available.

### NFR-005 Accessibility

CLI output must remain understandable without color.

### NFR-006 Determinism

Core findings must be reproducible with the same code, configuration,
and rule version.

### NFR-007 Security

The scanner must treat scanned repositories as untrusted input.

### NFR-008 Maintainability

Rules must be independently testable and versioned.

## Acceptance criteria

### Scan

``` bash
vibeguard scan .
```

must: - discover the project, - run available analyzers, - show
progress, - show findings, - show scores, - return the correct exit
code.

### JSON

``` bash
vibeguard scan . --json
```

must produce valid JSON with no ANSI control sequences.

### Secret safety

A fixture containing a fake API key must never cause the full value to
appear in stdout, stderr, or a generated report.

### Narrow terminal

Output must not create uncontrolled horizontal overflow.

### Broken analyzer

If one analyzer crashes, the CLI reports the analyzer failure and
continues where safe.

## Future requirements

-   plugin SDK
-   remote team dashboards
-   SARIF output
-   pull-request comments
-   baseline/waiver management
-   custom organization policies
