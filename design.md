# VibeGuard --- CLI Design System

## 1. Design goal

VibeGuard should feel like a modern AI-native developer CLI: compact,
confident, technical, fast, and polished.

Reference category: Claude Code / Gemini CLI / OpenCode style terminal
experiences.

Do NOT imitate another product's branding, logo, or exact UI. Borrow
only the principles: - clear hierarchy - conversational prompt - compact
status indicators - progressive activity - useful whitespace - readable
code snippets - minimal chrome

## 2. Logo direction

The supplied reference establishes the visual direction:

-   large block-letter wordmark
-   white primary glyphs
-   offset cyan/blue and red/magenta edge/glitch layers
-   deliberate horizontal/vertical displacement
-   dark terminal background
-   high contrast
-   geometric rather than illustrative
-   recognizable even without color

The logo should read clearly as **VIBEGUARD** in the terminal.

Create the wordmark as a static terminal-safe asset, not an animated web
logo.

### Logo variants

1.  Full startup wordmark
2.  Compact `VG`/shield mark for status lines
3.  Plain text fallback for terminals without Unicode/color support

### Important

Do not make the logo so tall that it consumes most of the terminal. The
startup banner should remain compact and should gracefully shrink on
narrow terminals.

## 3. Terminal palette

Use semantic terminal colors rather than hard-coded RGB assumptions.

Suggested semantic mapping: - primary: bright white - accent: cyan -
secondary accent: magenta/red - success: green - warning: yellow -
critical: red - muted: gray - background: terminal default/dark

Respect `NO_COLOR`, TTY detection, and terminal capability.

## 4. Typography

Use the terminal's native monospace font.

Prefer: - bold text for hierarchy - symbols + text, not color alone -
short labels - aligned columns - readable 80-column layout

Never depend on a custom font being installed.

## 5. Status language

``` text
◆ VibeGuard
◉ Running
✓ Passed
⚠ Warning
✗ Critical
○ Skipped
```

Always provide ASCII fallbacks:

``` text
> Running
[OK]
[WARN]
[FAIL]
[SKIP]
```

## 6. Startup

Example:

``` text
$ vibeguard scan .

        [VIBEGUARD WORDMARK]

  AI APPLICATION SECURITY AGENT
  ──────────────────────────────

  Project    my-saas
  Mode       Deep Audit

  ◆ Discovering project...
```

Do not show a giant banner every time if the user runs a subcommand. Add
`--no-banner`.

## 7. Scan experience

Progressive output:

``` text
◆ Discovering project
  ✓ Next.js
  ✓ TypeScript
  ✓ Supabase

◆ Mapping attack surface
  ✓ 24 API routes
  ✓ 11 database tables
  ⚠ 3 privileged endpoints

◆ Running analysis
  ✓ Secrets
  ✓ Dependencies
  ⚠ Authorization
  ✓ Configuration
```

Avoid fake progress. Every progress message must correspond to an actual
operation.

## 8. Finding card

``` text
✗ VBG-AUTH-014  HIGH

Missing resource authorization
────────────────────────────────────
POST /api/orders/:id

Evidence
  app/api/orders/[id]/route.ts:42

Why it matters
  Authentication verifies the caller is signed in,
  but no ownership check was detected before the
  resource is accessed.

Confidence    HIGH
Category      Authorization

Suggested remediation
  Verify that the authenticated user's identity is
  authorized to access the requested order.

› vibeguard explain VBG-AUTH-014
```

## 9. Final report

``` text
╭────────────────────────────────────────────╮
│              AUDIT COMPLETE                │
├────────────────────────────────────────────┤
│ Security             61 / 100              │
│ Reliability          78 / 100              │
│ Production           64 / 100              │
│                                            │
│ ✗ 2 Critical   ⚠ 5 High   ● 7 Medium      │
│                                            │
│ STATUS: NOT READY                          │
╰────────────────────────────────────────────╯
```

## 10. Interaction

Interactive mode:

``` text
❯ explain VBG-AUTH-014
```

Natural language may be supported later:

``` text
❯ why is my authentication risky?
```

The CLI should always preserve explicit commands for deterministic
behavior.

## 11. Accessibility

-   Never encode severity by color alone.
-   Respect reduced/disabled animation environments.
-   Support plain output.
-   Keep output readable when redirected.
-   `--json` must contain no terminal decoration.

## 12. Responsive terminal behavior

At \<100 columns: - reduce borders - wrap descriptions - collapse
metadata - avoid horizontal overflow

At \<70 columns: - use compact finding format - disable decorative
banner automatically

## 13. Design principle

**Premium visual identity, zero distraction from evidence.**
