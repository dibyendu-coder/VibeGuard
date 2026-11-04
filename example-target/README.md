# Example Target for VibeGuard Testing

This directory contains a complete example application designed to test all features of **VibeGuard**.

---

## 📁 Files Included

- **`app.js`**: An Express server demonstrating common AI/vibe-coding security vulnerabilities and production readiness issues:
  - 🔑 Hardcoded secrets (Stripe API key & PostgreSQL connection URI)
  - 💉 SQL injection via unsanitized query parameters
  - ⚡ Dynamic command execution (`child_process.exec`)
  - 📂 Path traversal via unsanitized file path
  - 🌐 SSRF vulnerability (`axios.get` with user-controlled URL)
  - 🔓 Insecure wildcard CORS (`origin: '*'`)
  - 🛑 Synchronous blocking I/O inside an HTTP route handler (`fs.readFileSync`)
  - ⚠️ Error disclosure leaking server stack traces
  - 🔒 Sensitive endpoint missing authorization
- **`.env`**: Committed environment variables with production debug flags and credentials.
- **`Dockerfile`**: Docker container configured to run as root using `:latest` base image.
- **`package.json`**: Application dependency manifest.

---

## 🧪 Commands to Test VibeGuard

### 0. Launch Interactive Web Dashboard
```bash
vibeguard dashboard example-target
```
*Spins up the web dashboard at `http://localhost:4200` with the executive scorecards, interactive finding explorer, API route surface, and command guide.*

### 1. Interactive Control Center (Shows Banner + Feature Menu)
```bash
vibeguard
```
*(Select option `1`, `3`, `4`, `5`, etc., and enter `example-target` when prompted)*

### 2. Full Audit
```bash
# Using the directory:
vibeguard scan example-target

# Or directly specifying the file:
vibeguard scan example-target/app.js
```

### 3. Production Readiness Summary Table
```bash
vibeguard summary example-target
```

### 4. Inspect API Routes & Risk Surface
```bash
vibeguard routes example-target
```

### 5. List Compact Findings
```bash
vibeguard findings example-target
```

### 6. Explain a Specific Finding & Remediation
```bash
# Explain secret leakage:
vibeguard explain VBG-SECRET-001 --target example-target

# Explain command execution:
vibeguard explain VBG-CODE-003 --target example-target
```

### 7. Filter by Security Only
```bash
vibeguard scan example-target --security
```

### 8. Deep Graph & Flow Analysis
```bash
vibeguard scan example-target --deep
```

