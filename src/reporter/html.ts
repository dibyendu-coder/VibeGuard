import { ScanResult } from '../core/types.js';

function escapeHtml(str: string = ''): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function renderHtmlDashboard(result: ScanResult): string {
  const findings = result.findings || [];
  const manifest = result.manifest;
  const scores = result.scores;
  const routes = result.routes || [];

  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW').length;
  const infoCount = findings.filter((f) => f.severity === 'INFO').length;

  const statusColor =
    scores.status === 'READY'
      ? '#10b981' // green
      : scores.status === 'NEEDS_ATTENTION'
      ? '#f59e0b' // amber
      : '#ef4444'; // red

  const statusLabel =
    scores.status === 'READY'
      ? 'READY FOR PRODUCTION'
      : scores.status === 'NEEDS_ATTENTION'
      ? 'NEEDS ATTENTION'
      : 'NOT READY - ISSUES DETECTED';

  const findingsJson = JSON.stringify(findings).replace(/</g, '\\u003c');
  const resultJson = JSON.stringify(result).replace(/</g, '\\u003c');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeGuard Audit Dashboard - ${escapeHtml(manifest?.projectName || 'Project')}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --cyan: #06b6d4;
      --cyan-light: #22d3ee;
      --magenta: #ec4899;
      --green: #10b981;
      --amber: #f59e0b;
      --red: #ef4444;
      --code-bg: #030712;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      padding-bottom: 60px;
    }

    /* Header & Brand */
    header {
      background: linear-gradient(180deg, #131b2e 0%, var(--bg) 100%);
      border-bottom: 1px solid var(--card-border);
      padding: 24px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }
    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .brand-badge {
      background: linear-gradient(135deg, #06b6d4 0%, #ec4899 100%);
      color: #fff;
      padding: 6px 12px;
      font-weight: 800;
      border-radius: 6px;
      font-size: 14px;
      letter-spacing: 1px;
    }
    .brand-title {
      font-size: 20px;
      font-weight: 700;
      color: #fff;
    }
    .brand-subtitle {
      font-size: 13px;
      color: var(--text-muted);
    }
    .header-actions {
      display: flex;
      gap: 12px;
      align-items: center;
    }
    .btn {
      padding: 8px 16px;
      font-size: 13px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      border: 1px solid var(--card-border);
      background: var(--card-bg);
      color: var(--text);
      transition: all 0.2s ease;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn:hover {
      background: #1f2937;
      border-color: var(--cyan);
      color: #fff;
    }
    .btn-primary {
      background: var(--cyan);
      border-color: var(--cyan);
      color: #042f2e;
    }
    .btn-primary:hover {
      background: var(--cyan-light);
      color: #042f2e;
    }

    /* Container */
    .container {
      max-width: 1360px;
      margin: 0 auto;
      padding: 28px 24px;
    }

    /* Navigation Tabs */
    .tab-bar {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
      overflow-x: auto;
    }
    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 14px;
      font-weight: 600;
      padding: 12px 18px;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 8px;
      white-space: nowrap;
    }
    .tab-btn:hover {
      color: var(--text);
    }
    .tab-btn.active {
      color: var(--cyan-light);
      border-bottom-color: var(--cyan);
    }
    .tab-badge {
      background: #1f2937;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
    }

    /* Hero Status Banner */
    .hero-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 28px;
      display: grid;
      grid-template-columns: 1fr auto;
      align-items: center;
      gap: 24px;
      position: relative;
      overflow: hidden;
    }
    .hero-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 6px;
      height: 100%;
      background: ${statusColor};
    }
    .hero-info h1 {
      font-size: 24px;
      margin-bottom: 6px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .status-pill {
      font-size: 12px;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 999px;
      background: ${statusColor}22;
      color: ${statusColor};
      border: 1px solid ${statusColor}44;
      text-transform: uppercase;
    }
    .hero-meta {
      font-size: 13px;
      color: var(--text-muted);
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      margin-top: 8px;
    }
    .hero-meta span {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .score-circle {
      width: 100px;
      height: 100px;
      border-radius: 50%;
      background: conic-gradient(${statusColor} ${(scores?.overallScore || 0) * 3.6}deg, #1f2937 0deg);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 20px ${statusColor}33;
    }
    .score-inner {
      width: 82px;
      height: 82px;
      border-radius: 50%;
      background: var(--card-bg);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
    }
    .score-val {
      font-size: 24px;
      font-weight: 800;
      color: #fff;
      line-height: 1;
    }
    .score-label {
      font-size: 10px;
      color: var(--text-muted);
      text-transform: uppercase;
      font-weight: 600;
      margin-top: 2px;
    }

    /* Metric Grid */
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .metric-title {
      font-size: 12px;
      color: var(--text-muted);
      text-transform: uppercase;
      font-weight: 600;
    }
    .metric-value {
      font-size: 26px;
      font-weight: 800;
    }
    .crit { color: var(--red); }
    .high { color: #f97316; }
    .med { color: var(--amber); }
    .low { color: #3b82f6; }
    .info { color: #6b7280; }

    /* Production Readiness Dimensions Grid */
    .dimension-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .dimension-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .dimension-title {
      font-size: 14px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 2px;
    }
    .dimension-desc {
      font-size: 12px;
      color: var(--text-muted);
    }
    .status-badge {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 10px;
      border-radius: 6px;
      text-transform: uppercase;
    }
    .status-ready { background: #10b98122; color: #10b981; border: 1px solid #10b98144; }
    .status-warning { background: #f59e0b22; color: #f59e0b; border: 1px solid #f59e0b44; }
    .status-danger { background: #ef444422; color: #ef4444; border: 1px solid #ef444444; }
    .status-neutral { background: #6b728022; color: #9ca3af; border: 1px solid #6b728044; }

    /* Command Guide Section */
    .guide-banner {
      background: #131b2e;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 28px;
    }
    .guide-banner h2 {
      font-size: 18px;
      color: #fff;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .guide-banner p {
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 16px;
    }
    .pipeline-steps {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .step-card {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 14px;
    }
    .step-num {
      font-size: 11px;
      font-weight: 700;
      color: var(--cyan);
      text-transform: uppercase;
      margin-bottom: 4px;
    }
    .step-name {
      font-size: 13px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 4px;
    }
    .step-desc {
      font-size: 11px;
      color: var(--text-muted);
    }
    .command-list {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
    }
    .cmd-item {
      background: var(--code-bg);
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 10px 14px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .cmd-syntax {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--cyan-light);
      font-size: 13px;
      font-weight: 600;
    }
    .cmd-desc {
      font-size: 11px;
      color: var(--text-muted);
    }

    /* Findings Filter & List */
    .filter-bar {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 20px;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      padding: 14px 18px;
      border-radius: 10px;
    }
    .search-input {
      background: var(--bg);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 8px 14px;
      color: #fff;
      font-size: 13px;
      flex: 1;
      min-width: 220px;
    }
    .search-input:focus {
      outline: none;
      border-color: var(--cyan);
    }
    .pill-group {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .filter-pill {
      background: var(--bg);
      border: 1px solid var(--card-border);
      color: var(--text-muted);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .filter-pill:hover, .filter-pill.active {
      background: #1f2937;
      color: #fff;
      border-color: var(--cyan);
    }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 16px;
      transition: border-color 0.2s ease;
    }
    .finding-card:hover {
      border-color: #374151;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    .finding-title-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .finding-id {
      font-family: monospace;
      font-size: 12px;
      font-weight: 700;
      padding: 2px 8px;
      background: #1f2937;
      border-radius: 4px;
      color: var(--cyan-light);
    }
    .finding-title {
      font-size: 16px;
      font-weight: 700;
      color: #fff;
    }
    .finding-category {
      font-size: 11px;
      color: var(--text-muted);
      background: #1e293b;
      padding: 2px 8px;
      border-radius: 4px;
    }
    .finding-location {
      font-family: monospace;
      font-size: 12px;
      color: var(--cyan);
      margin-bottom: 12px;
      display: inline-block;
    }
    .code-evidence {
      background: var(--code-bg);
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 12px 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      color: #e5e7eb;
      overflow-x: auto;
      margin-bottom: 14px;
      white-space: pre-wrap;
    }
    .finding-section {
      margin-top: 10px;
    }
    .section-label {
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 700;
      color: var(--text-muted);
      margin-bottom: 4px;
    }
    .section-body {
      font-size: 13px;
      color: #d1d5db;
    }
    .remediation-box {
      background: #064e3b22;
      border: 1px solid #064e3b66;
      border-radius: 6px;
      padding: 12px 14px;
      margin-top: 12px;
    }
    .remediation-box .section-label {
      color: #34d399;
    }

    /* API Routes Table */
    .routes-table {
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      overflow: hidden;
    }
    .routes-table th, .routes-table td {
      padding: 14px 18px;
      text-align: left;
      border-bottom: 1px solid var(--card-border);
      font-size: 13px;
    }
    .routes-table th {
      background: #131b2e;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
    }
    .method-badge {
      font-family: monospace;
      font-size: 11px;
      font-weight: 800;
      padding: 2px 8px;
      border-radius: 4px;
    }
    .method-get { background: #10b98122; color: #10b981; }
    .method-post { background: #3b82f622; color: #60a5fa; }
    .method-put { background: #f59e0b22; color: #fbbf24; }
    .method-delete { background: #ef444422; color: #f87171; }
    .tag-badge {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 4px;
      background: #374151;
      color: #e5e7eb;
      margin-right: 4px;
    }
    .tag-risk {
      background: #7f1d1d;
      color: #fca5a5;
    }

    /* Tab panels */
    .tab-panel {
      display: none;
    }
    .tab-panel.active {
      display: block;
    }
  </style>
</head>
<body>

  <header>
    <div class="brand-wrap">
      <div class="brand-badge">VIBEGUARD</div>
      <div>
        <div class="brand-title">Production Readiness & Security Auditor</div>
        <div class="brand-subtitle">Automated Pre-Production Quality & Vulnerability Report</div>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn" onclick="window.print()">🖨️ Print / Save PDF</button>
      <button class="btn btn-primary" onclick="downloadJson()">⬇️ Export JSON Report</button>
    </div>
  </header>

  <div class="container">

    <!-- Hero Card -->
    <div class="hero-card">
      <div class="hero-info">
        <h1>
          <span>${escapeHtml(manifest?.projectName || 'Project Audit')}</span>
          <span class="status-pill">${statusLabel}</span>
        </h1>
        <div class="hero-meta">
          <span>📁 Target: <strong>${escapeHtml(manifest?.rootDir || '.')}</strong></span>
          <span>⏱️ Scanned in: <strong>${result.durationMs || 120}ms</strong></span>
          <span>🏷️ Version: <strong>0.1.0</strong></span>
          <span>📅 Date: <strong>${escapeHtml(result.timestamp || new Date().toISOString())}</strong></span>
        </div>
      </div>
      <div class="score-circle">
        <div class="score-inner">
          <div class="score-val">${scores?.overallScore || 0}</div>
          <div class="score-label">Score</div>
        </div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('overview')">
        📊 Overview & Matrix
      </button>
      <button class="tab-btn" onclick="switchTab('findings')">
        🔍 Findings & Vulnerabilities
        <span class="tab-badge">${findings.length}</span>
      </button>
      <button class="tab-btn" onclick="switchTab('routes')">
        🛣️ API Route Surface
        <span class="tab-badge">${routes.length}</span>
      </button>
      <button class="tab-btn" onclick="switchTab('guide')">
        📖 Command Guide & Architecture
      </button>
    </div>

    <!-- TAB 1: OVERVIEW & READINESS MATRIX -->
    <div id="tab-overview" class="tab-panel active">
      <!-- Metric Highlights -->
      <div class="metric-grid">
        <div class="metric-card">
          <span class="metric-title">Critical Findings</span>
          <span class="metric-value crit">${criticalCount}</span>
        </div>
        <div class="metric-card">
          <span class="metric-title">High Findings</span>
          <span class="metric-value high">${highCount}</span>
        </div>
        <div class="metric-card">
          <span class="metric-title">Medium Findings</span>
          <span class="metric-value med">${mediumCount}</span>
        </div>
        <div class="metric-card">
          <span class="metric-title">Low Findings</span>
          <span class="metric-value low">${lowCount}</span>
        </div>
        <div class="metric-card">
          <span class="metric-title">Informational</span>
          <span class="metric-value info">${infoCount}</span>
        </div>
        <div class="metric-card">
          <span class="metric-title">API Routes Discovered</span>
          <span class="metric-value">${routes.length}</span>
        </div>
      </div>

      <!-- Production Readiness Scorecards -->
      <h3 style="margin-bottom: 14px; font-size: 16px; color: #fff;">Production Readiness Dimensions</h3>
      <div class="dimension-grid">
        <div class="dimension-card">
          <div>
            <div class="dimension-title">🔒 Security</div>
            <div class="dimension-desc">Secrets, injections, XSS, SSRF & authentication</div>
          </div>
          <span class="status-badge ${criticalCount + highCount > 0 ? 'status-danger' : 'status-ready'}">
            ${criticalCount + highCount > 0 ? 'NOT_READY' : 'GOOD'}
          </span>
        </div>

        <div class="dimension-card">
          <div>
            <div class="dimension-title">⚡ Reliability</div>
            <div class="dimension-desc">Async blocking, missing timeouts, error handlers</div>
          </div>
          <span class="status-badge ${scores.readinessDimensions?.reliability === 'GOOD' ? 'status-ready' : 'status-warning'}">
            ${scores.readinessDimensions?.reliability || 'GOOD'}
          </span>
        </div>

        <div class="dimension-card">
          <div>
            <div class="dimension-title">⚙️ Configuration</div>
            <div class="dimension-desc">Committed .env, debug flags, and runtime settings</div>
          </div>
          <span class="status-badge ${scores.readinessDimensions?.configuration === 'GOOD' ? 'status-ready' : 'status-danger'}">
            ${scores.readinessDimensions?.configuration || 'INSECURE'}
          </span>
        </div>

        <div class="dimension-card">
          <div>
            <div class="dimension-title">📦 Dependencies</div>
            <div class="dimension-desc">Lockfile presence, package manifests & integrity</div>
          </div>
          <span class="status-badge ${manifest?.hasLockfile ? 'status-ready' : 'status-warning'}">
            ${manifest?.hasLockfile ? 'GOOD' : 'NO_LOCKFILE'}
          </span>
        </div>

        <div class="dimension-card">
          <div>
            <div class="dimension-title">🐳 Deployment</div>
            <div class="dimension-desc">Docker root checks, :latest tag, healthcheck</div>
          </div>
          <span class="status-badge ${scores.readinessDimensions?.deployment === 'GOOD' ? 'status-ready' : 'status-warning'}">
            ${scores.readinessDimensions?.deployment || 'LIMITED'}
          </span>
        </div>

        <div class="dimension-card">
          <div>
            <div class="dimension-title">📊 Observability</div>
            <div class="dimension-desc">/healthz routes, SIGTERM listeners & telemetry</div>
          </div>
          <span class="status-badge ${scores.readinessDimensions?.observability === 'GOOD' ? 'status-ready' : 'status-warning'}">
            ${scores.readinessDimensions?.observability || 'LIMITED'}
          </span>
        </div>

        <div class="dimension-card">
          <div>
            <div class="dimension-title">🧪 Testing & QA</div>
            <div class="dimension-desc">Unit/integration tests, test runner config & CI steps</div>
          </div>
          <span class="status-badge ${scores.readinessDimensions?.testing === 'GOOD' ? 'status-ready' : 'status-neutral'}">
            ${scores.readinessDimensions?.testing || 'REVIEW'}
          </span>
        </div>
      </div>
    </div>

    <!-- TAB 2: FINDINGS EXPLORER -->
    <div id="tab-findings" class="tab-panel">
      <!-- Filter Bar -->
      <div class="filter-bar">
        <input type="text" id="searchInput" class="search-input" placeholder="Search by title, rule ID (e.g. VBG-SECRET), file, or category..." oninput="filterFindings()">
        <div class="pill-group">
          <button class="filter-pill active" onclick="setSeverityFilter('ALL', this)">All (${findings.length})</button>
          <button class="filter-pill" onclick="setSeverityFilter('CRITICAL', this)">Critical (${criticalCount})</button>
          <button class="filter-pill" onclick="setSeverityFilter('HIGH', this)">High (${highCount})</button>
          <button class="filter-pill" onclick="setSeverityFilter('MEDIUM', this)">Medium (${mediumCount})</button>
          <button class="filter-pill" onclick="setSeverityFilter('LOW', this)">Low (${lowCount})</button>
        </div>
      </div>

      <!-- Findings Container -->
      <div id="findingsContainer">
        ${
          findings.length === 0
            ? '<div style="text-align: center; padding: 48px; color: var(--text-muted); background: var(--card-bg); border-radius: 10px;">🎉 No findings detected! Application passed all audit checks.</div>'
            : findings
                .map((f) => {
                  const sevClass =
                    f.severity === 'CRITICAL'
                      ? 'crit'
                      : f.severity === 'HIGH'
                      ? 'high'
                      : f.severity === 'MEDIUM'
                      ? 'med'
                      : 'low';
                  const sevBadge =
                    f.severity === 'CRITICAL'
                      ? 'status-danger'
                      : f.severity === 'HIGH'
                      ? 'status-danger'
                      : f.severity === 'MEDIUM'
                      ? 'status-warning'
                      : 'status-ready';
                  const evidenceSnippet = f.evidence?.[0]?.snippet || '';
                  const filePath = f.file || f.evidence?.[0]?.filePath || 'unknown';
                  const line = f.line || f.evidence?.[0]?.line || 1;

                  return `
            <div class="finding-card" data-severity="${escapeHtml(f.severity)}" data-category="${escapeHtml(f.category || '')}" data-text="${escapeHtml(
                    (f.title + ' ' + f.id + ' ' + filePath + ' ' + (f.description || '')).toLowerCase()
                  )}">
              <div class="finding-header">
                <div class="finding-title-wrap">
                  <span class="status-badge ${sevBadge}">${escapeHtml(f.severity)}</span>
                  <span class="finding-id">${escapeHtml(f.id)}</span>
                  <span class="finding-title">${escapeHtml(f.title)}</span>
                </div>
                <span class="finding-category">${escapeHtml(f.category || 'General')}</span>
              </div>
              <div class="finding-location">📍 ${escapeHtml(filePath)}:${line}</div>

              ${
                evidenceSnippet
                  ? `<div class="code-evidence">${escapeHtml(evidenceSnippet)}</div>`
                  : ''
              }

              <div class="finding-section">
                <div class="section-label">Why It Matters (Impact)</div>
                <div class="section-body">${escapeHtml(f.impact || f.description || 'Security or operational risk.')}</div>
              </div>

              <div class="remediation-box">
                <div class="section-label">How To Fix (Remediation)</div>
                <div class="section-body">${escapeHtml(f.remediation || 'Review and refactor vulnerable code pattern.')}</div>
              </div>
            </div>`;
                })
                .join('')
        }
      </div>
    </div>

    <!-- TAB 3: API ROUTE SURFACE -->
    <div id="tab-routes" class="tab-panel">
      ${
        routes.length === 0
          ? '<div style="text-align: center; padding: 48px; color: var(--text-muted); background: var(--card-bg); border-radius: 10px;">No HTTP routes detected in this project.</div>'
          : `
      <table class="routes-table">
        <thead>
          <tr>
            <th>Method</th>
            <th>Route Endpoint</th>
            <th>Security Flags & Risk Indicators</th>
            <th>Handler Source File</th>
          </tr>
        </thead>
        <tbody>
          ${routes
            .map((r) => {
              const method = (r.method || 'GET').toUpperCase();
              const methodClass =
                method === 'POST'
                  ? 'method-post'
                  : method === 'DELETE'
                  ? 'method-delete'
                  : method === 'PUT' || method === 'PATCH'
                  ? 'method-put'
                  : 'method-get';
              const flags = r.securityFlags || r.flags || [];
              return `
            <tr>
              <td><span class="method-badge ${methodClass}">${escapeHtml(method)}</span></td>
              <td style="font-family: monospace; font-weight: 600; color: #fff;">${escapeHtml(r.path || '/')}</td>
              <td>
                ${
                  flags.length === 0
                    ? '<span class="tag-badge">PROTECTED</span>'
                    : flags
                        .map(
                          (fl: string) =>
                            `<span class="tag-badge ${fl.includes('NO_AUTH') || fl.includes('UNPROTECTED') ? 'tag-risk' : ''}">${escapeHtml(fl)}</span>`
                        )
                        .join('')
                }
              </td>
              <td style="font-family: monospace; font-size: 12px; color: var(--text-muted);">${escapeHtml(r.filePath || r.file || 'app.js')}</td>
            </tr>`;
            })
            .join('')}
        </tbody>
      </table>`
      }
    </div>

    <!-- TAB 4: COMMAND GUIDE & ARCHITECTURE -->
    <div id="tab-guide" class="tab-panel">
      <div class="guide-banner">
        <h2>🛠️ What Happens After Running Each VibeGuard Command?</h2>
        <p>VibeGuard performs deterministic pre-production auditing through a multi-stage static analysis pipeline. Understand each command and its exact execution step:</p>

        <!-- Pipeline Steps -->
        <div class="pipeline-steps">
          <div class="step-card">
            <div class="step-num">Step 1</div>
            <div class="step-name">Discovery</div>
            <div class="step-desc">Discovers project languages, frameworks, lockfiles, Dockerfiles, and .env files.</div>
          </div>
          <div class="step-card">
            <div class="step-num">Step 2</div>
            <div class="step-name">Graph Analysis</div>
            <div class="step-desc">Maps HTTP routes, data flows, input sources, database queries, and sinks.</div>
          </div>
          <div class="step-card">
            <div class="step-num">Step 3</div>
            <div class="step-name">23 Specialist Analyzers</div>
            <div class="step-desc">Audits secrets, injections, CORS, SSRF, async blocking, and container risks.</div>
          </div>
          <div class="step-card">
            <div class="step-num">Step 4</div>
            <div class="step-name">Readiness Scoring</div>
            <div class="step-desc">Calculates overall production readiness (READY, NEEDS_ATTENTION, or NOT_READY).</div>
          </div>
          <div class="step-card">
            <div class="step-num">Step 5</div>
            <div class="step-name">Remediation</div>
            <div class="step-desc">Provides exact WHAT, WHERE, WHY, HOW, and fix instructions.</div>
          </div>
        </div>

        <!-- Command Cheat Sheet -->
        <h3 style="margin-bottom: 12px; font-size: 15px; color: #fff;">CLI Command Reference & Effects</h3>
        <div class="command-list">
          <div class="cmd-item">
            <span class="cmd-syntax">vibeguard scan [dir]</span>
            <span class="cmd-desc">Runs complete pre-production audit on directory and outputs colorful terminal report. Exit code 2 if blocking risks exist.</span>
          </div>

          <div class="cmd-item">
            <span class="cmd-syntax">vibeguard scan [dir] --deep</span>
            <span class="cmd-desc">Enables multi-file application graph and inter-procedural tainted data flow analysis.</span>
          </div>

          <div class="cmd-item">
            <span class="cmd-syntax">vibeguard dashboard [dir]</span>
            <span class="cmd-desc">Generates and launches this interactive web dashboard in your browser.</span>
          </div>

          <div class="cmd-item">
            <span class="cmd-syntax">vibeguard summary [dir]</span>
            <span class="cmd-desc">Renders high-level production readiness scorecard and metric overview without detailed finding logs.</span>
          </div>

          <div class="cmd-item">
            <span class="cmd-syntax">vibeguard routes [dir]</span>
            <span class="cmd-desc">Discovers and lists all API routes, endpoint methods, and authentication/authorization boundary flags.</span>
          </div>

          <div class="cmd-item">
            <span class="cmd-syntax">vibeguard findings [dir]</span>
            <span class="cmd-desc">Displays a fast, compact list of all detected vulnerabilities and findings sorted by severity.</span>
          </div>

          <div class="cmd-item">
            <span class="cmd-syntax">vibeguard explain &lt;id&gt;</span>
            <span class="cmd-desc">Outputs deterministic remediation breakdown (WHAT, WHERE, WHY, HOW, IMPACT) for any specific rule or finding ID.</span>
          </div>

          <div class="cmd-item">
            <span class="cmd-syntax">vibeguard baseline create [dir]</span>
            <span class="cmd-desc">Generates a fingerprint file to suppress current legacy technical debt and fail only on newly introduced regressions.</span>
          </div>
        </div>
      </div>
    </div>

  </div>

  <script>
    const scanData = ${resultJson};
    let currentSeverity = 'ALL';

    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));

      const targetBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
      if (targetBtn) targetBtn.classList.add('active');

      const targetPanel = document.getElementById('tab-' + tabId);
      if (targetPanel) targetPanel.classList.add('active');
    }

    function setSeverityFilter(sev, el) {
      currentSeverity = sev;
      document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
      el.classList.add('active');
      filterFindings();
    }

    function filterFindings() {
      const query = (document.getElementById('searchInput')?.value || '').toLowerCase().trim();
      const cards = document.querySelectorAll('.finding-card');

      cards.forEach(card => {
        const cardSev = card.getAttribute('data-severity');
        const cardText = card.getAttribute('data-text');

        const matchesSev = currentSeverity === 'ALL' || cardSev === currentSeverity;
        const matchesQuery = !query || cardText.includes(query);

        if (matchesSev && matchesQuery) {
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      });
    }

    function downloadJson() {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scanData, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", "vibeguard-audit-" + (scanData.project?.name || 'report') + ".json");
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    }
  </script>
</body>
</html>`;
}
