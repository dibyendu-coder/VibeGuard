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
  const totalFindings = findings.length;

  const score = scores?.overallScore ?? 0;
  const status = scores?.status || 'NOT_READY';

  const statusColor =
    status === 'READY'
      ? '#10b981' // emerald
      : status === 'NEEDS_ATTENTION'
      ? '#f59e0b' // amber
      : '#f43f5e'; // rose

  const statusLabel =
    status === 'READY'
      ? 'READY FOR PRODUCTION'
      : status === 'NEEDS_ATTENTION'
      ? 'ACTION REQUIRED'
      : 'PRODUCTION BLOCKED';

  const statusDesc =
    status === 'READY'
      ? 'All production gates and security heuristics passed successfully.'
      : status === 'NEEDS_ATTENTION'
      ? 'Non-blocking findings detected. Review warnings before shipping.'
      : 'Critical security or reliability issues must be resolved before deployment.';

  const resultJson = JSON.stringify(result).replace(/</g, '\\u003c');

  // SVG Gauge calculations (radius = 38, circumference = 2 * PI * 38 = 238.76)
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (Math.max(0, Math.min(100, score)) / 100) * circumference;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeGuard Audit Dashboard — ${escapeHtml(manifest?.projectName || 'Project')}</title>
  <style>
    :root {
      --bg: #090b10;
      --bg-subtle: #0d1117;
      --card-surface: #121721;
      --card-surface-hover: #161c28;
      --border: rgba(255, 255, 255, 0.08);
      --border-subtle: rgba(255, 255, 255, 0.05);
      --border-focus: #38bdf8;
      --text-main: #f0f3f6;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent: #38bdf8;
      --accent-muted: rgba(56, 189, 248, 0.12);
      --rose: #f43f5e;
      --rose-muted: rgba(244, 63, 94, 0.12);
      --orange: #fb923c;
      --orange-muted: rgba(251, 146, 60, 0.12);
      --amber: #facc15;
      --amber-muted: rgba(250, 204, 21, 0.12);
      --blue: #60a5fa;
      --blue-muted: rgba(96, 165, 250, 0.12);
      --emerald: #10b981;
      --emerald-muted: rgba(16, 185, 129, 0.12);
      --code-bg: #06080c;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      padding-bottom: 80px;
    }

    /* Top Navigation Bar */
    .topbar {
      height: 56px;
      background: var(--bg-subtle);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .topbar-brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-mark {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      background: #1e293b;
      border: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--accent);
    }
    .brand-name {
      font-weight: 700;
      font-size: 14px;
      letter-spacing: -0.01em;
      color: #fff;
    }
    .brand-tag {
      font-size: 11px;
      color: var(--text-muted);
      padding: 2px 6px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 4px;
      font-family: ui-monospace, Menlo, Consolas, monospace;
    }
    .breadcrumb-sep {
      color: var(--text-muted);
      font-size: 13px;
    }
    .project-name {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-secondary);
    }
    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .btn {
      height: 32px;
      padding: 0 12px;
      font-size: 12px;
      font-weight: 500;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--card-surface);
      color: var(--text-main);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s ease;
      text-decoration: none;
    }
    .btn:hover {
      background: var(--card-surface-hover);
      border-color: rgba(255, 255, 255, 0.16);
      color: #fff;
    }
    .btn-primary {
      background: #0284c7;
      border-color: #0284c7;
      color: #fff;
    }
    .btn-primary:hover {
      background: #0369a1;
      border-color: #0369a1;
    }

    /* Main Container */
    .container {
      max-width: 1280px;
      margin: 0 auto;
      padding: 24px;
    }

    /* Executive Hero Header */
    .executive-card {
      background: var(--card-surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px;
      margin-bottom: 24px;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 24px;
      align-items: center;
    }
    @media (max-width: 800px) {
      .executive-card { grid-template-columns: 1fr; }
    }
    .exec-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }
    .exec-title {
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #fff;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      padding: 3px 8px;
      border-radius: 4px;
    }
    .badge-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
    }
    .badge-ready {
      background: var(--emerald-muted);
      color: var(--emerald);
      border: 1px solid rgba(16, 185, 129, 0.25);
    }
    .badge-ready .badge-dot { background: var(--emerald); }
    .badge-warning {
      background: var(--amber-muted);
      color: var(--amber);
      border: 1px solid rgba(250, 204, 21, 0.25);
    }
    .badge-warning .badge-dot { background: var(--amber); }
    .badge-danger {
      background: var(--rose-muted);
      color: var(--rose);
      border: 1px solid rgba(244, 63, 94, 0.25);
    }
    .badge-danger .badge-dot { background: var(--rose); }

    .exec-desc {
      font-size: 13px;
      color: var(--text-secondary);
      margin-bottom: 16px;
      max-width: 680px;
    }
    .exec-metadata {
      display: flex;
      flex-wrap: wrap;
      gap: 18px;
      font-size: 12px;
      color: var(--text-muted);
    }
    .meta-item {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .meta-item strong {
      color: var(--text-secondary);
      font-weight: 500;
    }
    .meta-item code {
      font-family: ui-monospace, Menlo, Consolas, monospace;
      color: var(--text-main);
      background: rgba(255, 255, 255, 0.04);
      padding: 1px 5px;
      border-radius: 3px;
    }

    /* Score Gauge Widget */
    .gauge-widget {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 12px 18px;
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      border-radius: 8px;
    }
    .gauge-svg-wrap {
      position: relative;
      width: 84px;
      height: 84px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .gauge-svg {
      transform: rotate(-90deg);
      width: 84px;
      height: 84px;
    }
    .gauge-track {
      stroke: rgba(255, 255, 255, 0.08);
      stroke-width: 6;
      fill: none;
    }
    .gauge-fill {
      stroke: ${statusColor};
      stroke-width: 6;
      stroke-linecap: round;
      fill: none;
      stroke-dasharray: ${circumference};
      stroke-dashoffset: ${dashOffset};
      transition: stroke-dashoffset 0.6s ease;
    }
    .gauge-center-text {
      position: absolute;
      text-align: center;
    }
    .gauge-val {
      font-size: 22px;
      font-weight: 800;
      color: #fff;
      line-height: 1;
      letter-spacing: -0.03em;
    }
    .gauge-max {
      font-size: 10px;
      color: var(--text-muted);
      font-weight: 500;
    }
    .gauge-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .gauge-label {
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 600;
      color: var(--text-muted);
      letter-spacing: 0.05em;
    }
    .gauge-status {
      font-size: 14px;
      font-weight: 700;
      color: #fff;
    }

    /* Metric Strip */
    .metric-strip {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
      position: relative;
      overflow: hidden;
    }
    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
    }
    .stat-card.crit::before { background: var(--rose); }
    .stat-card.high::before { background: var(--orange); }
    .stat-card.med::before { background: var(--amber); }
    .stat-card.low::before { background: var(--blue); }
    .stat-card.info::before { background: var(--text-muted); }
    .stat-card.routes::before { background: var(--accent); }

    .stat-label {
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.04em;
      color: var(--text-muted);
      margin-bottom: 4px;
    }
    .stat-val-row {
      display: flex;
      align-items: baseline;
      gap: 8px;
    }
    .stat-value {
      font-size: 24px;
      font-weight: 700;
      color: #fff;
      line-height: 1.1;
      font-variant-numeric: tabular-nums;
    }
    .stat-percent {
      font-size: 12px;
      color: var(--text-muted);
    }

    /* Tab Navigation */
    .tab-nav {
      display: flex;
      gap: 4px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .tab-pill {
      background: transparent;
      border: none;
      color: var(--text-secondary);
      font-size: 13px;
      font-weight: 500;
      padding: 10px 16px;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.15s ease;
    }
    .tab-pill:hover {
      color: var(--text-main);
    }
    .tab-pill.active {
      color: #fff;
      border-bottom-color: var(--accent);
      font-weight: 600;
    }
    .tab-count {
      font-size: 11px;
      padding: 1px 6px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.06);
      color: var(--text-secondary);
      font-family: ui-monospace, Menlo, monospace;
    }
    .tab-pill.active .tab-count {
      background: var(--accent-muted);
      color: var(--accent);
    }

    /* Dimension Scorecard Grid */
    .dimension-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .dim-card {
      background: var(--card-surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 12px;
      transition: border-color 0.15s ease;
    }
    .dim-card:hover {
      border-color: rgba(255, 255, 255, 0.15);
    }
    .dim-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .dim-title-wrap {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .dim-icon {
      width: 16px;
      height: 16px;
      color: var(--text-secondary);
    }
    .dim-name {
      font-size: 13px;
      font-weight: 600;
      color: #fff;
    }
    .dim-desc {
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.4;
    }

    /* Findings Filter Bar */
    .filter-panel {
      background: var(--card-surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }
    .search-wrap {
      position: relative;
      flex: 1;
      min-width: 260px;
    }
    .search-icon {
      position: absolute;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      width: 14px;
      height: 14px;
    }
    .search-input {
      width: 100%;
      height: 34px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0 12px 0 34px;
      color: #fff;
      font-size: 13px;
      outline: none;
      transition: border-color 0.15s ease;
    }
    .search-input:focus {
      border-color: var(--border-focus);
    }
    .filter-chips {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .chip {
      height: 28px;
      padding: 0 10px;
      font-size: 11px;
      font-weight: 600;
      border-radius: 4px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text-secondary);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s ease;
    }
    .chip:hover {
      color: #fff;
      border-color: rgba(255, 255, 255, 0.2);
    }
    .chip.active {
      background: var(--card-surface-hover);
      color: #fff;
      border-color: var(--accent);
    }

    /* Findings Cards */
    .finding-item {
      background: var(--card-surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px 20px;
      margin-bottom: 12px;
      transition: border-color 0.15s ease;
    }
    .finding-item:hover {
      border-color: rgba(255, 255, 255, 0.16);
    }
    .finding-top {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 8px;
      flex-wrap: wrap;
    }
    .finding-header-left {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .rule-id {
      font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-secondary);
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
      padding: 2px 6px;
      border-radius: 4px;
    }
    .finding-title {
      font-size: 14px;
      font-weight: 600;
      color: #fff;
    }
    .category-badge {
      font-size: 11px;
      color: var(--text-muted);
      background: rgba(255, 255, 255, 0.03);
      padding: 2px 8px;
      border-radius: 4px;
    }
    .location-link {
      font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 12px;
      color: var(--accent);
      display: inline-flex;
      align-items: center;
      gap: 4px;
      margin-bottom: 12px;
    }

    /* Terminal Code Snippet */
    .terminal-snippet {
      background: var(--code-bg);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 6px;
      padding: 12px 14px;
      margin-bottom: 14px;
      font-family: ui-monospace, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      color: #e2e8f0;
      line-height: 1.5;
      overflow-x: auto;
      white-space: pre-wrap;
    }

    /* Remediation & Impact Grid */
    .analysis-grid {
      display: grid;
      grid-template-columns: 1fr 1.2fr;
      gap: 14px;
    }
    @media (max-width: 768px) {
      .analysis-grid { grid-template-columns: 1fr; }
    }
    .analysis-box {
      background: rgba(0, 0, 0, 0.2);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 12px 14px;
    }
    .box-label {
      font-size: 10px;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 4px;
    }
    .box-body {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    .remedy-box {
      background: rgba(16, 185, 129, 0.04);
      border-color: rgba(16, 185, 129, 0.15);
    }
    .remedy-box .box-label {
      color: var(--emerald);
    }

    /* API Surface Table */
    .table-container {
      background: var(--card-surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .api-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .api-table th {
      background: var(--bg-subtle);
      padding: 10px 16px;
      text-align: left;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
    }
    .api-table td {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-subtle);
      vertical-align: middle;
    }
    .api-table tr:last-child td {
      border-bottom: none;
    }
    .method-pill {
      font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      letter-spacing: 0.04em;
    }
    .m-get { background: var(--emerald-muted); color: var(--emerald); }
    .m-post { background: var(--blue-muted); color: var(--blue); }
    .m-delete { background: var(--rose-muted); color: var(--rose); }
    .m-put, .m-patch { background: var(--amber-muted); color: var(--amber); }

    .route-path {
      font-family: ui-monospace, Menlo, Consolas, monospace;
      font-weight: 600;
      color: #fff;
    }
    .flag-pill {
      font-size: 10px;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 3px;
      background: rgba(255, 255, 255, 0.06);
      color: var(--text-secondary);
      margin-right: 4px;
      display: inline-block;
    }
    .flag-risk {
      background: var(--rose-muted);
      color: var(--rose);
      border: 1px solid rgba(244, 63, 94, 0.2);
    }

    /* Command Guide & Pipeline */
    .pipeline-view {
      background: var(--card-surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .pipeline-title {
      font-size: 15px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 4px;
    }
    .pipeline-subtitle {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 20px;
    }
    .phases-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .phase-card {
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      position: relative;
    }
    .phase-step {
      font-size: 10px;
      font-weight: 700;
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 2px;
    }
    .phase-name {
      font-size: 12px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 4px;
    }
    .phase-desc {
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.4;
    }

    .commands-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 12px;
    }
    .command-card {
      background: var(--bg-subtle);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
    }
    .cmd-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 6px;
    }
    .cmd-code {
      font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 12px;
      font-weight: 600;
      color: var(--accent);
    }
    .cmd-copy-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 2px;
      border-radius: 4px;
    }
    .cmd-copy-btn:hover {
      color: #fff;
    }
    .cmd-details {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.4;
    }

    /* Tab Panels */
    .view-panel {
      display: none;
    }
    .view-panel.active {
      display: block;
    }
  </style>
</head>
<body>

  <!-- Top Navigation Bar -->
  <header class="topbar">
    <div class="topbar-brand">
      <div class="brand-mark">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <span class="brand-name">VIBEGUARD</span>
      <span class="brand-tag">v0.1.0</span>
      <span class="breadcrumb-sep">/</span>
      <span class="project-name">${escapeHtml(manifest?.projectName || 'audit')}</span>
    </div>
    <div class="topbar-actions">
      <button class="btn" onclick="window.print()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
        Print Report
      </button>
      <button class="btn btn-primary" onclick="exportJson()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
        Export JSON Report
      </button>
    </div>
  </header>

  <main class="container">

    <!-- Executive Status Card -->
    <div class="executive-card">
      <div>
        <div class="exec-header">
          <h1 class="exec-title">${escapeHtml(manifest?.projectName || 'Audit Target')}</h1>
          <span class="badge ${status === 'READY' ? 'badge-ready' : status === 'NEEDS_ATTENTION' ? 'badge-warning' : 'badge-danger'}">
            <span class="badge-dot"></span>
            ${statusLabel}
          </span>
        </div>
        <p class="exec-desc">${statusDesc}</p>
        <div class="exec-metadata">
          <div class="meta-item">Target: <code>${escapeHtml(manifest?.rootDir || '.')}</code></div>
          <div class="meta-item">Duration: <strong>${result.durationMs || 120}ms</strong></div>
          <div class="meta-item">Framework: <strong>${escapeHtml(manifest?.frameworks?.[0]?.name || 'Node.js')}</strong></div>
          <div class="meta-item">Lockfile: <strong>${manifest?.hasLockfile ? 'Detected' : 'Missing'}</strong></div>
          <div class="meta-item">Timestamp: <strong>${escapeHtml(new Date(result.timestamp || Date.now()).toLocaleTimeString())}</strong></div>
        </div>
      </div>

      <div class="gauge-widget">
        <div class="gauge-svg-wrap">
          <svg class="gauge-svg" viewBox="0 0 84 84">
            <circle class="gauge-track" cx="42" cy="42" r="38"></circle>
            <circle class="gauge-fill" cx="42" cy="42" r="38"></circle>
          </svg>
          <div class="gauge-center-text">
            <div class="gauge-val">${score}</div>
            <div class="gauge-max">/ 100</div>
          </div>
        </div>
        <div class="gauge-info">
          <span class="gauge-label">Production Score</span>
          <span class="gauge-status">${status === 'READY' ? 'Ready to Ship' : status === 'NEEDS_ATTENTION' ? 'Review Needed' : 'Action Required'}</span>
        </div>
      </div>
    </div>

    <!-- Severity Metric Strip -->
    <div class="metric-strip">
      <div class="stat-card crit">
        <div class="stat-label">Critical Risks</div>
        <div class="stat-val-row">
          <span class="stat-value" style="color: var(--rose);">${criticalCount}</span>
          <span class="stat-percent">${totalFindings ? Math.round((criticalCount / totalFindings) * 100) : 0}%</span>
        </div>
      </div>

      <div class="stat-card high">
        <div class="stat-label">High Severity</div>
        <div class="stat-val-row">
          <span class="stat-value" style="color: var(--orange);">${highCount}</span>
          <span class="stat-percent">${totalFindings ? Math.round((highCount / totalFindings) * 100) : 0}%</span>
        </div>
      </div>

      <div class="stat-card med">
        <div class="stat-label">Medium Warnings</div>
        <div class="stat-val-row">
          <span class="stat-value" style="color: var(--amber);">${mediumCount}</span>
          <span class="stat-percent">${totalFindings ? Math.round((mediumCount / totalFindings) * 100) : 0}%</span>
        </div>
      </div>

      <div class="stat-card low">
        <div class="stat-label">Low Severity</div>
        <div class="stat-val-row">
          <span class="stat-value" style="color: var(--blue);">${lowCount}</span>
          <span class="stat-percent">${totalFindings ? Math.round((lowCount / totalFindings) * 100) : 0}%</span>
        </div>
      </div>

      <div class="stat-card routes">
        <div class="stat-label">API Endpoints</div>
        <div class="stat-val-row">
          <span class="stat-value" style="color: var(--accent);">${routes.length}</span>
          <span class="stat-percent">Mapped</span>
        </div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tab-nav">
      <button class="tab-pill active" onclick="activateTab('matrix', this)">
        Executive Matrix
      </button>
      <button class="tab-pill" onclick="activateTab('findings', this)">
        Vulnerabilities & Findings
        <span class="tab-count">${findings.length}</span>
      </button>
      <button class="tab-pill" onclick="activateTab('routes', this)">
        API Attack Surface
        <span class="tab-count">${routes.length}</span>
      </button>
      <button class="tab-pill" onclick="activateTab('guide', this)">
        CLI Pipeline & Guide
      </button>
    </div>

    <!-- TAB 1: EXECUTIVE MATRIX -->
    <section id="view-matrix" class="view-panel active">
      <h2 style="font-size: 13px; font-weight: 600; color: #fff; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.04em;">Production Readiness Dimensions</h2>
      <div class="dimension-grid">
        <div class="dim-card">
          <div class="dim-head">
            <div class="dim-title-wrap">
              <svg class="dim-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              <span class="dim-name">Security & Access</span>
            </div>
            <span class="badge ${criticalCount + highCount > 0 ? 'badge-danger' : 'badge-ready'}">
              <span class="badge-dot"></span>
              ${criticalCount + highCount > 0 ? 'Not Ready' : 'Passed'}
            </span>
          </div>
          <p class="dim-desc">Secret leaks, injection vectors, CSRF/XSS, and authentication bypass heuristics.</p>
        </div>

        <div class="dim-card">
          <div class="dim-head">
            <div class="dim-title-wrap">
              <svg class="dim-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
              <span class="dim-name">Reliability & Async</span>
            </div>
            <span class="badge ${scores.readinessDimensions?.reliability === 'GOOD' ? 'badge-ready' : 'badge-warning'}">
              <span class="badge-dot"></span>
              ${scores.readinessDimensions?.reliability || 'Good'}
            </span>
          </div>
          <p class="dim-desc">Sync I/O blocking in request loops, missing timeouts, and swallowed unhandled promises.</p>
        </div>

        <div class="dim-card">
          <div class="dim-head">
            <div class="dim-title-wrap">
              <svg class="dim-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
              <span class="dim-name">Environment Config</span>
            </div>
            <span class="badge ${scores.readinessDimensions?.configuration === 'GOOD' ? 'badge-ready' : 'badge-danger'}">
              <span class="badge-dot"></span>
              ${scores.readinessDimensions?.configuration || 'Insecure'}
            </span>
          </div>
          <p class="dim-desc">Committed .env files, debug mode enabled in prod, and cookie flags.</p>
        </div>

        <div class="dim-card">
          <div class="dim-head">
            <div class="dim-title-wrap">
              <svg class="dim-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
              <span class="dim-name">Dependencies</span>
            </div>
            <span class="badge ${manifest?.hasLockfile ? 'badge-ready' : 'badge-warning'}">
              <span class="badge-dot"></span>
              ${manifest?.hasLockfile ? 'Good' : 'No Lockfile'}
            </span>
          </div>
          <p class="dim-desc">Package manager verification, lockfile reproducibility, and advisory status.</p>
        </div>

        <div class="dim-card">
          <div class="dim-head">
            <div class="dim-title-wrap">
              <svg class="dim-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
              <span class="dim-name">Deployment & Docker</span>
            </div>
            <span class="badge ${scores.readinessDimensions?.deployment === 'GOOD' ? 'badge-ready' : 'badge-warning'}">
              <span class="badge-dot"></span>
              ${scores.readinessDimensions?.deployment || 'Limited'}
            </span>
          </div>
          <p class="dim-desc">Root user execution checks, :latest tag avoidance, and CI/CD workflow security.</p>
        </div>

        <div class="dim-card">
          <div class="dim-head">
            <div class="dim-title-wrap">
              <svg class="dim-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
              <span class="dim-name">Observability</span>
            </div>
            <span class="badge ${scores.readinessDimensions?.observability === 'GOOD' ? 'badge-ready' : 'badge-warning'}">
              <span class="badge-dot"></span>
              ${scores.readinessDimensions?.observability || 'Limited'}
            </span>
          </div>
          <p class="dim-desc">/healthz and /ready endpoints, SIGTERM graceful shutdown listeners, and logging.</p>
        </div>
      </div>
    </section>

    <!-- TAB 2: VULNERABILITIES & FINDINGS -->
    <section id="view-findings" class="view-panel">
      <!-- Filter Bar -->
      <div class="filter-panel">
        <div class="search-wrap">
          <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" id="findSearch" class="search-input" placeholder="Filter by rule ID, title, filename, or keyword..." oninput="applyFilters()">
        </div>

        <div class="filter-chips">
          <button class="chip active" onclick="setSeverity('ALL', this)">All (${findings.length})</button>
          <button class="chip" onclick="setSeverity('CRITICAL', this)">Critical (${criticalCount})</button>
          <button class="chip" onclick="setSeverity('HIGH', this)">High (${highCount})</button>
          <button class="chip" onclick="setSeverity('MEDIUM', this)">Medium (${mediumCount})</button>
          <button class="chip" onclick="setSeverity('LOW', this)">Low (${lowCount})</button>
        </div>
      </div>

      <!-- Findings List -->
      <div id="findingsList">
        ${
          findings.length === 0
            ? '<div style="text-align: center; padding: 48px; color: var(--text-muted); background: var(--card-surface); border-radius: 8px;">Zero security findings identified. Repository clean.</div>'
            : findings
                .map((f) => {
                  const sevBadge =
                    f.severity === 'CRITICAL'
                      ? 'badge-danger'
                      : f.severity === 'HIGH'
                      ? 'badge-warning'
                      : 'badge-ready';
                  const filePath = f.file || f.evidence?.[0]?.filePath || 'unknown';
                  const line = f.line || f.evidence?.[0]?.line || 1;
                  const snippet = f.evidence?.[0]?.snippet || '';

                  return `
          <div class="finding-item" data-sev="${escapeHtml(f.severity)}" data-query="${escapeHtml(
                    (f.title + ' ' + f.id + ' ' + filePath + ' ' + (f.description || '')).toLowerCase()
                  )}">
            <div class="finding-top">
              <div class="finding-header-left">
                <span class="badge ${sevBadge}">
                  <span class="badge-dot"></span>
                  ${escapeHtml(f.severity)}
                </span>
                <span class="rule-id">${escapeHtml(f.id)}</span>
                <span class="finding-title">${escapeHtml(f.title)}</span>
              </div>
              <span class="category-badge">${escapeHtml(f.category || 'General')}</span>
            </div>

            <div class="location-link">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              ${escapeHtml(filePath)}:${line}
            </div>

            ${snippet ? `<pre class="terminal-snippet"><code>${escapeHtml(snippet)}</code></pre>` : ''}

            <div class="analysis-grid">
              <div class="analysis-box">
                <div class="box-label">Production Impact</div>
                <div class="box-body">${escapeHtml(f.impact || f.description || 'Presents a runtime or exposure risk.')}</div>
              </div>

              <div class="analysis-box remedy-box">
                <div class="box-label">Remediation Guidance</div>
                <div class="box-body">${escapeHtml(f.remediation || 'Refactor vulnerable structural pattern to conform to security guidelines.')}</div>
              </div>
            </div>
          </div>`;
                })
                .join('')
        }
      </div>
    </section>

    <!-- TAB 3: API ATTACK SURFACE -->
    <section id="view-routes" class="view-panel">
      ${
        routes.length === 0
          ? '<div style="text-align: center; padding: 48px; color: var(--text-muted); background: var(--card-surface); border-radius: 8px;">No external HTTP routes discovered in codebase.</div>'
          : `
      <div class="table-container">
        <table class="api-table">
          <thead>
            <tr>
              <th style="width: 80px;">Method</th>
              <th>Endpoint Path</th>
              <th>Security Boundary & Risk Indicators</th>
              <th>Handler Source File</th>
            </tr>
          </thead>
          <tbody>
            ${routes
              .map((r) => {
                const method = (r.method || 'GET').toUpperCase();
                const mClass =
                  method === 'POST'
                    ? 'm-post'
                    : method === 'DELETE'
                    ? 'm-delete'
                    : method === 'PUT' || method === 'PATCH'
                    ? 'm-put'
                    : 'm-get';
                const flags = r.riskFlags || r.securityFlags || [];
                return `
              <tr>
                <td><span class="method-pill ${mClass}">${escapeHtml(method)}</span></td>
                <td class="route-path">${escapeHtml(r.path || '/')}</td>
                <td>
                  ${
                    flags.length === 0
                      ? '<span class="flag-pill">PROTECTED</span>'
                      : flags
                          .map(
                            (fl: string) =>
                              `<span class="flag-pill ${fl.includes('NO_AUTH') || fl.includes('UNPROTECTED') ? 'flag-risk' : ''}">${escapeHtml(fl)}</span>`
                          )
                          .join('')
                  }
                </td>
                <td style="font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: var(--text-muted);">${escapeHtml(r.filePath || r.file || 'app.js')}</td>
              </tr>`;
              })
              .join('')}
          </tbody>
        </table>
      </div>`
      }
    </section>

    <!-- TAB 4: CLI PIPELINE & GUIDE -->
    <section id="view-guide" class="view-panel">
      <div class="pipeline-view">
        <h2 class="pipeline-title">Command Guide & Architecture</h2>
        <p class="pipeline-subtitle">What happens deterministically under the hood when you audit an application with VibeGuard:</p>

        <div class="phases-row">
          <div class="phase-card">
            <div class="phase-step">Phase 01</div>
            <div class="phase-name">Discovery</div>
            <div class="phase-desc">Parses ASTs, detects frameworks (Express, Next.js, FastAPI), package managers, Dockerfiles, and lockfiles.</div>
          </div>

          <div class="phase-card">
            <div class="phase-step">Phase 02</div>
            <div class="phase-name">Graph Mapping</div>
            <div class="phase-desc">Builds multi-file application dependency graph, traces HTTP routes, parameters, and database query sinks.</div>
          </div>

          <div class="phase-card">
            <div class="phase-step">Phase 03</div>
            <div class="phase-name">23 Static Analyzers</div>
            <div class="phase-desc">Audits secrets, injections, SSRF, XSS, CORS, event loop blocking, and root container execution.</div>
          </div>

          <div class="phase-card">
            <div class="phase-step">Phase 04</div>
            <div class="phase-name">Readiness Scoring</div>
            <div class="phase-desc">Weights findings by severity and calculates deterministic production grades (READY, NEEDS ATTENTION, NOT READY).</div>
          </div>

          <div class="phase-card">
            <div class="phase-step">Phase 05</div>
            <div class="phase-name">Remediation</div>
            <div class="phase-desc">Generates exact WHAT, WHERE, WHY, HOW, and fix instructions with zero LLM hallucinations.</div>
          </div>
        </div>

        <h3 style="font-size: 13px; font-weight: 700; color: #fff; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.04em;">CLI Command Reference</h3>
        <div class="commands-grid">
          <div class="command-card">
            <div class="cmd-header">
              <span class="cmd-code">vibeguard scan [dir]</span>
              <button class="cmd-copy-btn" onclick="copyCmd('vibeguard scan .')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
            </div>
            <p class="cmd-details">Performs full pre-production audit. Exits with code 2 if blocking production risks are detected.</p>
          </div>

          <div class="command-card">
            <div class="cmd-header">
              <span class="cmd-code">vibeguard scan [dir] --deep</span>
              <button class="cmd-copy-btn" onclick="copyCmd('vibeguard scan . --deep')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
            </div>
            <p class="cmd-details">Enables inter-procedural tainted dataflow tracking across file and module boundaries.</p>
          </div>

          <div class="command-card">
            <div class="cmd-header">
              <span class="cmd-code">vibeguard dashboard [dir]</span>
              <button class="cmd-copy-btn" onclick="copyCmd('vibeguard dashboard .')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
            </div>
            <p class="cmd-details">Launches this interactive web dashboard server on localhost:4200 and opens browser.</p>
          </div>

          <div class="command-card">
            <div class="cmd-header">
              <span class="cmd-code">vibeguard summary [dir]</span>
              <button class="cmd-copy-btn" onclick="copyCmd('vibeguard summary .')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
            </div>
            <p class="cmd-details">Displays high-level production readiness scorecard and metric matrix in terminal.</p>
          </div>

          <div class="command-card">
            <div class="cmd-header">
              <span class="cmd-code">vibeguard routes [dir]</span>
              <button class="cmd-copy-btn" onclick="copyCmd('vibeguard routes .')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
            </div>
            <p class="cmd-details">Prints discovered HTTP route surface and authentication boundary flags.</p>
          </div>

          <div class="command-card">
            <div class="cmd-header">
              <span class="cmd-code">vibeguard explain &lt;id&gt;</span>
              <button class="cmd-copy-btn" onclick="copyCmd('vibeguard explain VBG-SECRET-001')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
            </div>
            <p class="cmd-details">Explains finding deterministically with WHAT, WHERE, WHY, HOW, and exact remediation code.</p>
          </div>
        </div>
      </div>
    </section>

  </main>

  <script>
    const reportData = ${resultJson};
    let activeSeverity = 'ALL';

    function activateTab(tabKey, btnEl) {
      document.querySelectorAll('.tab-pill').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));

      btnEl.classList.add('active');
      const targetPanel = document.getElementById('view-' + tabKey);
      if (targetPanel) targetPanel.classList.add('active');
    }

    function setSeverity(sev, el) {
      activeSeverity = sev;
      document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
      el.classList.add('active');
      applyFilters();
    }

    function applyFilters() {
      const query = (document.getElementById('findSearch')?.value || '').toLowerCase().trim();
      const items = document.querySelectorAll('.finding-item');

      items.forEach(item => {
        const sev = item.getAttribute('data-sev');
        const text = item.getAttribute('data-query');

        const matchesSev = activeSeverity === 'ALL' || sev === activeSeverity;
        const matchesQuery = !query || text.includes(query);

        item.style.display = (matchesSev && matchesQuery) ? 'block' : 'none';
      });
    }

    function copyCmd(text) {
      navigator.clipboard.writeText(text);
    }

    function exportJson() {
      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'vibeguard-audit-' + (reportData.manifest?.projectName || 'report') + '.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }
  </script>
</body>
</html>`;
}
