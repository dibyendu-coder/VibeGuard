import pc from 'picocolors';
import { Confidence, Finding, ScanResult, Severity } from '../core/types.js';

export { maskSecret } from '../core/masker.js';

export function formatSeverity(severity: Severity, noColor = false): string {
  if (noColor) {
    return severity;
  }
  switch (severity) {
    case 'CRITICAL':
      return pc.bgRed(pc.black(pc.bold(' CRITICAL ')));
    case 'HIGH':
      return pc.red(pc.bold('HIGH'));
    case 'MEDIUM':
      return pc.yellow(pc.bold('MEDIUM'));
    case 'LOW':
      return pc.cyan('LOW');
    case 'INFO':
      return pc.dim('INFO');
  }
}

export function formatConfidence(confidence: Confidence, noColor = false): string {
  if (noColor) {
    return `${confidence} CONFIDENCE`;
  }
  switch (confidence) {
    case 'HIGH':
      return pc.green(pc.bold('HIGH CONFIDENCE'));
    case 'MEDIUM':
      return pc.yellow('MEDIUM CONFIDENCE');
    case 'LOW':
      return pc.dim('LOW CONFIDENCE');
  }
}

export function formatFindingCard(finding: Finding, noColor = false): string {
  const sev = formatSeverity(finding.severity, noColor);
  const conf = formatConfidence(finding.confidence, noColor);

  const titleLine = noColor
    ? `[${finding.severity}] ${finding.id} ${finding.title}`
    : `${pc.bold(finding.id)}  ${sev}  ${pc.bold(finding.title)}`;

  const divider = noColor ? '─'.repeat(54) : pc.dim('─'.repeat(54));

  let body = `${titleLine}\n${divider}\n`;
  body += `${noColor ? 'Category:' : pc.dim('Category:')} ${finding.category}  ${noColor ? '│' : pc.dim('│')}  ${conf}\n\n`;
  body += `${finding.description}\n`;

  if (finding.evidence.length > 0) {
    body += `\n${noColor ? 'Evidence:' : pc.bold('Evidence:')}\n`;
    finding.evidence.forEach((ev) => {
      const loc = ev.line ? `${ev.filePath}:${ev.line}` : ev.filePath;
      const snippetStr = ev.snippet ? `\n   ${noColor ? ev.snippet : pc.dim(ev.snippet)}` : '';
      body += `  ${noColor ? '→' : pc.cyan('→')} ${noColor ? loc : pc.bold(loc)}${snippetStr}\n`;
    });
  }

  body += `\n${noColor ? 'Why it matters:' : pc.bold('Why it matters:')}\n  ${finding.impact}\n`;
  body += `\n${noColor ? 'Remediation:' : pc.bold('Remediation:')}\n  ${finding.remediation}\n`;

  if (finding.references && finding.references.length > 0) {
    body += `\n${noColor ? 'References:' : pc.dim('References:')}\n  ${noColor ? finding.references.join('\n  ') : pc.dim(finding.references.join('\n  '))}\n`;
  }

  return body;
}

export function renderProgressStages(result: ScanResult, noColor = false): string {
  const { manifest, analyzerStatuses, graphSummary, baselineStatus } = result;
  let out = '';

  // 1. Discovering project section
  out += noColor ? '\n◆ Project\n' : `\n${pc.bold(pc.cyan('◆ Project'))}\n`;

  if (manifest.frameworks.length > 0) {
    manifest.frameworks.forEach((fw) => {
      const vStr = fw.version ? ` (${fw.version})` : '';
      out += noColor ? `  ✓ ${fw.name}${vStr}\n` : `  ${pc.green('✓')} ${fw.name}${pc.dim(vStr)}\n`;
    });
  }
  if (manifest.languages.length > 0) {
    manifest.languages.forEach((lang) => {
      out += noColor ? `  ✓ ${lang}\n` : `  ${pc.green('✓')} ${lang}\n`;
    });
  }
  if (manifest.packageManager) {
    out += noColor
      ? `  ✓ Package Manager: ${manifest.packageManager} (Lockfile: ${manifest.hasLockfile ? 'Yes' : 'No'})\n`
      : `  ${pc.green('✓')} Package Manager: ${pc.cyan(manifest.packageManager)} ${pc.dim(`(Lockfile: ${manifest.hasLockfile ? 'Yes' : 'No'})`)}\n`;
  }

  // 2. Application Graph summary if available
  if (graphSummary) {
    out += noColor ? '\n◆ Application graph\n' : `\n${pc.bold(pc.cyan('◆ Application graph'))}\n`;
    out += noColor ? `  ✓ ${graphSummary.routesCount} routes\n` : `  ${pc.green('✓')} ${graphSummary.routesCount} routes\n`;
    out += noColor ? `  ✓ ${graphSummary.modulesCount} modules\n` : `  ${pc.green('✓')} ${graphSummary.modulesCount} modules\n`;
    out += noColor ? `  ✓ ${graphSummary.externalCallsCount} external calls\n` : `  ${pc.green('✓')} ${graphSummary.externalCallsCount} external calls\n`;
    out += noColor ? `  ✓ ${graphSummary.databaseOpsCount} database operations\n` : `  ${pc.green('✓')} ${graphSummary.databaseOpsCount} database operations\n`;
  }

  // 3. Security Analysis Section
  out += noColor ? '\n◆ Security analysis\n' : `\n${pc.bold(pc.cyan('◆ Security analysis'))}\n`;

  for (const st of analyzerStatuses) {
    const mark =
      st.status === 'failed'
        ? noColor ? '✗' : pc.red('✗')
        : st.findingsCount > 0
        ? noColor ? '⚠' : pc.yellow('⚠')
        : noColor ? '✓' : pc.green('✓');

    const countStr =
      st.findingsCount > 0
        ? noColor ? `(${st.findingsCount} findings)` : pc.dim(`(${st.findingsCount} findings)`)
        : noColor ? '(passed)' : pc.dim('(passed)');

    out += `  ${mark} ${st.name} ${countStr}\n`;
  }

  if (baselineStatus) {
    out += noColor
      ? `\n  [Baseline Mode Active] Suppressed ${baselineStatus.suppressedFindings} existing findings, ${baselineStatus.newFindings} new findings\n`
      : `\n  ${pc.yellow('[Baseline Active]')} Suppressed ${baselineStatus.suppressedFindings} existing, ${pc.bold(baselineStatus.newFindings + ' new findings')}\n`;
  }

  return out;
}

export function renderApiSurface(routes: any[], noColor = false): string {
  if (!routes || routes.length === 0) return '';
  let out = `\n${noColor ? 'API SURFACE' : pc.bold(pc.cyan('API SURFACE'))}\n`;
  out += `${noColor ? '─'.repeat(54) : pc.dim('─'.repeat(54))}\n`;

  for (const r of routes) {
    const mStr = (r.method || 'GET').padEnd(6);
    const methodFormatted = noColor
      ? mStr
      : r.method === 'GET'
      ? pc.green(mStr)
      : r.method === 'POST'
      ? pc.blue(mStr)
      : r.method === 'DELETE'
      ? pc.red(mStr)
      : pc.yellow(mStr);

    const flagsStr = r.riskFlags && r.riskFlags.length > 0 ? ` [${r.riskFlags.join(', ')}]` : '';
    out += `  ${methodFormatted} ${r.path}${noColor ? flagsStr : pc.dim(flagsStr)}\n`;
  }
  return out;
}

export function renderTerminalReport(result: ScanResult, noColor = false): string {
  const { manifest, findings, scores, durationMs, routes, graphSummary } = result;
  const c = noColor
    ? {
        bold: (s: string) => s,
        green: (s: string) => s,
        red: (s: string) => s,
        yellow: (s: string) => s,
        cyan: (s: string) => s,
        dim: (s: string) => s,
      }
    : pc;

  let output = '';

  // Progressive summary stages
  output += renderProgressStages(result, noColor);

  const statusStr =
    scores.status === 'READY'
      ? 'STATUS: READY'
      : scores.status === 'NEEDS_ATTENTION'
      ? 'STATUS: NEEDS ATTENTION'
      : 'STATUS: NOT READY';

  output += `\n${c.bold('Audit complete.')} (${c.bold('AUDIT COMPLETE')} - ${statusStr})\n\n`;

  // Production Readiness Dimensions Table
  output += `${c.bold('Production Readiness')}\n`;
  output += `${c.dim('────────────────────────────────────')}\n`;

  const dims = scores.readinessDimensions || {
    security: scores.securityScore >= 80 ? 'READY' : 'NEEDS_ATTENTION',
    reliability: scores.reliabilityScore >= 80 ? 'GOOD' : 'NEEDS_ATTENTION',
    configuration: scores.configScore >= 80 ? 'GOOD' : 'NEEDS_ATTENTION',
    dependencies: 'REVIEW',
    deployment: 'LIMITED',
    observability: 'LIMITED',
    testing: 'LIMITED',
  };

  const dimRows: [string, string][] = [
    ['Security', dims.security],
    ['Reliability', dims.reliability],
    ['Configuration', dims.configuration],
    ['Dependencies', dims.dependencies],
    ['Deployment', dims.deployment],
    ['Observability', dims.observability],
    ['Testing', dims.testing],
  ];

  dimRows.forEach(([name, status]) => {
    let formattedStatus = status;
    if (!noColor) {
      if (status === 'READY' || status === 'GOOD') formattedStatus = pc.green(pc.bold(status));
      else if (status === 'NEEDS_ATTENTION' || status === 'REVIEW' || status === 'LIMITED') formattedStatus = pc.yellow(pc.bold(status));
      else formattedStatus = pc.red(pc.bold(status));
    }
    output += `${name.padEnd(18)} ${formattedStatus}\n`;
  });

  // Findings Breakdown
  output += `\n${c.bold('Findings')}\n\n`;
  output += `${c.red('CRITICAL').padEnd(18)} ${scores.criticalCount}\n`;
  output += `${c.red('HIGH').padEnd(18)} ${scores.highCount}\n`;
  output += `${c.yellow('MEDIUM').padEnd(18)} ${scores.mediumCount}\n`;
  output += `${c.cyan('LOW').padEnd(18)} ${scores.lowCount}\n`;
  output += `${c.dim('INFO').padEnd(18)} ${scores.infoCount}\n`;

  // Summary Metrics
  const routesCount = routes ? routes.length : manifest.routesCount || 0;
  const flowsCount = result.correlatedFindings ? result.correlatedFindings.length * 2 : 0;
  const filesCount = manifest.sourceFilesCount || manifest.totalFilesCount || 0;

  output += `\nRoutes discovered: ${routesCount}\n`;
  output += `Data flows analyzed: ${flowsCount}\n`;
  output += `Files analyzed: ${filesCount}\n`;

  // Detailed Findings Cards if findings exist
  if (findings.length > 0) {
    output += `\n${c.dim('────────────────────────────────────')}\n`;
    output += `${c.bold('DETAILED FINDINGS (' + findings.length + ')')}\n\n`;
    findings.forEach((finding) => {
      output += formatFindingCard(finding, noColor) + '\n';
    });
  }

  // Recommended Next Steps
  output += `\n${c.bold('Run:')}\n\n`;
  output += `  vibeguard findings .\n`;
  output += `  vibeguard explain <id>\n`;
  output += `  vibeguard routes .\n`;
  output += `  vibeguard scan . --json\n`;

  return output;
}
