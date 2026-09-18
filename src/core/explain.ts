import pc from 'picocolors';
import { Finding } from './types.js';

export function explainFinding(finding: Finding, isNoColor: boolean = false): string {
  const c = isNoColor
    ? {
        bold: (s: string) => s,
        red: (s: string) => s,
        yellow: (s: string) => s,
        cyan: (s: string) => s,
        green: (s: string) => s,
        dim: (s: string) => s,
      }
    : pc;

  const lines: string[] = [];

  lines.push('');
  lines.push(c.bold(`FINDING EXPLANATION: ${finding.id}`));
  lines.push('─────────────────────────────────────────────────────────────────');
  lines.push(`${c.bold('Title:')}       ${finding.title}`);
  lines.push(`${c.bold('Category:')}    ${finding.category}${finding.subcategory ? ` (${finding.subcategory})` : ''}`);
  lines.push(`${c.bold('Severity:')}    ${finding.severity}`);
  lines.push(`${c.bold('Confidence:')}  ${finding.confidence}`);
  if (finding.exploitability) {
    lines.push(`${c.bold('Exploitability:')} ${finding.exploitability}`);
  }
  lines.push(`${c.bold('Location:')}    ${finding.file || 'unknown'}:${finding.line || 1}`);
  lines.push('');

  lines.push(c.bold('WHAT (Description):'));
  lines.push(`  ${finding.description}`);
  lines.push('');

  lines.push(c.bold('WHERE (Evidence):'));
  if (finding.evidence && finding.evidence.length > 0) {
    finding.evidence.forEach((ev) => {
      lines.push(`  File: ${ev.filePath}:${ev.line || 1}`);
      if (ev.snippet) {
        lines.push(`  Snippet: ${c.dim(ev.snippet)}`);
      }
    });
  } else {
    lines.push(`  File: ${finding.file || 'unknown'}:${finding.line || 1}`);
  }
  lines.push('');

  lines.push(c.bold('WHY (Detection Reason & Context):'));
  lines.push(`  ${finding.confidence_reason || finding.detection_reason || 'Static deterministic analysis rules matched vulnerable structural code patterns.'}`);
  lines.push('');

  if (finding.data_flow && finding.data_flow.length > 0) {
    lines.push(c.bold('HOW (Taint & Data-Flow Propagation):'));
    finding.data_flow.forEach((step, idx) => {
      lines.push(`  Step ${idx + 1} [${step.type.toUpperCase()}]: ${step.file}:${step.line} -> ${step.description}`);
    });
    lines.push('');
  }

  lines.push(c.bold('IMPACT:'));
  lines.push(`  ${finding.impact}`);
  if (finding.production_impact) {
    lines.push(`  Production Risk: ${finding.production_impact}`);
  }
  lines.push('');

  lines.push(c.bold('HOW TO FIX (Remediation):'));
  lines.push(`  ${finding.remediation}`);
  lines.push('');

  if (finding.references && finding.references.length > 0) {
    lines.push(c.bold('REFERENCES:'));
    finding.references.forEach((ref) => lines.push(`  - ${ref}`));
    lines.push('');
  }

  lines.push('─────────────────────────────────────────────────────────────────');
  return lines.join('\n');
}
