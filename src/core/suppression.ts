import fs from 'fs';
import path from 'path';
import { Finding } from './types.js';

export interface SuppressionResult {
  activeFindings: Finding[];
  suppressedCount: number;
  suppressedRuleIds: string[];
}

export function loadIgnoreFile(projectRoot: string): Set<string> {
  const ignoreSet = new Set<string>();
  const ignorePath = path.join(projectRoot, '.vibeguardignore');

  if (fs.existsSync(ignorePath)) {
    try {
      const content = fs.readFileSync(ignorePath, 'utf-8');
      content.split(/\r?\n/).forEach((line) => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          ignoreSet.add(trimmed);
        }
      });
    } catch {
      // ignore read errors
    }
  }

  return ignoreSet;
}

export function filterSuppressedFindings(
  findings: Finding[],
  projectRoot: string
): SuppressionResult {
  const fileIgnoredRules = loadIgnoreFile(projectRoot);
  const activeFindings: Finding[] = [];
  const suppressedRuleIds: string[] = [];

  for (const finding of findings) {
    // 1. Check .vibeguardignore match by ID, rule_id, or fingerprint
    if (
      fileIgnoredRules.has(finding.id) ||
      (finding.rule_id && fileIgnoredRules.has(finding.rule_id)) ||
      fileIgnoredRules.has(finding.fingerprint)
    ) {
      suppressedRuleIds.push(finding.id);
      continue;
    }

    // 2. Check inline file comments if file is available
    if (finding.file) {
      try {
        const resolvedRoot = path.resolve(projectRoot);
        const fullPath = path.resolve(resolvedRoot, finding.file);

        // Security Audit Fix: Ensure target file is strictly within projectRoot
        if (!fullPath.startsWith(resolvedRoot + path.sep) && fullPath !== resolvedRoot) {
          activeFindings.push(finding);
          continue;
        }

        if (fs.existsSync(fullPath)) {
          const content = fs.readFileSync(fullPath, 'utf-8');
          const lines = content.split(/\r?\n/);

          // File-level inline ignore: /* vibeguard-ignore-file VBG-xxx */
          const hasFileIgnore = lines.some((l) =>
            l.includes('vibeguard-ignore-file') &&
            (l.includes(finding.id) || (finding.rule_id && l.includes(finding.rule_id)))
          );

          if (hasFileIgnore) {
            suppressedRuleIds.push(finding.id);
            continue;
          }

          // Line-level inline ignore on finding line or line immediately preceding it
          if (finding.line && finding.line > 0) {
            const targetLineIdx = finding.line - 1;
            const currentLine = lines[targetLineIdx] || '';
            const prevLine = targetLineIdx > 0 ? lines[targetLineIdx - 1] : '';

            const hasLineIgnore =
              (currentLine.includes('vibeguard-ignore-line') || prevLine.includes('vibeguard-ignore-line')) &&
              (currentLine.includes(finding.id) ||
                prevLine.includes(finding.id) ||
                (finding.rule_id && (currentLine.includes(finding.rule_id) || prevLine.includes(finding.rule_id))));

            if (hasLineIgnore) {
              suppressedRuleIds.push(finding.id);
              continue;
            }
          }
        }
      } catch {
        // ignore inline file read error
      }
    }

    activeFindings.push(finding);
  }

  return {
    activeFindings,
    suppressedCount: suppressedRuleIds.length,
    suppressedRuleIds,
  };
}
