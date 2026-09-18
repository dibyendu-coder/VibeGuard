import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class XssAnalyzer implements Analyzer {
  id = 'xss-analyzer';
  name = 'Cross-Site Scripting (XSS) Analyzer';
  category = 'Security';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx']);

    for (const file of files) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        const isXssSink = /dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(/i.test(line);
        if (!isXssSink) continue;

        // Check if content is static or explicitly sanitized: DOMPurify, sanitizeHtml, cleanHtml
        const isSanitizedOrStatic = /DOMPurify|sanitize|cleanHtml|escapeHtml/i.test(line) || /^[^'{]*['"]<[^>]+>['"]\s*\}?\s*$/i.test(line.trim());
        if (isSanitizedOrStatic) {
          continue;
        }

        const hasUserInput = /req\.(query|params|body|headers|cookies)|searchParams|params\.|props\.|input|data\./i.test(
          line
        );

        const severity = hasUserInput ? 'HIGH' : 'MEDIUM';
        const confidence = hasUserInput ? 'HIGH' : 'MEDIUM';

        const fingerprint = generateFingerprint('VBG-XSS-001', file.relativePath, 'Security', line);

        findings.push({
          id: 'VBG-XSS-001',
          title: 'Potential Cross-Site Scripting (XSS) via Unsanitized HTML Sink',
          category: 'Security',
          severity,
          confidence,
          description: 'Rendering unescaped content directly into HTML sink without DOM sanitization.',
          impact: 'Attackers can inject malicious client-side JavaScript scripts to hijack user sessions, steal cookies, or perform actions on behalf of users.',
          evidence: [
            {
              filePath: file.relativePath,
              line: lineNum,
              snippet: line.trim(),
            },
          ],
          file: file.relativePath,
          line: lineNum,
          remediation: 'Sanitize HTML inputs using an established library like DOMPurify or sanitize-html before assigning to HTML sinks.',
          references: ['https://owasp.org/www-community/attacks/xss/'],
          fingerprint,
        });
      }
    }

    return findings;
  }
}
