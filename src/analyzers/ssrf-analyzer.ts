import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class SsrfAnalyzer implements Analyzer {
  id = 'ssrf-analyzer';
  name = 'Server-Side Request Forgery (SSRF) Analyzer';
  category = 'Security';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py']);

    for (const file of files) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        const isHttpFetch = /fetch\s*\(|axios\.(get|post|put|delete|request)|requests\.(get|post|put|delete)|urllib\.request/i.test(
          line
        );
        if (!isHttpFetch) continue;

        // Check if URL is hardcoded static string: e.g. fetch("https://api.example.com/data")
        const isStaticUrl = /^[^'"\+]*fetch\s*\(\s*['"]https?:\/\/[^'"]+['"]\s*[\),]/i.test(line.trim());
        if (isStaticUrl) {
          // Static hardcoded URL - safe, do not flag
          continue;
        }

        const hasUserInput = /req\.(query|params|body|headers|cookies)|searchParams|params\.|request\.(args|form|json|headers|cookies)/i.test(
          line
        );

        if (hasUserInput) {
          const fingerprint = generateFingerprint('VBG-SSRF-001', file.relativePath, 'Security', line);

          findings.push({
            id: 'VBG-SSRF-001',
            title: 'Potential Server-Side Request Forgery (SSRF)',
            category: 'Security',
            severity: 'HIGH',
            confidence: 'HIGH',
            description: 'User-controlled input directly influences the target URL of an outbound HTTP request.',
            impact: 'An attacker can force the server to issue HTTP requests to internal intranet services, cloud metadata endpoints (169.254.169.254), or arbitrary external hosts.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Validate and restrict target URLs against an explicit domain whitelist. Prevent connections to internal IP address ranges and metadata services.',
            references: ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
            fingerprint,
          });
        }
      }
    }

    return findings;
  }
}
