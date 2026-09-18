import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class CorsSecurityAnalyzer implements Analyzer {
  id = 'cors-security-analyzer';
  name = 'CORS Misconfiguration Analyzer';
  category = 'Configuration';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py', '.json']);

    for (const file of files) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        // 1. Wildcard origin with credentials
        if (
          /(origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin.*\*)/i.test(line) &&
          (/credentials/i.test(line) || /credentials/i.test(file.content))
        ) {
          const fingerprint = generateFingerprint('VBG-CORS-001', file.relativePath, 'Configuration', line);
          findings.push({
            id: 'VBG-CORS-001',
            title: 'Permissive CORS Configuration: Wildcard Origin with Credentials Allowed',
            category: 'Configuration',
            severity: 'HIGH',
            confidence: 'HIGH',
            description: "CORS configuration uses wildcard '*' origin combined with credentials mode.",
            impact: 'Third-party sites can perform cross-origin authenticated requests and read response data.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Specify an explicit list of trusted origin domains when credentials are enabled.',
            references: ['https://portswigger.net/web-security/cors'],
            fingerprint,
          });
        }
        // 2. Reflected Origin in CORS header
        else if (/Access-Control-Allow-Origin.*req\.headers\.origin/i.test(line) || /origin\s*:\s*req\.headers\.origin/i.test(line)) {
          const fingerprint = generateFingerprint('VBG-CORS-002', file.relativePath, 'Configuration', line);
          findings.push({
            id: 'VBG-CORS-002',
            title: 'Reflected CORS Origin Misconfiguration',
            category: 'Configuration',
            severity: 'HIGH',
            confidence: 'HIGH',
            description: 'CORS dynamically reflects incoming Request Origin header without validating against an allowed domain list.',
            impact: 'Any domain can send authenticated requests with credentials and access confidential user responses.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Validate req.headers.origin against a whitelist of trusted domains before setting Access-Control-Allow-Origin.',
            references: ['https://portswigger.net/web-security/cors'],
            fingerprint,
          });
        }
      }
    }

    return findings;
  }
}
