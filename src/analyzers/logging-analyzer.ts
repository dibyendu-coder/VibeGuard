import { generateFingerprint } from '../core/fingerprint.js';
import { maskSnippet } from '../core/masker.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class LoggingAnalyzer implements Analyzer {
  id = 'logging-analyzer';
  name = 'Logging & Information Disclosure Analyzer';
  category = 'Privacy';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py']);

    for (const file of files) {
      // Don't flag test fixtures or test files unless they are intended
      const isTestFile = file.relativePath.includes('test') || file.relativePath.includes('spec');
      if (isTestFile && !file.relativePath.includes('fixtures/vulnerable-')) {
        continue;
      }

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;
        const trimmed = line.trim();

        if (trimmed.startsWith('//') || trimmed.startsWith('#')) continue;

        // Rule 3: Dumping process.env / os.environ to logs (VBG-LOG-003)
        if (
          /console\.(?:log|info|warn|error|dir)\(\s*process\.env\s*\)/i.test(trimmed) ||
          /logging\.(?:info|debug|warning|error)\(\s*os\.environ\s*\)/i.test(trimmed)
        ) {
          const fp = generateFingerprint('VBG-LOG-003', file.relativePath, lineNum, trimmed);
          findings.push({
            id: 'VBG-LOG-003',
            title: 'Full environment configuration printed to application logs',
            category: 'Privacy',
            severity: 'HIGH',
            confidence: 'HIGH',
            description: 'Printing process.env or os.environ writes all active environment variables—including database passwords, secret keys, and tokens—to stdout/log collectors.',
            impact: 'Any developer, log aggregation provider, or CI observer with log access can view all environment secrets in plaintext.',
            file: file.relativePath,
            line: lineNum,
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: maskSnippet(trimmed),
              },
            ],
            remediation: 'Never log the full environment object. Log only non-sensitive diagnostic variables explicitly.',
            references: ['https://cwe.mitre.org/data/definitions/532.html'],
            fingerprint: fp,
          });
          continue;
        }

        // Rule 1: Logging sensitive credentials, tokens, or authorization headers (VBG-LOG-001)
        if (
          /(?:console\.(?:log|info|warn|error)|logger\.(?:info|debug|warn|error)|logging\.(?:info|debug|warning|error))\s*\([^)]*(?:token|password|passwd|authHeader|authorization|secretKey|apiKey|clientSecret)\b/i.test(
            trimmed
          )
        ) {
          // Avoid false-positive on static strings like "Token expired", "Invalid password"
          const isStaticStatusMessage = /['"][^'"]*(?:expired|invalid|failed|verified|accepted|required)['"]/i.test(
            trimmed
          ) && !/,\s*[a-zA-Z0-9_]*(?:token|password|auth|secret|key)/i.test(trimmed);

          if (!isStaticStatusMessage) {
            const fp = generateFingerprint('VBG-LOG-001', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-LOG-001',
              title: 'Sensitive credential or authorization token printed to logs',
              category: 'Privacy',
              severity: 'HIGH',
              confidence: 'HIGH',
              description: 'Sensitive variables (passwords, tokens, or authorization headers) are being output to logging statements.',
              impact: 'Plaintext tokens or passwords stored in application logs can be intercepted by unauthorized staff, third-party log ingestion services, or persisted in unencrypted log files.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Sanitize or mask sensitive fields prior to logging, or remove authentication tokens and credentials from log arguments.',
              references: ['https://cwe.mitre.org/data/definitions/532.html'],
              fingerprint: fp,
            });
          }
        }

        // Rule 2: Stack traces returned to clients (VBG-LOG-002)
        if (
          /(?:res\.status\(\d+\)\.json|NextResponse\.json|return\s+jsonify)\s*\([^)]*(?:err\.stack|error\.stack|traceback\.format_exc\(\)|stack:\s*err)/i.test(
            trimmed
          )
        ) {
          const fp = generateFingerprint('VBG-LOG-002', file.relativePath, lineNum, trimmed);
          findings.push({
            id: 'VBG-LOG-002',
            title: 'Internal runtime stack trace returned to API caller',
            category: 'Privacy',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            description: 'The API response returns an internal execution stack trace directly to the HTTP client.',
            impact: 'Stack traces disclose internal file paths, framework versions, database schema structures, and third-party dependency details that assist attackers in crafting exploits.',
            file: file.relativePath,
            line: lineNum,
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: maskSnippet(trimmed),
              },
            ],
            remediation: 'Log full stack traces internally to server error logs, and return generic, sanitized error messages (e.g. { error: "Internal Server Error" }) to clients.',
            references: ['https://cwe.mitre.org/data/definitions/209.html'],
            fingerprint: fp,
          });
        }
      }
    }

    return findings;
  }
}
