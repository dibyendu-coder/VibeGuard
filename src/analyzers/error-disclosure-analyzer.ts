import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class ErrorDisclosureAnalyzer implements Analyzer {
  id = 'error-disclosure-analyzer';
  name = 'Error Disclosure & Verbose Logging Analyzer';
  category = 'Reliability';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py']);

    for (const file of files) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        // 1. Returning stack trace to client response: e.g. res.status(500).json({ error: err.stack }) or res.send(err.stack)
        if (/(res|response)\.(json|send|status)\s*\(.*(err|error)\.(stack|message)/i.test(line)) {
          const fingerprint = generateFingerprint('VBG-ERR-001', file.relativePath, 'Reliability', line);
          findings.push({
            id: 'VBG-ERR-001',
            title: 'Internal Stack Trace / Exception Message Returned to Client',
            category: 'Reliability',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            description: 'HTTP response exposes internal exception message or stack trace directly to callers.',
            impact: 'Discloses backend framework details, file system paths, and internal variable names to potential attackers.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Log full stack traces internally on the server and return generic error responses (e.g. { error: "Internal server error" }) to clients in production.',
            references: ['https://owasp.org/www-community/Improper_Error_Handling'],
            fingerprint,
          });
        }
      }
    }

    return findings;
  }
}
