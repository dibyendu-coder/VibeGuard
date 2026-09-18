import path from 'path';
import { generateFingerprint } from '../core/fingerprint.js';
import { maskSnippet } from '../core/masker.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class DataExposureAnalyzer implements Analyzer {
  id = 'data-exposure-analyzer';
  name = 'Data Safety & Privacy Exposure Auditor';
  category = 'Data Safety';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.jsx', '.ts', '.tsx', '.py']);

    for (const file of files) {
      const isTestOrDoc =
        file.relativePath.includes('test') ||
        file.relativePath.includes('fixture') ||
        file.relativePath.includes('example');

      file.lines.forEach((lineText, idx) => {
        const lineNum = idx + 1;

        // 1. Sensitive Data Logged (e.g. console.log(password), logger.info(token), console.log(req.body))
        if (
          /(console\.(log|info|debug|error)|logger\.(info|debug|error))\s*\([^)]*\b(password|passwd|secret|jwt|token|bearer|api_key|credit_card|ssn|authorization)\b/i.test(
            lineText
          ) &&
          !isTestOrDoc
        ) {
          const ruleId = 'VBG-DAT-001';
          const maskedSnippet = maskSnippet(lineText.trim());
          findings.push({
            id: ruleId,
            rule_id: ruleId,
            title: 'Sensitive Credential / Data Logged to Output',
            category: 'Data Safety',
            subcategory: 'Data Exposure',
            analyzer: this.id,
            severity: 'HIGH',
            confidence: 'HIGH',
            description: 'Sensitive field (password, token, secret, or authorization header) is recorded via logging statements.',
            impact: 'Plaintext credentials captured in log sinks, CloudWatch, Datadog, or external log management SaaS.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: maskedSnippet,
                isSecretMasked: true,
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Redact or sanitize sensitive fields prior to logging or use automatic log redactor middleware.',
            references: ['https://cwe.mitre.org/data/definitions/532.html'],
            fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
            production_impact: 'Third-party log collectors store plaintext passwords/tokens accessible by unauthorized operators.',
          });
        }

        // 2. Sensitive Data in GET URL / Query Params
        if (
          /app\.get\s*\([^)]*\b(password|secret|token|api_key)\b/i.test(lineText) ||
          (/req\.query\.(password|token|secret|api_key)\b/i.test(lineText) &&
            !file.content.includes('req.body'))
        ) {
          const ruleId = 'VBG-DAT-002';
          findings.push({
            id: ruleId,
            rule_id: ruleId,
            title: 'Sensitive Data Transmitted via URL Query Parameter',
            category: 'Data Safety',
            subcategory: 'Data Exposure',
            analyzer: this.id,
            severity: 'HIGH',
            confidence: 'HIGH',
            description: 'Sensitive credential or secret parameter accepted in GET URL query parameters.',
            impact: 'URL query strings are routinely cached in browser history, proxy server logs, and Referer headers.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: lineText.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Transmit credentials via POST body parameters or HTTP authorization headers.',
            references: ['https://cwe.mitre.org/data/definitions/598.html'],
            fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
          });
        }

        // 3. Password or Private Hash Returned in API Response
        if (
          /res\.(json|send)\s*\([^)]*\b(password_hash|passwordHash|hashedPassword|secret_key|private_key)\b/i.test(
            lineText
          ) &&
          !isTestOrDoc
        ) {
          const ruleId = 'VBG-DAT-003';
          findings.push({
            id: ruleId,
            rule_id: ruleId,
            title: 'Internal Credential / Hash Returned in Response',
            category: 'Data Safety',
            subcategory: 'Data Exposure',
            analyzer: this.id,
            severity: 'CRITICAL',
            confidence: 'HIGH',
            description: 'API endpoint response payload includes internal password hashes or secret key fields.',
            impact: 'Exposes hashed user credentials or internal secret material directly to client-side callers.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: lineText.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Filter or strip password, hash, and secret fields before serializing response payloads.',
            references: ['https://cwe.mitre.org/data/definitions/200.html'],
            fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
            production_impact: 'Client users receive database password hashes allowing offline cracking attacks.',
          });
        }
      });
    }

    return findings;
  }
}
