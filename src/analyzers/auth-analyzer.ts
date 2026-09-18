import { generateFingerprint } from '../core/fingerprint.js';
import { maskSnippet } from '../core/masker.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class AuthAnalyzer implements Analyzer {
  id = 'auth-analyzer';
  name = 'Authentication & Authorization Analyzer';
  category = 'Authorization';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.ts', '.tsx', '.js', '.jsx', '.py']);

    for (const file of files) {
      const isClientComponent =
        file.content.includes("'use client'") ||
        file.content.includes('"use client"') ||
        file.relativePath.includes('components/') ||
        file.relativePath.endsWith('.tsx') ||
        file.relativePath.endsWith('.jsx');

      const isApiRoute =
        file.relativePath.includes('api/') ||
        file.relativePath.includes('routes/') ||
        file.relativePath.endsWith('route.ts') ||
        file.relativePath.endsWith('route.js');

      // Rule 1: Client-side only authorization check (VBG-AUTH-001)
      if (isClientComponent) {
        for (let i = 0; i < file.lines.length; i++) {
          const line = file.lines[i];
          const lineNum = i + 1;
          const trimmed = line.trim();

          if (
            /if\s*\(\s*(?:user\.(?:role|isAdmin)(?:\s*===?\s*['"][^'"]+['"])?|role\s*===?\s*['"][^'"]+['"]|isAdmin)\s*\)/i.test(trimmed) ||
            /(?:user\.(?:role|isAdmin)|role\s*===?\s*['"]admin['"]|isAdmin)\s*\?\s*(?:<|<[A-Z]|show|render)/i.test(
              trimmed
            )
          ) {
            const fp = generateFingerprint('VBG-AUTH-001', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-AUTH-001',
              title: 'Client-side-only authorization boundary detected',
              category: 'Authorization',
              severity: 'HIGH',
              confidence: 'HIGH',
              description:
                "Authorization checks evaluated solely in client-side code (e.g. if (user.role === 'admin')) only hide UI elements and do not protect underlying data or server endpoints.",
              impact:
                'Any attacker can manipulate client-side JavaScript state or send HTTP requests directly to backend endpoints, bypassing the client UI check completely.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation:
                'Enforce all authorization rules on the server side (in API route handlers, server actions, or database RLS policies). Never rely on client state for security boundaries.',
              references: ['https://cwe.mitre.org/data/definitions/602.html', 'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control'],
              fingerprint: fp,
            });
            break;
          }
        }
      }

      // Rule 2: Privileged admin route missing authorization middleware (VBG-AUTH-002)
      if (isApiRoute && (file.relativePath.includes('admin') || file.relativePath.includes('manage'))) {
        const hasAuthOrRoleCheck =
          /(?:admin|role|isAdmin|requireAdmin|authorize|authenticate|getSession|auth\(|session\?\.user)/i.test(
            file.content
          );

        if (!hasAuthOrRoleCheck) {
          const fp = generateFingerprint('VBG-AUTH-002', file.relativePath, 1, file.relativePath);
          findings.push({
            id: 'VBG-AUTH-002',
            title: 'Privileged admin endpoint missing server-side authorization check',
            category: 'Authorization',
            severity: 'HIGH',
            confidence: 'MEDIUM',
            description: `The API route path indicates a privileged admin operation (${file.relativePath}), but no server-side authorization check or role requirement was detected in the handler.`,
            impact: 'Unauthenticated or non-admin callers may trigger administrative functionality or access restricted data.',
            file: file.relativePath,
            line: 1,
            evidence: [
              {
                filePath: file.relativePath,
                line: 1,
                snippet: `Route file: ${file.relativePath}`,
              },
            ],
            remediation: 'Implement server-side role verification (e.g. check user.role === "admin") before executing any administrative logic.',
            references: ['https://cwe.mitre.org/data/definitions/285.html'],
            fingerprint: fp,
          });
        }
      }

      // Rule 3: Insecure JWT verification (VBG-AUTH-003)
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;
        const trimmed = line.trim();

        if (/jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*['"]none['"]/i.test(trimmed)) {
          const fp = generateFingerprint('VBG-AUTH-003', file.relativePath, lineNum, trimmed);
          findings.push({
            id: 'VBG-AUTH-003',
            title: "Insecure JWT verification with 'none' algorithm permitted",
            category: 'Authentication',
            severity: 'CRITICAL',
            confidence: 'HIGH',
            description: "JWT verification explicitly allows the 'none' algorithm, permitting tokens without cryptographic signatures.",
            impact: 'Attackers can forge arbitrary JWT tokens with any payload or role without providing a valid secret key.',
            file: file.relativePath,
            line: lineNum,
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: maskSnippet(trimmed),
              },
            ],
            remediation: "Require strong asymmetric (RS256) or symmetric (HS256) algorithms and disallow algorithm: 'none'.",
            references: ['https://cwe.mitre.org/data/definitions/347.html'],
            fingerprint: fp,
          });
        }

        if (/jwt\.decode\s*\([^)]*\)/i.test(trimmed) && !/jwt\.verify/i.test(file.content)) {
          const fp = generateFingerprint('VBG-AUTH-003', file.relativePath, lineNum, trimmed);
          findings.push({
            id: 'VBG-AUTH-003',
            title: 'JWT payload decoded without cryptographic verification',
            category: 'Authentication',
            severity: 'HIGH',
            confidence: 'MEDIUM',
            description: 'jwt.decode() is used without calling jwt.verify() to validate the token signature.',
            impact: 'jwt.decode merely parses base64 claims without verifying the signature, allowing unauthenticated token tampering.',
            file: file.relativePath,
            line: lineNum,
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: maskSnippet(trimmed),
              },
            ],
            remediation: 'Always verify JWT tokens with a secret or public key using jwt.verify() before trusting claims.',
            references: ['https://cwe.mitre.org/data/definitions/345.html'],
            fingerprint: fp,
          });
        }
      }
    }

    return findings;
  }
}
