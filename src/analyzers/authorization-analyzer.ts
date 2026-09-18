import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class AuthorizationAnalyzer implements Analyzer {
  id = 'authorization-analyzer';
  name = 'Authorization & Access Control Analyzer';
  category = 'Authorization';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py']);

    for (const file of files) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        // 1. Detect Privilege Escalation via Client-Controlled Input
        // e.g. const { role } = req.body; if (role === "admin")
        if (/(req\.body|req\.query|req\.cookies|request\.json|request\.args)\.(role|isAdmin|permissions|group|tier)\b|const\s*\{\s*(role|isAdmin)\s*\}\s*=\s*req/i.test(line)) {
          const fingerprint = generateFingerprint('VBG-AUTHZ-001', file.relativePath, 'Authorization', line);
          findings.push({
            id: 'VBG-AUTHZ-001',
            title: 'Privilege Escalation via Client-Controlled Authorization State',
            category: 'Authorization',
            severity: 'HIGH',
            confidence: 'HIGH',
            description: 'Authorization decisions rely directly on user-controlled body/query parameter (e.g. role, isAdmin).',
            impact: 'An attacker can supply `{"role": "admin"}` in client requests to elevate privileges without server verification.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Derive role and permission scopes exclusively from trusted server-side identity sessions or verified JWT claims.',
            references: ['https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/'],
            fingerprint,
          });
        }

        // 2. Sensitive Route missing resource-level authorization (BOLA / IDOR)
        const isSensitiveRoute = /(app|router)\.(get|post|put|delete)\s*\(\s*['"`]\/(admin|users|orders|accounts|payments|files)\/:[a-zA-Z0-9_]+/i.test(line);
        if (isSensitiveRoute) {
          const contentSlice = file.lines.slice(i, i + 30).join('\n');
          const hasAuth = /auth|authenticate|verifyToken|isAuth|getSession|jwt/i.test(contentSlice);
          const hasOwnerCheck = /user\.id\s*===|ownerId|belongsToUser|checkOwnership|user_id\s*==/i.test(contentSlice);

          if (hasAuth && !hasOwnerCheck) {
            const fingerprint = generateFingerprint('VBG-AUTHZ-002', file.relativePath, 'Authorization', line);
            findings.push({
              id: 'VBG-AUTHZ-002',
              title: 'Potential Broken Object Level Authorization (BOLA / IDOR)',
              category: 'Authorization',
              severity: 'HIGH',
              confidence: 'MEDIUM',
              description: 'Sensitive resource route requires authentication but no explicit resource ownership or access check was detected.',
              impact: 'Authenticated users may access or manipulate target resources belonging to other users by changing the ID parameter.',
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: line.trim(),
                },
              ],
              file: file.relativePath,
              line: lineNum,
              remediation: 'Enforce resource ownership validation (e.g., verifying `resource.ownerId === currentUser.id`) in controller handler before returning target resource.',
              references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
              fingerprint,
            });
          }
        }
      }
    }

    return findings;
  }
}
