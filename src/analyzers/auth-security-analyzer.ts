import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class AuthSecurityAnalyzer implements Analyzer {
  id = 'auth-security-analyzer';
  name = 'Authentication Deep Security Analyzer';
  category = 'Authentication';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py']);

    for (const file of files) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        // 1. Plaintext Password Handling or MD5 / SHA1 Hashing for Passwords
        if (/password\s*=\s*(req\.body|request\.(form|json))\.(password|pass)/i.test(line) && !/bcrypt|argon2|scrypt|hashPassword|pbkdf2/i.test(file.content)) {
          const fingerprint = generateFingerprint('VBG-AUTH-004', file.relativePath, 'Authentication', line);
          findings.push({
            id: 'VBG-AUTH-004',
            title: 'Potential Plaintext or Unsalted Password Storage',
            category: 'Authentication',
            severity: 'HIGH',
            confidence: 'HIGH',
            description: 'Password value from input stored or processed without salt/strong password hashing algorithm.',
            impact: 'Database compromise directly exposes user credentials in plaintext or easily crackable form.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Use bcrypt, Argon2id, or scrypt with adequate work factor for hashing user passwords before storage.',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
            fingerprint,
          });
        }

        // 2. JWT Signing without expiration
        if (/jwt\.sign\s*\(/i.test(line) && !/expiresIn|exp/i.test(line) && !/expiresIn|exp/i.test(file.lines.slice(i, i + 10).join(' '))) {
          const fingerprint = generateFingerprint('VBG-AUTH-005', file.relativePath, 'Authentication', line);
          findings.push({
            id: 'VBG-AUTH-005',
            title: 'JWT Token Created Without Expiration (expiresIn missing)',
            category: 'Authentication',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            description: 'JWT token signing does not specify an expiration time (expiresIn).',
            impact: 'Tokens remain valid indefinitely if stolen or intercepted, extending the window of unauthorized access.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Always set a short expiration time (e.g. expiresIn: "15m" or "1h") when signing JWT tokens.',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'],
            fingerprint,
          });
        }

        // 3. Insecure Cookie Settings for Authentication
        if (/res\.cookie\s*\([^)]*/i.test(line) && (/httpOnly\s*:\s*false/i.test(line) || (!line.includes('httpOnly') && !file.content.includes('httpOnly')))) {
          const fingerprint = generateFingerprint('VBG-AUTH-006', file.relativePath, 'Authentication', line);
          findings.push({
            id: 'VBG-AUTH-006',
            title: 'Insecure Cookie Configuration (Missing httpOnly flag)',
            category: 'Authentication',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            description: 'Cookie set without httpOnly: true flag.',
            impact: 'Cookies accessible to client-side scripts can be stolen by attackers via Cross-Site Scripting (XSS).',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Set httpOnly: true, secure: true, and sameSite: "strict" or "lax" on all authentication cookies.',
            references: ['https://owasp.org/www-community/HttpOnly'],
            fingerprint,
          });
        }
      }
    }

    return findings;
  }
}
