import { generateFingerprint } from '../core/fingerprint.js';
import { maskSecret, maskSnippet } from '../core/masker.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

interface SecretPattern {
  ruleId: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH';
  confidence: 'HIGH' | 'MEDIUM';
  category: 'Secrets';
  regex: RegExp;
  description: string;
  impact: string;
  remediation: string;
  references: string[];
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    ruleId: 'VBG-SECRET-001',
    title: 'Hardcoded credential or API key detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    category: 'Secrets',
    // Matches OpenAI, Anthropic, Stripe, AWS, GitHub, Slack, Google, SendGrid, VibeGuard mock keys
    regex: /(?:vbg_test_[0-9a-zA-Z_\-]{20,}|sk_live_[0-9a-zA-Z]{20,}|sk_test_[0-9a-zA-Z]{20,}|sk-ant-[0-9a-zA-Z_\-]{20,}|sk-[0-9a-zA-Z]{20,}|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|xoxb-[0-9]{10,}-[0-9a-zA-Z]{20,}|AIza[0-9A-Za-z\\-_]{35}|SG\.[a-zA-Z0-9_\-]{20,})/g,
    description: 'A live third-party API key or cloud credential was detected in the project source.',
    impact: 'Attackers who gain read access to the repository or client bundle can impersonate your services, drain accounts, or access private tenant data.',
    remediation: 'Immediately rotate the exposed secret. Move credentials into server-only environment variables and reference them securely via runtime config.',
    references: ['https://cwe.mitre.org/data/definitions/798.html', 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'],
  },
  {
    ruleId: 'VBG-SECRET-002',
    title: 'Private cryptographic key committed to codebase',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    category: 'Secrets',
    regex: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
    description: 'A private cryptographic key header was identified in the analyzed file.',
    impact: 'Exposed private keys compromise TLS, token signing, SSH access, and asymmetric encryption.',
    remediation: 'Revoke the compromised key immediately. Use a secret manager (AWS Secrets Manager, Vault, GCP Secret Manager) to load private keys securely at runtime.',
    references: ['https://cwe.mitre.org/data/definitions/321.html'],
  },
  {
    ruleId: 'VBG-SECRET-003',
    title: 'Database connection string containing embedded credentials',
    severity: 'HIGH',
    confidence: 'HIGH',
    category: 'Secrets',
    regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[a-zA-Z0-9_\-\.%]+:[^@\s'"]+@[a-zA-Z0-9_\-\.:]+\/[a-zA-Z0-9_\-\.%]+/g,
    description: 'A database connection URI with hardcoded username and password was found in the codebase.',
    impact: 'Direct access to production or staging databases could lead to data exfiltration, ransomware, or destruction of persistent stores.',
    remediation: 'Store database credentials in environment variables (e.g. DATABASE_URL) supplied at deployment time. Never commit connection strings with passwords.',
    references: ['https://cwe.mitre.org/data/definitions/256.html'],
  },
  {
    ruleId: 'VBG-SECRET-004',
    title: 'Hardcoded authentication secret or password in source code',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'Secrets',
    regex: /(?:const|let|var)\s+(?:NEXTAUTH_SECRET|JWT_SECRET|AUTH_SECRET|SESSION_SECRET)\s*=\s*['"]([a-zA-Z0-9_\-!@#$%^&*]{8,})['"]/g,
    description: 'An authentication or session signing secret is hardcoded directly into the application code.',
    impact: 'Hardcoded signing secrets allow attackers to forge session cookies or JWT tokens to authenticate as any user or admin.',
    remediation: 'Read auth secrets from process.env at runtime. Ensure a strong random secret is generated per environment.',
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
  },
  {
    ruleId: 'VBG-SECRET-005',
    title: 'Sensitive secret exposed via client-accessible framework prefix',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    category: 'Secrets',
    regex: /(?:NEXT_PUBLIC_|VITE_|REACT_APP_)(?:[A-Z0-9_]*(?:SECRET|PRIVATE|KEY|TOKEN|PASSWORD)[A-Z0-9_]*)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{8,})['"]?/g,
    description: 'A sensitive secret is prefixed with a client framework exposure tag (e.g. NEXT_PUBLIC_, VITE_, REACT_APP_) that bakes the value into client bundles.',
    impact: 'Framework conventions automatically bundle these environment variables into public client-side JavaScript, exposing the secret to all website visitors.',
    remediation: 'Remove the client-side prefix (e.g. NEXT_PUBLIC_) for secrets. Secrets must only be accessed in server-side functions or API routes.',
    references: ['https://nextjs.org/docs/pages/building-your-application/configuring/environment-variables#bundling-environment-variables-for-the-browser'],
  },
];

export class SecretAnalyzer implements Analyzer {
  id = 'secret-analyzer';
  name = 'Secret Detection Analyzer';
  category = 'Secrets';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context);

    for (const file of files) {
      // Avoid flagging test mock files if they explicitly say fake/dummy
      const isTestFile = file.relativePath.includes('test') || file.relativePath.includes('spec');

      for (let lineIdx = 0; lineIdx < file.lines.length; lineIdx++) {
        const lineContent = file.lines[lineIdx];
        const lineNum = lineIdx + 1;

        for (const pattern of SECRET_PATTERNS) {
          // Reset regex state for global regex
          pattern.regex.lastIndex = 0;
          let match: RegExpExecArray | null;

          while ((match = pattern.regex.exec(lineContent)) !== null) {
            const rawMatched = match[0];

            // False-positive reduction: ignore obvious placeholders
            if (
              rawMatched.includes('your_') ||
              rawMatched.includes('example') ||
              rawMatched.includes('placeholder') ||
              rawMatched.includes('xxx') ||
              rawMatched.includes('TODO') ||
              rawMatched.includes('dummy') ||
              (isTestFile && rawMatched.includes('test-key'))
            ) {
              continue;
            }

            const maskedSnippet = maskSnippet(lineContent.trim());
            const maskedSecretVal = maskSecret(match[1] || rawMatched);
            const fingerprint = generateFingerprint(pattern.ruleId, file.relativePath, lineNum, maskedSnippet);

            findings.push({
              id: pattern.ruleId,
              title: pattern.title,
              category: pattern.category,
              severity: pattern.severity,
              confidence: pattern.confidence,
              description: pattern.description,
              impact: pattern.impact,
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  column: match.index + 1,
                  snippet: `${maskedSnippet} (Value: ${maskedSecretVal})`,
                  isSecretMasked: true,
                },
              ],
              remediation: pattern.remediation,
              references: pattern.references,
              fingerprint,
            });
            break; // Move to next line for this pattern
          }
        }
      }
    }

    return findings;
  }
}
