import fs from 'fs';
import path from 'path';
import { generateFingerprint } from '../core/fingerprint.js';
import { maskSnippet } from '../core/masker.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class ConfigAnalyzer implements Analyzer {
  id = 'config-analyzer';
  name = 'Environment & Configuration Analyzer';
  category = 'Configuration';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { manifest, projectRoot } = context;

    // Rule 1: Committed .env files (VBG-CONFIG-001)
    for (const envFile of manifest.envFiles) {
      if (envFile === '.env.example' || envFile === '.env.sample' || envFile === '.env.template') {
        continue;
      }
      const isProductionEnv = envFile.includes('prod') || envFile.includes('production');
      const severity = isProductionEnv ? 'CRITICAL' : 'HIGH';
      const fp = generateFingerprint('VBG-CONFIG-001', envFile, 1, envFile);

      findings.push({
        id: 'VBG-CONFIG-001',
        title: `Committed environment file (${envFile}) detected`,
        category: 'Configuration',
        severity,
        confidence: 'HIGH',
        description: `An environment configuration file '${envFile}' is present in the repository root. Environment files often contain sensitive secrets or environment-specific configs and should never be committed.`,
        impact: 'Exposing configuration files in version control risks credential leakage and unauthorized access when the repository is shared or breached.',
        file: envFile,
        line: 1,
        evidence: [
          {
            filePath: envFile,
            line: 1,
            snippet: `Tracked environment file: ${envFile}`,
          },
        ],
        remediation: `Add '${envFile}' to your .gitignore file and purge it from git history using 'git rm --cached ${envFile}'. Use .env.example as a sanitized template.`,
        references: ['https://12factor.net/config'],
        fingerprint: fp,
      });
    }

    // Scan config files and production settings
    const files = getScanFiles(context);

    for (const file of files) {
      const isConfigFile =
        file.relativePath.includes('config') ||
        file.relativePath.includes('settings') ||
        file.relativePath.endsWith('.env') ||
        file.relativePath.includes('.env.');

      const isProductionConfig =
        file.relativePath.includes('prod') ||
        file.relativePath.includes('production') ||
        file.filePath.includes('prod') ||
        file.filePath.includes('production') ||
        file.relativePath.includes('docker-compose.prod');

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;
        const trimmed = line.trim();

        // Rule 2: Localhost URL in production-like configuration (VBG-CONFIG-002)
        if (isProductionConfig && /(?:https?:\/\/)?(?:localhost|127\.0\.0\.1)(?::\d+)?/i.test(line)) {
          if (!trimmed.startsWith('#') && !trimmed.startsWith('//')) {
            const fp = generateFingerprint('VBG-CONFIG-002', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CONFIG-002',
              title: 'Development localhost URL configured in production configuration',
              category: 'Configuration',
              severity: 'HIGH',
              confidence: 'HIGH',
              description: 'A localhost or loopback (127.0.0.1) address was detected in a production configuration file.',
              impact: 'If deployed to production, client requests, webhooks, or internal services calling localhost will fail or attempt to reach unintended local ports.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Replace localhost addresses with environment variable references (e.g. process.env.API_URL) that resolve to your live domain in production.',
              references: ['https://cwe.mitre.org/data/definitions/1188.html'],
              fingerprint: fp,
            });
          }
        }

        // Rule 3: Debug mode enabled (VBG-CONFIG-003)
        if (isConfigFile || isProductionConfig || file.relativePath.endsWith('.py')) {
          if (
            /(?:^|\s)(?:DEBUG|debug)\s*=\s*(?:True|true|1)\b/.test(trimmed) ||
            /["']debug["']\s*:\s*true\b/.test(trimmed)
          ) {
            if (!trimmed.startsWith('#') && !trimmed.startsWith('//') && !file.relativePath.includes('test')) {
              const fp = generateFingerprint('VBG-CONFIG-003', file.relativePath, lineNum, trimmed);
              findings.push({
                id: 'VBG-CONFIG-003',
                title: 'Debug mode enabled in application configuration',
                category: 'Configuration',
                severity: isProductionConfig ? 'HIGH' : 'MEDIUM',
                confidence: 'MEDIUM',
                description: 'Debug mode appears to be explicitly enabled in configuration.',
                impact: 'When debug mode is active in production, frameworks often display detailed interactive debuggers, stack traces, and environment variables to any user.',
                file: file.relativePath,
                line: lineNum,
                evidence: [
                  {
                    filePath: file.relativePath,
                    line: lineNum,
                    snippet: maskSnippet(trimmed),
                  },
                ],
                remediation: 'Ensure debug mode is dynamically loaded from an environment variable (e.g., DEBUG=False or NODE_ENV=production) and strictly disabled in production.',
                references: ['https://cwe.mitre.org/data/definitions/215.html', 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'],
                fingerprint: fp,
              });
            }
          }
        }

        // Rule 4: Client-exposed environment variable with sensitive name (VBG-CONFIG-004)
        if (/(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SECRET|PRIVATE|ADMIN|TOKEN|AUTH_KEY)[A-Z0-9_]*/i.test(line)) {
          // Avoid false-positive if variable explicitly includes PUBLISHABLE, ANON, or PUBLIC (which are expected)
          if (!/PUBLISHABLE|ANON|PUBLIC_KEY/i.test(line)) {
            const fp = generateFingerprint('VBG-CONFIG-004', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CONFIG-004',
              title: 'Client-exposed environment variable contains sensitive identifier',
              category: 'Configuration',
              severity: 'HIGH',
              confidence: 'HIGH',
              description: 'An environment variable exposed to client browsers (via NEXT_PUBLIC_, VITE_, or REACT_APP_) includes sensitive keywords like SECRET, PRIVATE, ADMIN, or TOKEN in its name.',
              impact: 'Variables with client prefixes are compiled into browser assets. Secrets placed in these variables are completely visible to client users.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Keep server-side secrets in variables without client prefixes (e.g. STRIPE_SECRET_KEY, not NEXT_PUBLIC_STRIPE_SECRET_KEY).',
              references: ['https://nextjs.org/docs/pages/building-your-application/configuring/environment-variables'],
              fingerprint: fp,
            });
          }
        }

        // Rule 6: Insecure Cookie Flags (VBG-CONFIG-006)
        if (
          /httpOnly\s*:\s*false/i.test(trimmed) ||
          /secure\s*:\s*false/i.test(trimmed) ||
          /sameSite\s*:\s*['"]none['"]/i.test(trimmed)
        ) {
          const fp = generateFingerprint('VBG-CONFIG-006', file.relativePath, lineNum, trimmed);
          findings.push({
            id: 'VBG-CONFIG-006',
            title: 'Insecure Cookie Security Flags Configured',
            category: 'Configuration',
            subcategory: 'Cookie Security',
            analyzer: this.id,
            severity: 'MEDIUM',
            confidence: 'HIGH',
            description: 'Cookie set with insecure options (httpOnly: false, secure: false, or sameSite: "none").',
            impact: 'Session cookies exposed to client-side XSS stealing or cross-site request forgery (CSRF) interception.',
            file: file.relativePath,
            line: lineNum,
            evidence: [{ filePath: file.relativePath, line: lineNum, snippet: maskSnippet(trimmed) }],
            remediation: 'Configure cookies with httpOnly: true, secure: true, and sameSite: "lax" or "strict".',
            references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
            fingerprint: fp,
          });
        }
      }
    }

    // Rule 5: Missing required environment configuration from .env.example (VBG-CONFIG-005)
    // Rule 7: Code environment variable references missing from .env.example (VBG-CONFIG-007)
    const envExamplePath = path.join(projectRoot, '.env.example');
    if (fs.existsSync(envExamplePath)) {
      try {
        const exampleContent = fs.readFileSync(envExamplePath, 'utf-8');
        const exampleVars = new Set(
          exampleContent
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter((l) => l && !l.startsWith('#'))
            .map((l) => l.split('=')[0].trim())
        );

        // Scan code for process.env.VAR references
        const missingFromExample: Set<string> = new Set();
        const codeFiles = files.filter((f) => !f.relativePath.includes('test') && !f.relativePath.includes('.env'));
        
        for (const f of codeFiles) {
          const matches = f.content.matchAll(/process\.env\.([A-Z0-9_]+)/g);
          for (const match of matches) {
            const varName = match[1];
            if (
              !['NODE_ENV', 'PORT', 'HOST', 'TZ', 'PATH', 'PWD'].includes(varName) &&
              !exampleVars.has(varName)
            ) {
              missingFromExample.add(varName);
            }
          }
        }

        if (missingFromExample.size > 0) {
          const missingArr = Array.from(missingFromExample);
          const fp = generateFingerprint('VBG-CONFIG-007', '.env.example', 1, missingArr.join(','));
          findings.push({
            id: 'VBG-CONFIG-007',
            title: 'Environment Variables Referenced in Code Missing from .env.example',
            category: 'Configuration',
            subcategory: 'Documentation',
            analyzer: this.id,
            severity: 'INFO',
            confidence: 'MEDIUM',
            description: `Application source code references environment variables (${missingArr.slice(0, 3).join(', ')}) that are not documented in .env.example.`,
            impact: 'New developers or automated deployment scripts may fail to populate required environment settings.',
            file: '.env.example',
            line: 1,
            evidence: [{ filePath: '.env.example', line: 1, snippet: `Undocumented env vars: ${missingArr.join(', ')}` }],
            remediation: 'Add placeholder definitions for all referenced environment variables into .env.example.',
            references: ['https://12factor.net/config'],
            fingerprint: fp,
          });
        }

        // Check active .env or .env.local
        const activeEnv = manifest.envFiles.find((f) => f === '.env' || f === '.env.local');
        if (activeEnv) {
          const activePath = path.join(projectRoot, activeEnv);
          const activeContent = fs.readFileSync(activePath, 'utf-8');
          const missingVars = Array.from(exampleVars).filter(
            (v) => !activeContent.includes(`${v}=`)
          );

          if (missingVars.length > 0) {
            const fp = generateFingerprint('VBG-CONFIG-005', activeEnv, 1, missingVars.join(','));
            findings.push({
              id: 'VBG-CONFIG-005',
              title: `Missing required environment variables declared in .env.example`,
              category: 'Configuration',
              severity: 'LOW',
              confidence: 'MEDIUM',
              description: `.env.example specifies environment variables (${missingVars.slice(0, 3).join(', ')}${missingVars.length > 3 ? '...' : ''}) that are missing from ${activeEnv}.`,
              impact: 'The application may encounter unhandled runtime errors or crashes during startup when attempting to read undefined configuration.',
              file: activeEnv,
              line: 1,
              evidence: [
                {
                  filePath: activeEnv,
                  line: 1,
                  snippet: `Missing variables: ${missingVars.join(', ')}`,
                },
              ],
              remediation: `Define the missing variables (${missingVars.join(', ')}) in your active environment file.`,
              references: ['https://12factor.net/config'],
              fingerprint: fp,
            });
          }
        }
      } catch {
        // Ignore .env.example read error
      }
    }

    return findings;
  }
}
