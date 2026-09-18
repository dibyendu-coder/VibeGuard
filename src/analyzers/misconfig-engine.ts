import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class MisconfigEngine implements Analyzer {
  id = 'misconfig-engine';
  name = 'Security Misconfiguration Engine';
  category = 'Configuration';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.env', '.env.local', '.env.development', '.js', '.ts', '.py', '.json', '.yml', '.yaml']);

    const rootCauseSeen = new Set<string>();

    for (const file of files) {
      // 1. Committed .env file containing credentials
      if (file.relativePath.match(/^\.env(\.(local|prod|production))?$/) && !rootCauseSeen.has('committed-env')) {
        rootCauseSeen.add('committed-env');
        const fingerprint = generateFingerprint('VBG-CFG-001', file.relativePath, 'Configuration', 'committed-env');
        findings.push({
          id: 'VBG-CFG-001',
          title: 'Committed Environment File (.env)',
          category: 'Configuration',
          severity: 'HIGH',
          confidence: 'HIGH',
          description: `Environment configuration file '${file.relativePath}' is committed into repository root.`,
          impact: 'Exposes secrets, API keys, or database credentials to version control history and unauthorized repository access.',
          evidence: [
            {
              filePath: file.relativePath,
              line: 1,
              snippet: `File path: ${file.relativePath}`,
            },
          ],
          file: file.relativePath,
          line: 1,
          remediation: 'Add .env files to .gitignore and use example templates (.env.example) without real secrets.',
          references: ['https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/'],
          fingerprint,
        });
      }

      // 2. Debug or Development Mode Enabled
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        if (/(DEBUG|NODE_ENV|FLASK_DEBUG|APP_DEBUG)\s*[:=]\s*['"]?(true|1|development|dev)['"]?/i.test(line) && !rootCauseSeen.has(`debug-enabled:${file.relativePath}`)) {
          rootCauseSeen.add(`debug-enabled:${file.relativePath}`);
          const fingerprint = generateFingerprint('VBG-CFG-002', file.relativePath, 'Configuration', line);
          findings.push({
            id: 'VBG-CFG-002',
            title: 'Debug Mode or Development Environment Enabled',
            category: 'Configuration',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            description: 'Application or framework configured with debug mode enabled.',
            impact: 'Enabling debug mode in production exposes detailed error stack traces, internal state, or interactive debug consoles.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Ensure DEBUG=false and NODE_ENV=production in production deployment environments.',
            references: ['https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/'],
            fingerprint,
          });
        }

        // 3. Localhost Production Endpoint Hardcoded
        if (/(api_url|backend_url|host)\s*[:=]\s*['"]https?:\/\/localhost:\d+/i.test(line) && !rootCauseSeen.has(`localhost-endpoint:${file.relativePath}`)) {
          rootCauseSeen.add(`localhost-endpoint:${file.relativePath}`);
          const fingerprint = generateFingerprint('VBG-CFG-003', file.relativePath, 'Configuration', line);
          findings.push({
            id: 'VBG-CFG-003',
            title: 'Hardcoded Localhost Endpoint in Configuration',
            category: 'Configuration',
            severity: 'LOW',
            confidence: 'MEDIUM',
            description: 'Configuration sets endpoint URL to http://localhost.',
            impact: 'Production deployments pointing to localhost will fail to reach remote backend services or expose local loopback services.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Use environment variables for service URL endpoints.',
            references: ['https://12factor.net/config'],
            fingerprint,
          });
        }
      }
    }

    return findings;
  }
}
