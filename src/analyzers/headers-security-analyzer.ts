import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class HeadersSecurityAnalyzer implements Analyzer {
  id = 'headers-security-analyzer';
  name = 'Security Headers Analyzer';
  category = 'Configuration';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check config / server files
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', 'next.config.js', 'next.config.mjs']);
    let hasHelmetOrHeaders = false;
    let mainServerFile: any = null;

    for (const file of files) {
      if (file.relativePath.includes('next.config') || file.relativePath.includes('server') || file.relativePath.includes('app')) {
        if (!mainServerFile) mainServerFile = file;
        if (/helmet\s*\(|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security/i.test(file.content)) {
          hasHelmetOrHeaders = true;
          break;
        }
      }
    }

    if (!hasHelmetOrHeaders && mainServerFile) {
      const fingerprint = generateFingerprint('VBG-HDR-001', mainServerFile.relativePath, 'Configuration', 'security-headers');
      findings.push({
        id: 'VBG-HDR-001',
        title: 'Missing Essential Security Headers Configuration',
        category: 'Configuration',
        severity: 'LOW',
        confidence: 'MEDIUM',
        description: 'Web application does not explicitly set security headers (Content-Security-Policy, X-Frame-Options, HSTS, X-Content-Type-Options).',
        impact: 'Increases susceptibility to clickjacking, MIME-sniffing, and downgrade attacks.',
        evidence: [
          {
            filePath: mainServerFile.relativePath,
            line: 1,
            snippet: 'No HTTP security header middleware (e.g. Helmet) detected in server configuration.',
          },
        ],
        file: mainServerFile.relativePath,
        line: 1,
        remediation: 'Use Helmet middleware (Express) or configure headers in next.config.js to enforce CSP, HSTS, X-Frame-Options, and X-Content-Type-Options.',
        references: ['https://owasp.org/www-project-secure-headers/'],
        fingerprint,
      });
    }

    return findings;
  }
}
