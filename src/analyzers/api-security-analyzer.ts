import { generateFingerprint } from '../core/fingerprint.js';
import { maskSnippet } from '../core/masker.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class ApiSecurityAnalyzer implements Analyzer {
  id = 'api-security-analyzer';
  name = 'API Security Heuristics Analyzer';
  category = 'API';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py']);

    for (const file of files) {
      const isApiRoute =
        file.relativePath.includes('api/') ||
        file.relativePath.includes('routes/') ||
        file.relativePath.includes('controllers/') ||
        file.relativePath.endsWith('route.ts') ||
        file.relativePath.endsWith('route.js') ||
        file.relativePath.includes('views.py');

      const fileText = file.content;
      // Strip comments so explanatory text does not trigger or suppress heuristics
      const codeWithoutComments = fileText.replace(/\/\/.*|\/\*[\s\S]*?\*\//g, '');

      // Rule 1: API route accessing user-controlled ID without ownership/auth check (VBG-API-001)
      if (
        isApiRoute &&
        (file.relativePath.includes('[') ||
          file.relativePath.includes(':id') ||
          /req\.params\.(?:id|userId|orderId|accountId)/.test(codeWithoutComments) ||
          /params\.(?:id|userId|orderId|accountId)/.test(codeWithoutComments))
      ) {
        // Look for common mutations or fetches: findUnique, findById, delete, update, SELECT
        const accessesResource = /(?:findById|findUnique|delete|update|remove|select|query|db\.)/i.test(
          codeWithoutComments
        );
        // Look for actual authorization check in code
        const hasAuthCheck = /(?:session\b|auth\(|jwt\b|authorize\b|authenticate\b|permission\b|isOwner\b|requireAuth\b|getServerSession\b|currentUser\b|role\s*===)/i.test(
          codeWithoutComments
        );

        if (accessesResource && !hasAuthCheck) {
          // Find first line referencing id/params
          let targetLine = 1;
          for (let i = 0; i < file.lines.length; i++) {
            if (/params|req\.params|\[id\]/.test(file.lines[i])) {
              targetLine = i + 1;
              break;
            }
          }
          const snippet = file.lines[targetLine - 1]?.trim() || file.relativePath;
          const fp = generateFingerprint('VBG-API-001', file.relativePath, targetLine, snippet);

          findings.push({
            id: 'VBG-API-001',
            title: 'Potential missing resource authorization in parameterized route',
            category: 'API',
            severity: 'HIGH',
            confidence: 'MEDIUM',
            description: `The route accesses a database resource using a user-controlled identifier, but no ownership check or authorization guard was detected in the analyzed code path.`,
            impact: 'Any authenticated or unauthenticated caller can modify or exfiltrate another tenant or user\'s data simply by guessing or iterating identifiers (IDOR / BOLA).',
            file: file.relativePath,
            line: targetLine,
            evidence: [
              {
                filePath: file.relativePath,
                line: targetLine,
                snippet: maskSnippet(snippet),
              },
            ],
            remediation: 'Verify that the authenticated caller has explicit ownership or tenancy rights to access the requested resource ID before querying or mutating.',
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
            fingerprint: fp,
          });
        }
      }

      // Check per-line heuristics
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('#')) continue;

        // Rule 2: Unrestricted file operations / path traversal (VBG-API-002)
        if (
          /(?:fs\.readFile|fs\.readFileSync|res\.sendFile|open)\s*\([^)]*(?:req\.query|req\.params|request\.args|params\.)/i.test(
            line
          )
        ) {
          const fp = generateFingerprint('VBG-API-002', file.relativePath, lineNum, trimmed);
          findings.push({
            id: 'VBG-API-002',
            title: 'Unrestricted file operation with user-controlled path parameter',
            category: 'API',
            severity: 'HIGH',
            confidence: 'HIGH',
            description: 'Directly passing user-controlled parameters into filesystem read operations allows directory traversal.',
            impact: 'Attackers can read sensitive server files, configuration files (.env), or private source code by supplying paths with ../ sequences.',
            file: file.relativePath,
            line: lineNum,
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: maskSnippet(trimmed),
              },
            ],
            remediation: 'Sanitize paths using a strict allowlist or path validation that ensures the resolved path remains strictly within an intended root directory.',
            references: ['https://cwe.mitre.org/data/definitions/22.html'],
            fingerprint: fp,
          });
        }

        // Rule 3: Unsafe open redirect (VBG-API-003)
        if (
          /(?:res\.redirect|redirect)\s*\([^)]*(?:req\.query|req\.body|request\.args\.get|request\.GET)/i.test(
            line
          )
        ) {
          const fp = generateFingerprint('VBG-API-003', file.relativePath, lineNum, trimmed);
          findings.push({
            id: 'VBG-API-003',
            title: 'Potential open redirect using untrusted user input',
            category: 'API',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            description: 'HTTP redirection destination is constructed directly from request query parameters without domain validation.',
            impact: 'Attackers can exploit open redirects to orchestrate phishing attacks using trusted domains to lure users to malicious sites.',
            file: file.relativePath,
            line: lineNum,
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: maskSnippet(trimmed),
              },
            ],
            remediation: 'Validate redirect URLs against a whitelist of approved domains or restrict redirection strictly to relative internal paths.',
            references: ['https://cwe.mitre.org/data/definitions/601.html'],
            fingerprint: fp,
          });
        }

        // Rule 4: Overly permissive CORS (VBG-API-004)
        if (
          /cors\(\s*\{\s*origin\s*:\s*['"]\*['"]/i.test(line) ||
          /res\.setHeader\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]\s*\)/i.test(line) ||
          /add_middleware\(CORSMiddleware[^)]*allow_origins=\[[^\]]*['"]\*['"]/i.test(line)
        ) {
          const fp = generateFingerprint('VBG-API-004', file.relativePath, lineNum, trimmed);
          findings.push({
            id: 'VBG-API-004',
            title: 'Wildcard CORS origin configured on API endpoint',
            category: 'API',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            description: "CORS configuration allows arbitrary origins ('*') to make cross-origin requests to this endpoint.",
            impact: 'Wildcard origins allow arbitrary malicious third-party websites to query your API from a victim user\'s browser.',
            file: file.relativePath,
            line: lineNum,
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: maskSnippet(trimmed),
              },
            ],
            remediation: 'Specify explicit trusted domain origins instead of using wildcard * in CORS headers.',
            references: ['https://cwe.mitre.org/data/definitions/942.html'],
            fingerprint: fp,
          });
        }

        // Rule 5: Sensitive information leakage in API response (VBG-API-005)
        if (
          /(?:res\.json|NextResponse\.json|return\s+jsonify)\s*\([^)]*(?:password_hash|passwordHash|hashedPassword|secret_key|accessToken)/i.test(
            line
          )
        ) {
          const fp = generateFingerprint('VBG-API-005', file.relativePath, lineNum, trimmed);
          findings.push({
            id: 'VBG-API-005',
            title: 'Sensitive user credential fields returned in API response',
            category: 'API',
            severity: 'HIGH',
            confidence: 'MEDIUM',
            description: 'API response serializes sensitive credential fields (password hash, secret key, or token) to the client.',
            impact: 'Exposing password hashes or internal keys to clients enables offline cracking or account takeover.',
            file: file.relativePath,
            line: lineNum,
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: maskSnippet(trimmed),
              },
            ],
            remediation: 'Strip sensitive attributes from user objects before returning them in API responses (e.g. use select or omit password fields).',
            references: ['https://cwe.mitre.org/data/definitions/200.html'],
            fingerprint: fp,
          });
        }
      }
    }

    return findings;
  }
}
