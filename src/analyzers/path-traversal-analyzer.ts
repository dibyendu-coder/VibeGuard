import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class PathTraversalAnalyzer implements Analyzer {
  id = 'path-traversal-analyzer';
  name = 'Path Traversal Analyzer';
  category = 'Security';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py']);

    for (const file of files) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        const isFsOp = /fs\.(readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|createReadStream|createWriteStream)|open\s*\(/i.test(
          line
        );
        if (!isFsOp) continue;

        const hasUserInput = /req\.(query|params|body|headers|cookies)|searchParams|params\.|request\.(args|form|json|headers|cookies)/i.test(
          line
        );

        if (hasUserInput) {
          const fingerprint = generateFingerprint('VBG-PATH-001', file.relativePath, 'Security', line);

          findings.push({
            id: 'VBG-PATH-001',
            title: 'Potential Path Traversal / Arbitrary File Access',
            category: 'Security',
            severity: 'HIGH',
            confidence: 'HIGH',
            description: 'Untrusted user input flows directly into a filesystem access operation.',
            impact: 'Attackers can use directory traversal sequences (`../` or `..\\`) to access or overwrite sensitive system files.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Sanitize file paths using path.basename, path.resolve with a strict base directory whitelist, or disallow parent relative paths.',
            references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
            fingerprint,
          });
        }
      }
    }

    return findings;
  }
}
