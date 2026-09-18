import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class SqlInjectionAnalyzer implements Analyzer {
  id = 'sql-injection-analyzer';
  name = 'SQL Injection Analyzer';
  category = 'Database';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py']);

    for (const file of files) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        // Check for SQL query context
        const isSqlQuery = /db\.(query|execute)|prisma\.\$queryRaw|sequelize\.query|session\.query|SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM/i.test(
          line
        );
        if (!isSqlQuery) continue;

        // Check for parameterized queries (SAFE / LOWER RISK)
        // e.g., db.query("SELECT ... WHERE id = $1", [req.query.id]) or db.query("SELECT ... WHERE id = ?", [id])
        const isParameterized =
          /\$1|\$2|\?|\:\b[a-zA-Z_]+\b/.test(line) &&
          (/\[.*\]/.test(line) || /params|bind|values/i.test(line));

        if (isParameterized) {
          // SAFE parameterized query - do NOT flag as SQL injection
          continue;
        }

        // Detect user-controlled input in concatenation or template literal
        const hasUserInput = /req\.(query|params|body|headers|cookies)|searchParams|params\.|request\.(args|form|json|headers|cookies)/i.test(
          line
        );
        const hasConcatOrTemplate =
          line.includes('+') || line.includes('`') || line.includes('%') || line.includes('.format(') || line.includes('f"');

        if (hasUserInput && hasConcatOrTemplate) {
          const sourceMatch = line.match(
            /(req\.(?:query|params|body|headers|cookies)(?:\.[a-zA-Z0-9_]+)?|searchParams\.get\(|params\.[a-zA-Z0-9_]+|request\.(?:args|form|json|headers|cookies)(?:\[|\.)[a-zA-Z0-9_'\"]+\]?)/i
          );
          const source = sourceMatch ? sourceMatch[0] : 'User Input';

          const fingerprint = generateFingerprint('VBG-SQL-001', file.relativePath, 'Database', line);

          findings.push({
            id: 'VBG-SQL-001',
            title: 'Potential SQL Injection Vulnerability',
            category: 'Database',
            severity: 'HIGH',
            confidence: 'HIGH',
            description: `Dynamic construction of SQL query string using unparsed user input '${source}'.`,
            impact: 'Attackers can manipulate SQL query logic to read, alter, or delete database tables or bypass authentication.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Use parameterized queries, prepared statements, or a type-safe ORM query builder instead of string concatenation/template literals.',
            references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
            fingerprint,
          });
        }
      }
    }

    return findings;
  }
}
