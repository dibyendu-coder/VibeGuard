import { generateFingerprint } from '../core/fingerprint.js';
import { maskSnippet } from '../core/masker.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class UnsafeCodeAnalyzer implements Analyzer {
  id = 'unsafe-code-analyzer';
  name = 'Unsafe Code Patterns Analyzer';
  category = 'Security';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py', '.mjs']);

    for (const file of files) {
      const isPython = file.relativePath.endsWith('.py');
      const isJsTs = !isPython;

      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;
        const trimmed = line.trim();

        if (trimmed.startsWith('//') || trimmed.startsWith('#')) continue;

        // --- JavaScript / TypeScript Checks ---
        if (isJsTs) {
          // Rule 1: eval() (VBG-CODE-001)
          if (/(?:^|\s|\()eval\s*\(/i.test(trimmed)) {
            const fp = generateFingerprint('VBG-CODE-001', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CODE-001',
              title: 'Use of eval() detected',
              category: 'Security',
              severity: 'HIGH',
              confidence: 'HIGH',
              description: 'The JavaScript eval() function executes strings as arbitrary JavaScript with full caller privileges.',
              impact: 'If user-supplied or untrusted input reaches eval(), an attacker can achieve arbitrary remote code execution (RCE).',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Avoid eval() entirely. Use structured JSON parsing (JSON.parse) or safe lookup tables instead of dynamic evaluation.',
              references: ['https://cwe.mitre.org/data/definitions/95.html'],
              fingerprint: fp,
            });
          }

          // Rule 2: new Function() (VBG-CODE-002)
          if (/new\s+Function\s*\(/i.test(trimmed)) {
            const fp = generateFingerprint('VBG-CODE-002', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CODE-002',
              title: 'Use of new Function() constructor for dynamic code execution',
              category: 'Security',
              severity: 'HIGH',
              confidence: 'HIGH',
              description: 'Calling new Function() with dynamic strings compiles code at runtime, similar to eval.',
              impact: 'Untrusted input in Function constructor arguments allows arbitrary JavaScript execution in the server or browser runtime.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Refactor code to use statically defined functions and deterministic data dispatch patterns.',
              references: ['https://cwe.mitre.org/data/definitions/95.html'],
              fingerprint: fp,
            });
          }

          // Rule 3: Dynamic child_process execution (VBG-CODE-003)
          if (
            /(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|[a-zA-Z0-9_]+\s*\+\s*['"]|['"][^'"]*['"]\s*\+\s*[a-zA-Z0-9_]+)/i.test(
              trimmed
            )
          ) {
            const fp = generateFingerprint('VBG-CODE-003', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CODE-003',
              title: 'Dynamic shell command execution via child_process.exec',
              category: 'Security',
              severity: 'CRITICAL',
              confidence: 'HIGH',
              description: 'Shell commands are constructed using dynamic string interpolation or concatenation within child_process.exec / execSync.',
              impact: 'Unsanitized input containing shell metacharacters (; | && `) can execute arbitrary system commands on the host server.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Use child_process.execFile or child_process.spawn with an array of distinct arguments and shell: false.',
              references: ['https://cwe.mitre.org/data/definitions/78.html'],
              fingerprint: fp,
            });
          }

          // Rule 4: SQL string concatenation (VBG-CODE-004)
          if (
            /(?:(?:const|let|var)\s+[a-zA-Z0-9_]*query[a-zA-Z0-9_]*\s*=\s*|(?:query|execute|raw)\s*\()\s*(?:`[^`\r\n]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^`\r\n]*\$\{|"[^"\r\n]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"\r\n]*"\s*\+|'[^'\r\n]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^'\r\n]*'\s*\+)/i.test(
              trimmed
            )
          ) {
            const fp = generateFingerprint('VBG-CODE-004', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CODE-004',
              title: 'SQL query constructed via dynamic string concatenation or template literal',
              category: 'Security',
              severity: 'CRITICAL',
              confidence: 'HIGH',
              description: 'SQL query string incorporates variables through template literal interpolation (${...}) or string addition instead of parameterized query placeholders.',
              impact: 'SQL injection allows attackers to bypass authentication, read unauthorized database tables, modify data, or execute administrative commands.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Use parameterized queries ($1, $2, or ?) or an ORM query builder to ensure user inputs are always treated as literals.',
              references: ['https://cwe.mitre.org/data/definitions/89.html'],
              fingerprint: fp,
            });
          }

          // Rule 5: DangerouslySetInnerHTML / innerHTML (VBG-CODE-005)
          if (/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/i.test(trimmed) || /\.innerHTML\s*=/i.test(trimmed)) {
            const fp = generateFingerprint('VBG-CODE-005', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CODE-005',
              title: 'Direct HTML injection sink detected (dangerouslySetInnerHTML / innerHTML)',
              category: 'Security',
              severity: 'MEDIUM',
              confidence: 'HIGH',
              description: 'Direct insertion of unescaped HTML content bypassing React or DOM escaping mechanisms.',
              impact: 'If the injected content includes user-provided data, attackers can execute Cross-Site Scripting (XSS) scripts in victims\' browsers.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Sanitize HTML inputs with DOMPurify or sanitize-html before rendering, or use standard React text components.',
              references: ['https://cwe.mitre.org/data/definitions/79.html'],
              fingerprint: fp,
            });
          }
        }

        // --- Python Checks ---
        if (isPython) {
          // Rule 6: eval / exec in Python (VBG-CODE-006)
          if (/(?:^|\s)(?:eval|exec)\s*\(/i.test(trimmed)) {
            const fp = generateFingerprint('VBG-CODE-006', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CODE-006',
              title: 'Use of dynamic code execution (eval / exec) in Python',
              category: 'Security',
              severity: 'HIGH',
              confidence: 'HIGH',
              description: 'Python eval() or exec() executes arbitrary Python code within the application process.',
              impact: 'Permits remote code execution if any variable supplied to eval/exec is influenced by user input.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Replace dynamic eval/exec with safe alternatives like ast.literal_eval or structured dictionaries.',
              references: ['https://cwe.mitre.org/data/definitions/95.html'],
              fingerprint: fp,
            });
          }

          // Rule 7: Unsafe subprocess or os.system in Python (VBG-CODE-007)
          if (
            /(?:subprocess\.(?:Popen|call|run)\s*\([^)]*shell\s*=\s*True|os\.system\s*\()/i.test(
              trimmed
            )
          ) {
            const fp = generateFingerprint('VBG-CODE-007', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CODE-007',
              title: 'Unsafe subprocess execution with shell=True or os.system',
              category: 'Security',
              severity: 'CRITICAL',
              confidence: 'HIGH',
              description: 'Executing system commands through a shell (shell=True or os.system) exposes the command to shell injection.',
              impact: 'Attackers can append command separators to execute unauthorized commands with the process permissions.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Pass arguments as a list of strings and set shell=False (default) in subprocess.run.',
              references: ['https://cwe.mitre.org/data/definitions/78.html'],
              fingerprint: fp,
            });
          }

          // Rule 8: Unsafe SQL string formatting in Python (VBG-CODE-008)
          if (
            /(?:cursor\.execute|session\.execute|db\.execute)\s*\(\s*(?:f"[^"\r\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^"\r\n]*\{|f'[^'\r\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\r\n]*\{|"[^"\r\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^"\r\n]*"\s*[%+]|'[^'\r\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\r\n]*'\s*[%+])/i.test(
              trimmed
            )
          ) {
            const fp = generateFingerprint('VBG-CODE-008', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CODE-008',
              title: 'Unsafe SQL formatting with Python f-string or % formatting',
              category: 'Security',
              severity: 'CRITICAL',
              confidence: 'HIGH',
              description: 'SQL query string constructed via Python f-string or %-formatting before passing to execute().',
              impact: 'Vulnerable to SQL injection, enabling unauthorized database modifications or data dumping.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Use parameterized queries: cursor.execute("SELECT ... WHERE id = %s", (id,)) rather than formatting the query string.',
              references: ['https://cwe.mitre.org/data/definitions/89.html'],
              fingerprint: fp,
            });
          }

          // Rule 9: Dangerous deserialization in Python (VBG-CODE-009)
          if (
            /(?:pickle\.loads?|yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:Loader|CLoader|UnsafeLoader))/i.test(
              trimmed
            )
          ) {
            const fp = generateFingerprint('VBG-CODE-009', file.relativePath, lineNum, trimmed);
            findings.push({
              id: 'VBG-CODE-009',
              title: 'Insecure deserialization using pickle or unsafe YAML loader',
              category: 'Security',
              severity: 'HIGH',
              confidence: 'HIGH',
              description: 'Deserializing data with pickle or an unsafe PyYAML loader can execute arbitrary code during object instantiation.',
              impact: 'Loading untrusted serialized data grants full remote code execution in the Python process.',
              file: file.relativePath,
              line: lineNum,
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: maskSnippet(trimmed),
                },
              ],
              remediation: 'Use safe serialization formats such as JSON (json.loads) or PyYAML safe_load (yaml.safe_load).',
              references: ['https://cwe.mitre.org/data/definitions/502.html'],
              fingerprint: fp,
            });
          }
        }
      }
    }

    return findings;
  }
}
