import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';
import { Finding, ScanContext } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';

export class CommandInjectionAnalyzer implements Analyzer {
  id = 'command-injection-analyzer';
  name = 'Command Injection Analyzer';
  category = 'Security';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.ts', '.jsx', '.tsx', '.py']);

    for (const file of files) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const lineNum = i + 1;

        const isProcessExec = /(child_process\.)?(exec|execSync|spawn|spawnSync)|os\.system|subprocess\.(run|Popen|call)/i.test(
          line
        );
        if (!isProcessExec) continue;

        // Check if command is purely static hardcoded string: e.g. execSync('git status') or exec('npm test')
        const isStaticCommand =
          /^[^'"\+]*['"]\s*[a-zA-Z0-9_\-\s\/]+\s*['"]\s*\)?\s*;?$/.test(line.trim()) ||
          !/[+\$`]/.test(line);

        const hasUserInput = /req\.(query|params|body|headers|cookies)|searchParams|params\.|request\.(args|form|json|headers|cookies)/i.test(
          line
        );

        if (hasUserInput) {
          const fingerprint = generateFingerprint('VBG-CMD-001', file.relativePath, 'Security', line);

          findings.push({
            id: 'VBG-CMD-001',
            title: 'Potential Command Injection Vulnerability',
            category: 'Security',
            severity: 'CRITICAL',
            confidence: 'HIGH',
            description: 'Untrusted user input is passed directly to process shell execution.',
            impact: 'An attacker can append shell operators (e.g. `;`, `|`, `&&`) to execute arbitrary system commands with application privileges.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Avoid invoking system shell execution with dynamic strings. Use execFile or spawn with array arguments without shell option.',
            references: ['https://owasp.org/www-community/attacks/Command_Injection'],
            fingerprint,
          });
        } else if (!isStaticCommand && (line.includes('+') || line.includes('`') || line.includes('%') || line.includes('.format('))) {
          // Dynamic command execution without obvious user input -> MEDIUM confidence / HIGH severity
          const fingerprint = generateFingerprint('VBG-CMD-002', file.relativePath, 'Security', line);

          findings.push({
            id: 'VBG-CMD-002',
            title: 'Dynamic Process Command Execution',
            category: 'Security',
            severity: 'HIGH',
            confidence: 'MEDIUM',
            description: 'Process execution receives a dynamically constructed string command.',
            impact: 'If variables in command invocation are influenced by untrusted input, arbitrary shell commands can be executed.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: line.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Sanitize variables or use hardcoded command arguments with execFile/spawn.',
            references: ['https://owasp.org/www-community/attacks/Command_Injection'],
            fingerprint,
          });
        }
      }
    }

    return findings;
  }
}
