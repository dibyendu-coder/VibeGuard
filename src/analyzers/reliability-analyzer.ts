import path from 'path';
import { generateFingerprint } from '../core/fingerprint.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class ReliabilityAnalyzer implements Analyzer {
  id = 'reliability-analyzer';
  name = 'Reliability & Resilience Analyzer';
  category = 'Reliability';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context, ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py']);

    for (const file of files) {
      const isTestOrDoc =
        file.relativePath.includes('test') ||
        file.relativePath.includes('fixture') ||
        file.relativePath.includes('example') ||
        file.relativePath.includes('doc');

      file.lines.forEach((lineText, idx) => {
        const lineNum = idx + 1;

        // 1. Sync Blocking File I/O in JS/TS
        if (
          /\b(readFileSync|writeFileSync|appendFileSync|existsSync|readdirSync|statSync|unlinkSync)\b/.test(
            lineText
          ) &&
          !isTestOrDoc
        ) {
          // Check if file seems to be a server/route module or handler context
          if (
            file.content.includes('express') ||
            file.content.includes('app.get') ||
            file.content.includes('app.post') ||
            file.content.includes('router.') ||
            file.content.includes('req, res') ||
            file.content.includes('NextResponse') ||
            file.content.includes('NextApiRequest')
          ) {
            const ruleId = 'VBG-REL-001';
            findings.push({
              id: ruleId,
              rule_id: ruleId,
              title: 'Synchronous Blocking File Operation in Request Path',
              category: 'Reliability',
              subcategory: 'I/O Bottleneck',
              analyzer: this.id,
              severity: 'MEDIUM',
              confidence: 'HIGH',
              description: `Synchronous file method '${lineText.trim()}' blocks the single-threaded event loop during HTTP request execution.`,
              impact: 'High latency under concurrent request load, potential service unresponsiveness or request timeouts.',
              evidence: [
                {
                  filePath: file.relativePath,
                  line: lineNum,
                  snippet: lineText.trim(),
                },
              ],
              file: file.relativePath,
              line: lineNum,
              remediation: 'Replace synchronous I/O methods with asynchronous fs.promises or async/await implementations.',
              references: ['https://nodejs.org/api/fs.html#promises-api'],
              fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
              production_impact: 'High traffic spikes will exhaust event loop worker pool threads and block all concurrent users.',
              confidence_reason: 'Direct invocation of sync filesystem methods inside HTTP server request handler context.',
            });
          }
        }

        // 2. Swallowed Exceptions / Empty Catch Blocks
        if (
          /catch\s*\([^)]*\)\s*\{\s*\}/.test(lineText) ||
          (lineText.includes('catch') && lineText.endsWith('{}')) ||
          /except\s*:\s*pass\b/.test(lineText) ||
          /except\s+\w+\s*:\s*pass\b/.test(lineText)
        ) {
          const ruleId = 'VBG-REL-003';
          findings.push({
            id: ruleId,
            rule_id: ruleId,
            title: 'Swallowed Exception / Empty Catch Block',
            category: 'Reliability',
            subcategory: 'Error Handling',
            analyzer: this.id,
            severity: isTestOrDoc ? 'LOW' : 'MEDIUM',
            confidence: 'HIGH',
            description: 'Exceptions are caught and silently suppressed without logging, metrics, or error propagation.',
            impact: 'Failures occur silently without diagnostic audit trails, hiding critical root causes and leading to unpredictable runtime states.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: lineText.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Log caught errors with adequate contextual detail or rethrow/propagate custom failure instances.',
            references: ['https://cwe.mitre.org/data/definitions/391.html'],
            fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
            production_impact: 'Production silent failures cause corrupted application state that goes unnoticed until fatal failure.',
          });
        }

        // 3. Network Requests Without Timeout
        if (
          (/\b(fetch|axios|axios\.get|axios\.post|http\.get|https\.get)\(/.test(lineText) ||
            /\brequests\.(get|post|put|delete)\(/.test(lineText)) &&
          !lineText.includes('timeout') &&
          !lineText.includes('signal') &&
          !isTestOrDoc
        ) {
          // Verify if surrounding context lacks timeout configuration
          const ruleId = 'VBG-REL-002';
          findings.push({
            id: ruleId,
            rule_id: ruleId,
            title: 'Network Request Missing Timeout',
            category: 'Reliability',
            subcategory: 'Resilience',
            analyzer: this.id,
            severity: 'MEDIUM',
            confidence: 'MEDIUM',
            description: 'HTTP client call executed without explicit request timeout bounds.',
            impact: 'Hanging upstream microservices or network partitions can stall socket connections indefinitely, leaking file descriptors and worker resources.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: lineText.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Pass explicit timeout parameters (e.g. AbortSignal.timeout(5000) or axios timeout option).',
            references: ['https://cwe.mitre.org/data/definitions/400.html'],
            fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
            production_impact: 'Slow external APIs will cause cascading thread/socket pool exhaustion across server instances.',
          });
        }

        // 4. Unhandled Promise Rejection (.then without .catch)
        if (
          /\.then\(/.test(lineText) &&
          !lineText.includes('.catch(') &&
          !file.content.slice(file.content.indexOf(lineText)).includes('.catch(') &&
          !isTestOrDoc
        ) {
          const ruleId = 'VBG-REL-004';
          findings.push({
            id: ruleId,
            rule_id: ruleId,
            title: 'Unhandled Promise Rejection (.then without .catch)',
            category: 'Reliability',
            subcategory: 'Async Safety',
            analyzer: this.id,
            severity: 'LOW',
            confidence: 'MEDIUM',
            description: 'Promise chain initiated with .then() lacks explicit rejection handler or trailing .catch().',
            impact: 'Uncaught promise rejections can cause Node.js process termination or unhandled rejection warnings.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: lineText.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Append .catch() rejection handlers to Promise chains or refactor to async/await with try/catch.',
            references: ['https://nodejs.org/api/process.html#event-unhandledrejection'],
            fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
          });
        }

        // 5. Unbounded In-Memory Queue/Cache in Server Scope
        if (
          /(const|let|var)\s+(cache|queue|store|logs|history|buffer)\s*=\s*(\[\]|\{\}|new\s+Map\(\)|new\s+Set\(\))/.test(
            lineText
          ) &&
          !isTestOrDoc
        ) {
          const ruleId = 'VBG-REL-006';
          findings.push({
            id: ruleId,
            rule_id: ruleId,
            title: 'Potentially Unbounded In-Memory State Container',
            category: 'Reliability',
            subcategory: 'Memory Management',
            analyzer: this.id,
            severity: 'LOW',
            confidence: 'LOW',
            description: 'Global or module-scoped state container initialized without obvious capacity limits or eviction policy.',
            impact: 'Accumulation of request payloads, logs, or sessions over long process runtimes will result in Out-Of-Memory (OOM) process crashes.',
            evidence: [
              {
                filePath: file.relativePath,
                line: lineNum,
                snippet: lineText.trim(),
              },
            ],
            file: file.relativePath,
            line: lineNum,
            remediation: 'Use bounded LRU caches (e.g. lru-cache) or external persistence stores (e.g. Redis) with TTL eviction.',
            references: ['https://cwe.mitre.org/data/definitions/770.html'],
            fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
          });
        }
      });
    }

    return findings;
  }
}
