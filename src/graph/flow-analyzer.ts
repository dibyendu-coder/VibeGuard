import fs from 'fs';
import path from 'path';
import { DataFlowPath } from './types.js';

export function analyzeDataFlows(files: string[], rootDir: string): DataFlowPath[] {
  const flows: DataFlowPath[] = [];

  for (const filePath of files) {
    if (!filePath.match(/\.(js|ts|jsx|tsx|py)$/)) continue;
    const relPath = path.relative(rootDir, filePath).replace(/\\/g, '/');
    const content = readFileSafe(filePath);
    if (!content) continue;

    const lines = content.split('\n');

    // Simple multi-line static taint tracking
    // Look for variable assignments receiving user input:
    // const input = req.query.foo;
    // ...
    // db.query(`SELECT ... ${input}`);
    const variableTaints = new Map<string, { sourceExpr: string; line: number; sourceKind: string }>();

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const lineText = lines[i];

      // 1. Detect Source Assignment: const x = req.query.id
      const sourceMatch = lineText.match(
        /(?:const|let|var|\$)?\s*([a-zA-Z0-9_]+)\s*=\s*(req\.(?:query|params|body|headers|cookies)(?:\.[a-zA-Z0-9_]+)?|searchParams\.get\(|params\.[a-zA-Z0-9_]+|request\.(?:args|form|json|headers|cookies)(?:\[|\.)[a-zA-Z0-9_'\"]+\]?)/i
      );
      if (sourceMatch) {
        const varName = sourceMatch[1];
        const sourceExpr = sourceMatch[2];
        variableTaints.set(varName, {
          sourceExpr,
          line: lineNum,
          sourceKind: 'user_input',
        });
      }

      // 2. Direct Source in Sink or Variable in Sink
      // SQL Sink
      if (lineText.match(/db\.(query|execute)|prisma\.\$queryRaw|sequelize\.query|session\.query|SELECT\s+.*FROM/i)) {
        for (const [varName, taint] of variableTaints.entries()) {
          const varRegex = createVarRegex(varName);
          if (varRegex && varRegex.test(lineText)) {
            // Check if string concatenation or template literal is present in line or nearby lines
            if (lineText.includes('+') || lineText.includes('`') || lineText.includes('%') || lineText.includes('.format(') || lineText.includes('f"')) {
              flows.push({
                id: `flow-sql-${relPath}-${lineNum}`,
                source: {
                  expression: taint.sourceExpr,
                  filePath: relPath,
                  line: taint.line,
                  kind: taint.sourceKind,
                },
                sink: {
                  expression: lineText.trim(),
                  filePath: relPath,
                  line: lineNum,
                  kind: 'sql',
                },
                transformations: [],
                confidence: 'HIGH',
                isSanitized: false,
              });
            }
          }
        }
      }

      // Command Execution Sink
      if (lineText.match(/(child_process\.)?(exec|execSync|spawn|spawnSync)|os\.system|subprocess\.(run|Popen|call)/i)) {
        for (const [varName, taint] of variableTaints.entries()) {
          const varRegex = createVarRegex(varName);
          if (varRegex && varRegex.test(lineText)) {
            flows.push({
              id: `flow-exec-${relPath}-${lineNum}`,
              source: {
                expression: taint.sourceExpr,
                filePath: relPath,
                line: taint.line,
                kind: taint.sourceKind,
              },
              sink: {
                expression: lineText.trim(),
                filePath: relPath,
                line: lineNum,
                kind: 'exec',
              },
              transformations: [],
              confidence: 'HIGH',
              isSanitized: false,
            });
          }
        }
      }

      // Filesystem Sink
      if (lineText.match(/fs\.(readFile|writeFile|unlink|createReadStream)|open\s*\(/i)) {
        for (const [varName, taint] of variableTaints.entries()) {
          const varRegex = createVarRegex(varName);
          if (varRegex && varRegex.test(lineText)) {
            flows.push({
              id: `flow-fs-${relPath}-${lineNum}`,
              source: {
                expression: taint.sourceExpr,
                filePath: relPath,
                line: taint.line,
                kind: taint.sourceKind,
              },
              sink: {
                expression: lineText.trim(),
                filePath: relPath,
                line: lineNum,
                kind: 'fs',
              },
              transformations: [],
              confidence: 'HIGH',
              isSanitized: false,
            });
          }
        }
      }

      // SSRF Sink
      if (lineText.match(/fetch\s*\(|axios\.(get|post)|requests\.(get|post)|urllib/i)) {
        for (const [varName, taint] of variableTaints.entries()) {
          const varRegex = createVarRegex(varName);
          if (varRegex && varRegex.test(lineText)) {
            flows.push({
              id: `flow-ssrf-${relPath}-${lineNum}`,
              source: {
                expression: taint.sourceExpr,
                filePath: relPath,
                line: taint.line,
                kind: taint.sourceKind,
              },
              sink: {
                expression: lineText.trim(),
                filePath: relPath,
                line: lineNum,
                kind: 'ssrf',
              },
              transformations: [],
              confidence: 'HIGH',
              isSanitized: false,
            });
          }
        }
      }

      // XSS Sink
      if (lineText.match(/dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(/i)) {
        for (const [varName, taint] of variableTaints.entries()) {
          const varRegex = createVarRegex(varName);
          if (varRegex && varRegex.test(lineText)) {
            flows.push({
              id: `flow-xss-${relPath}-${lineNum}`,
              source: {
                expression: taint.sourceExpr,
                filePath: relPath,
                line: taint.line,
                kind: taint.sourceKind,
              },
              sink: {
                expression: lineText.trim(),
                filePath: relPath,
                line: lineNum,
                kind: 'xss',
              },
              transformations: [],
              confidence: 'HIGH',
              isSanitized: false,
            });
          }
        }
      }
    }
  }

  return flows;
}

function createVarRegex(varName: string): RegExp | null {
  if (!varName || !/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(varName)) {
    return null;
  }
  return new RegExp(`\\b${varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
}

function readFileSafe(filePath: string): string | null {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) return null;
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}
