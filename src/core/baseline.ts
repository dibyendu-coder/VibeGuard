import fs from 'fs';
import path from 'path';
import { Finding } from './types.js';

export interface BaselineFile {
  version: string;
  createdAt: string;
  fingerprints: string[];
  findingsCount: number;
}

export function createBaseline(findings: Finding[], outputPath: string): BaselineFile {
  const fingerprints = Array.from(new Set(findings.map((f) => f.fingerprint)));
  const baselineData: BaselineFile = {
    version: '0.1.0',
    createdAt: new Date().toISOString(),
    fingerprints,
    findingsCount: fingerprints.length,
  };

  const resolvedPath = path.resolve(outputPath);
  fs.writeFileSync(resolvedPath, JSON.stringify(baselineData, null, 2), 'utf-8');
  return baselineData;
}

export function loadBaseline(baselinePath: string): Set<string> | null {
  try {
    const resolvedPath = path.resolve(baselinePath);
    if (!fs.existsSync(resolvedPath)) return null;

    const content = fs.readFileSync(resolvedPath, 'utf-8');
    const data: BaselineFile = JSON.parse(content);
    return new Set(data.fingerprints || []);
  } catch {
    return null;
  }
}

export function filterFindingsWithBaseline(
  findings: Finding[],
  baselineFingerprints: Set<string>
): {
  newFindings: Finding[];
  existingCount: number;
} {
  const newFindings: Finding[] = [];
  let existingCount = 0;

  for (const f of findings) {
    if (baselineFingerprints.has(f.fingerprint)) {
      existingCount++;
    } else {
      newFindings.push(f);
    }
  }

  return { newFindings, existingCount };
}
