import { describe, expect, it } from 'vitest';
import path from 'path';
import { runScan } from '../src/orchestrator/scanner.js';

describe('Phase 2 - Scanner Security & Untrusted Repository Safety', () => {
  it('scans clean project without crashing or generating false positives', async () => {
    const fixture = path.resolve('fixtures/clean-project');
    const result = await runScan({ targetPath: fixture, deep: true });
    expect(result.exitCode).toBe(0);
    expect(result.findings.length).toBe(0);
  });

  it('masks secret values in evidence', async () => {
    const fixture = path.resolve('fixtures/secret-exposure');
    const result = await runScan({ targetPath: fixture });
    const secretFindings = result.findings.filter(f => f.category === 'Secrets');
    expect(secretFindings.length).toBeGreaterThan(0);
    for (const finding of secretFindings) {
      for (const ev of finding.evidence) {
        if (ev.snippet) {
          expect(ev.snippet).not.toContain('AKIAIOSFODNN7EXAMPLE');
          expect(ev.snippet).toContain('AKIA****************');
        }
      }
    }
  });

  it('does not execute application code or npm scripts during scan', async () => {
    const fixture = path.resolve('fixtures/vulnerable-node');
    const globalStateBefore = (global as any).hasExecutedTargetCode;
    await runScan({ targetPath: fixture, deep: true });
    const globalStateAfter = (global as any).hasExecutedTargetCode;
    expect(globalStateBefore).toBeUndefined();
    expect(globalStateAfter).toBeUndefined();
  });
});
