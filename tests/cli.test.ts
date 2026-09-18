import path from 'path';
import { describe, expect, it } from 'vitest';
import { runScan } from '../src/orchestrator/scanner.js';
import { renderJsonReport } from '../src/reporter/json.js';

describe('Scan Orchestrator & CLI output', () => {
  it('executes scan on fixture directory successfully', async () => {
    const fixtureDir = path.resolve(__dirname, '../fixtures/sample-nextjs');
    const scanResult = await runScan({ targetPath: fixtureDir });

    expect(scanResult.version).toBe('0.1.0');
    expect(scanResult.manifest.projectName).toBe('sample-nextjs');
    expect(scanResult.findings.length).toBeGreaterThan(0);
    expect(scanResult.scores.status).toBeDefined();
    expect(scanResult.exitCode).toBeDefined();
  });

  it('generates clean JSON report without ANSI control sequences', async () => {
    const fixtureDir = path.resolve(__dirname, '../fixtures/sample-nextjs');
    const scanResult = await runScan({ targetPath: fixtureDir, json: true });

    const jsonStr = renderJsonReport(scanResult);
    expect(() => JSON.parse(jsonStr)).not.toThrow();

    const parsed = JSON.parse(jsonStr);
    expect(parsed.project.name).toBe('sample-nextjs');
    expect(jsonStr).not.toMatch(/\x1B\[[0-9;]*[a-zA-Z]/);
  });
});
