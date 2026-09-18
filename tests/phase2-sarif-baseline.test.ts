import { describe, expect, it } from 'vitest';
import fs from 'fs';
import path from 'path';
import { runScan } from '../src/orchestrator/scanner.js';
import { renderSarifReport } from '../src/reporter/sarif.js';
import { createBaseline, loadBaseline, filterFindingsWithBaseline } from '../src/core/baseline.js';

describe('Phase 2 - SARIF Output & Baseline Support', () => {
  const nodeFixture = path.resolve('fixtures/vulnerable-node');
  const tempBaselinePath = path.resolve('fixtures/vulnerable-node/.vibeguard-baseline.json');

  it('generates valid SARIF v2.1.0 output', async () => {
    const result = await runScan({ targetPath: nodeFixture, deep: true });
    const sarifStr = renderSarifReport(result);
    const parsed = JSON.parse(sarifStr);

    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toBeDefined();
    expect(parsed.runs[0].tool.driver.name).toBe('VibeGuard');
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
    expect(sarifStr).not.toMatch(/\x1B\[[0-9;]*[a-zA-Z]/);
  });

  it('creates and applies baseline filtering correctly', async () => {
    const scanResult = await runScan({ targetPath: nodeFixture });
    const baseline = createBaseline(scanResult.findings, tempBaselinePath);

    expect(baseline.fingerprints.length).toBeGreaterThan(0);
    expect(fs.existsSync(tempBaselinePath)).toBe(true);

    const loadedSet = loadBaseline(tempBaselinePath);
    expect(loadedSet).not.toBeNull();

    const { newFindings, existingCount } = filterFindingsWithBaseline(scanResult.findings, loadedSet!);
    expect(newFindings.length).toBe(0);
    expect(existingCount).toBe(scanResult.findings.length);

    // Clean up temporary baseline file
    if (fs.existsSync(tempBaselinePath)) {
      fs.unlinkSync(tempBaselinePath);
    }
  });
});
