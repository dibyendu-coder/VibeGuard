import path from 'path';
import { describe, expect, it } from 'vitest';
import { explainFinding } from '../src/core/explain.js';
import { runScan } from '../src/orchestrator/scanner.js';

describe('Phase 3 - CLI Commands & Explain Engine Test Suite', () => {
  it('explains finding deterministically with WHAT, WHERE, WHY, HOW, IMPACT, FIX without an LLM', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/docker');
    const result = await runScan({ targetPath: fixturePath });

    expect(result.findings.length).toBeGreaterThan(0);
    const finding = result.findings[0];

    const explanationText = explainFinding(finding, true);

    expect(explanationText).toContain('FINDING EXPLANATION:');
    expect(explanationText).toContain('WHAT (Description):');
    expect(explanationText).toContain('WHERE (Evidence):');
    expect(explanationText).toContain('WHY (Detection Reason & Context):');
    expect(explanationText).toContain('IMPACT:');
    expect(explanationText).toContain('HOW TO FIX (Remediation):');
  });

  it('runs category-filtered scan correctly', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/docker');
    const result = await runScan({ targetPath: fixturePath, category: 'deployment' });

    expect(result.findings.length).toBeGreaterThan(0);
    result.findings.forEach((f) => {
      expect(f.category.toLowerCase()).toBe('deployment');
    });
  });
});
