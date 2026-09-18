import path from 'path';
import { describe, expect, it } from 'vitest';
import { runScan } from '../src/orchestrator/scanner.js';

describe('Phase 3 - Production Readiness & Deep Analyzers Test Suite', () => {
  it('detects Docker misconfigurations (root user, latest tag, copied .env)', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/docker');
    const result = await runScan({ targetPath: fixturePath });

    const ruleIds = result.findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-DEP-001'); // Root user
    expect(ruleIds).toContain('VBG-DEP-002'); // Floating :latest tag
    expect(ruleIds).toContain('VBG-DEP-003'); // Copied .env
  });

  it('detects CI workflow vulnerabilities (unmasked secret echo, unpinned actions)', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/ci');
    const result = await runScan({ targetPath: fixturePath });

    const ruleIds = result.findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-DEP-006'); // Secret echo
    expect(ruleIds).toContain('VBG-DEP-007'); // Unpinned action tag
  });

  it('detects Reliability risks (sync blocking I/O, missing fetch timeout, swallowed exception)', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/reliability');
    const result = await runScan({ targetPath: fixturePath });

    const ruleIds = result.findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-REL-001'); // Sync file read in HTTP request handler
    expect(ruleIds).toContain('VBG-REL-002'); // Fetch missing timeout
    expect(ruleIds).toContain('VBG-REL-003'); // Empty catch block
  });

  it('detects Data Exposure & Privacy leaks (logged passwords, returned password hash)', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/data-exposure');
    const result = await runScan({ targetPath: fixturePath });

    const ruleIds = result.findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-DAT-001'); // Password logged to console
    expect(ruleIds).toContain('VBG-DAT-003'); // Password hash in response
  });

  it('detects Production Configuration issues (debug mode, localhost DB URL)', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/production-config');
    const result = await runScan({ targetPath: fixturePath });

    const ruleIds = result.findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-CONFIG-003'); // DEBUG = True
    expect(ruleIds).toContain('VBG-CONFIG-002'); // Localhost URL in prod config
  });

  it('computes status-based readiness dimensions in ScoreResult', async () => {
    const fixturePath = path.resolve(__dirname, '../fixtures/docker');
    const result = await runScan({ targetPath: fixturePath });

    expect(result.scores.readinessDimensions).toBeDefined();
    expect(result.scores.readinessDimensions?.deployment).toBe('RISKY');
  });
});
