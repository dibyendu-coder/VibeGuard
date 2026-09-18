import path from 'path';
import { describe, expect, it } from 'vitest';
import { Analyzer } from '../src/analyzers/base.js';
import { computeExitCode, runScan } from '../src/orchestrator/scanner.js';
import { renderBanner } from '../src/reporter/banner.js';
import { renderJsonReport } from '../src/reporter/json.js';
import { renderTerminalReport } from '../src/reporter/terminal.js';

describe('CLI & Orchestrator Integration Suite', () => {
  const nextjsFixture = path.resolve(__dirname, '../fixtures/vulnerable-nextjs');
  const nodeFixture = path.resolve(__dirname, '../fixtures/vulnerable-node');
  const pythonFixture = path.resolve(__dirname, '../fixtures/vulnerable-python');
  const cleanFixture = path.resolve(__dirname, '../fixtures/clean-project');

  it('scans vulnerable-nextjs fixture and detects security findings with blocking exit code', async () => {
    const result = await runScan({ targetPath: nextjsFixture });
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.scores.status).toBe('NOT_READY');
    expect(result.exitCode).toBe(2);

    const ruleIds = result.findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-SECRET-001'); // Stripe secret
    expect(ruleIds).toContain('VBG-AUTH-001'); // Client-side role check
    expect(ruleIds).toContain('VBG-CONFIG-001'); // Committed .env.production
    expect(ruleIds).toContain('VBG-API-001'); // Missing resource authorization
  });

  it('scans vulnerable-node fixture and detects command exec and SQL injection', async () => {
    const result = await runScan({ targetPath: nodeFixture });
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.exitCode).toBe(2);

    const ruleIds = result.findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-CODE-003'); // Dynamic child_process.exec
    expect(ruleIds).toContain('VBG-CODE-004'); // SQL string concatenation
    expect(ruleIds).toContain('VBG-API-004'); // Wildcard CORS
  });

  it('scans vulnerable-python fixture and detects eval, shell=True, and pickle', async () => {
    const result = await runScan({ targetPath: pythonFixture });
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.exitCode).toBe(2);

    const ruleIds = result.findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-CODE-006'); // eval in Python
    expect(ruleIds).toContain('VBG-CODE-007'); // subprocess shell=True
    expect(ruleIds).toContain('VBG-CODE-008'); // SQL f-string
    expect(ruleIds).toContain('VBG-CODE-009'); // Insecure pickle deserialization
  });

  it('scans clean-project fixture and returns 0 exit code with READY status', async () => {
    const result = await runScan({ targetPath: cleanFixture });
    expect(result.findings).toHaveLength(0);
    expect(result.scores.overallScore).toBe(100);
    expect(result.scores.status).toBe('READY');
    expect(result.exitCode).toBe(0);
  });

  it('generates machine-readable JSON without any ANSI escape sequences', async () => {
    const result = await runScan({ targetPath: nextjsFixture, json: true });
    const jsonStr = renderJsonReport(result);

    // Valid JSON parse
    expect(() => JSON.parse(jsonStr)).not.toThrow();
    const parsed = JSON.parse(jsonStr);

    expect(parsed.project).toBeDefined();
    expect(parsed.scanMetadata).toBeDefined();
    expect(parsed.detectedTechnologies).toBeDefined();
    expect(parsed.dependencyInventory).toBeDefined();
    expect(parsed.findings).toBeDefined();
    expect(parsed.scores).toBeDefined();
    expect(parsed.summary).toBeDefined();
    expect(parsed.analyzerStatus).toBeDefined();

    // Zero ANSI sequences
    expect(jsonStr).not.toMatch(/\x1B\[[0-9;]*[a-zA-Z]/);
  });

  it('renders clean terminal report in NO_COLOR mode without ANSI escape sequences', async () => {
    const result = await runScan({ targetPath: nextjsFixture });
    const textReport = renderTerminalReport(result, true);

    expect(textReport).toContain('AUDIT COMPLETE');
    expect(textReport).toContain('STATUS: NOT READY');
    expect(textReport).not.toMatch(/\x1B\[[0-9;]*[a-zA-Z]/);
  });

  it('renders narrow terminal layout gracefully when width < 70 columns', () => {
    const narrowBanner = renderBanner({ noColor: false, terminalWidth: 60 });
    expect(narrowBanner).toContain('VIBEGUARD');
    expect(narrowBanner).not.toContain('██╗');
  });

  it('isolates analyzer failure: broken analyzer does not crash overall scan', async () => {
    const faultyAnalyzer: Analyzer = {
      id: 'faulty-analyzer',
      name: 'Faulty Test Analyzer',
      category: 'Security',
      async analyze() {
        throw new Error('Simulated analyzer crash');
      },
    };

    // Run scan with the faulty analyzer along with clean project
    const result = await runScan({ targetPath: cleanFixture }, [faultyAnalyzer]);

    expect(result).toBeDefined();
    expect(result.analyzerStatuses).toHaveLength(1);
    expect(result.analyzerStatuses[0].status).toBe('failed');
    expect(result.analyzerStatuses[0].error).toContain('Simulated analyzer crash');
  });

  it('correctly calculates exit code based on failure threshold', () => {
    // Clean findings -> 0
    expect(computeExitCode([], 'HIGH')).toBe(0);

    // Low severity findings with HIGH threshold -> 1 (warnings only)
    const lowFinding: any = [{ severity: 'LOW' }];
    expect(computeExitCode(lowFinding, 'HIGH')).toBe(1);

    // Critical finding with HIGH threshold -> 2 (blocking)
    const criticalFinding: any = [{ severity: 'CRITICAL' }];
    expect(computeExitCode(criticalFinding, 'HIGH')).toBe(2);
  });
});
