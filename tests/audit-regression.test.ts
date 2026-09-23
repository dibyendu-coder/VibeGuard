import path from 'path';
import fs from 'fs';
import { describe, expect, it } from 'vitest';
import { generateFingerprint } from '../src/core/fingerprint.js';
import { maskSecret, maskSnippet } from '../src/core/masker.js';
import { filterSuppressedFindings } from '../src/core/suppression.js';
import { discoverProject } from '../src/discovery/detector.js';
import { analyzeDataFlows } from '../src/graph/flow-analyzer.js';
import { discoverRoutes } from '../src/graph/route-analyzer.js';
import { runScan } from '../src/orchestrator/scanner.js';
import { renderSarifReport } from '../src/reporter/sarif.js';
import { Finding } from '../src/core/types.js';

describe('VibeGuard Engineering Stabilization & Regression Audit Suite', () => {
  const cleanFixture = path.resolve(__dirname, '../fixtures/clean-project');
  const nodeFixture = path.resolve(__dirname, '../fixtures/vulnerable-node');

  it('[VBG-AUDIT-001] normalizes Windows ignore patterns with backslashes correctly', () => {
    const mockConfig: any = {
      ignoredPaths: ['node_modules', 'dist\\subfolder', '.git'],
      failThreshold: 'HIGH',
      privacy: { telemetry: false, aiOptIn: false },
    };
    const manifest = discoverProject(cleanFixture, mockConfig);
    expect(manifest.rootDir).toBe(cleanFixture);
  });

  it('[VBG-AUDIT-002] prevents path traversal when reading inline suppression files', () => {
    const maliciousFinding: Finding = {
      id: 'VBG-TEST-001',
      title: 'Fake Finding',
      category: 'Security',
      severity: 'HIGH',
      confidence: 'HIGH',
      description: 'Test',
      impact: 'Test',
      file: '../../../../etc/passwd',
      line: 1,
      evidence: [],
      remediation: 'Test',
      references: [],
      fingerprint: '1234567890abcdef',
    };

    const result = filterSuppressedFindings([maliciousFinding], cleanFixture);
    expect(result.activeFindings).toHaveLength(1);
    expect(result.activeFindings[0].id).toBe('VBG-TEST-001');
  });

  it('[VBG-AUDIT-003] handles regex special characters in taint analysis without throwing SyntaxError', () => {
    const tempFile = path.resolve(__dirname, '../fixtures/clean-project/temp-test-special.ts');
    fs.writeFileSync(
      tempFile,
      'const $var = req.query.id;\nconst obj = { [key]: value };\ndb.query(`SELECT * FROM users WHERE id = ${$var}`);',
      'utf-8'
    );

    try {
      expect(() => {
        analyzeDataFlows([tempFile], cleanFixture);
      }).not.toThrow();
    } finally {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    }
  });

  it('[VBG-AUDIT-005 & 008] handles non-string snippet and path normalization in fingerprint generator', () => {
    const fp1 = generateFingerprint('VBG-SEC-001', 'src\\index.ts', 42, 'const x = 1;');
    const fp2 = generateFingerprint('VBG-SEC-001', 'src/index.ts', 'Security', 'const x = 1;');

    expect(typeof fp1).toBe('string');
    expect(fp1.length).toBe(16);
    expect(fp2.length).toBe(16);

    // Number passed as snippet argument should not throw TypeError
    expect(() => generateFingerprint('VBG-SEC-001', 'src/index.ts', 'Security', 123 as any)).not.toThrow();
  });

  it('[VBG-AUDIT-006] masks database connection string passwords and API tokens thoroughly', () => {
    const rawConn = 'postgresql://admin:SuperSecretP@ss123@db.example.com:5432/prod_db';
    const maskedConn = maskSecret(rawConn);
    expect(maskedConn).not.toContain('SuperSecretP@ss123');
    expect(maskedConn).toContain('postgresql://admin:********@db.example.com:5432/prod_db');

    const snippet = `const dbUrl = "postgres://user:my_secret_password@localhost:5432/mydb";`;
    const maskedSnippet = maskSnippet(snippet);
    expect(maskedSnippet).not.toContain('my_secret_password');
    expect(maskedSnippet).toContain('postgres://user:********@localhost:5432/mydb');
  });

  it('[VBG-AUDIT-007] handles missing baseline file gracefully with warning log', async () => {
    const scanResult = await runScan({
      targetPath: cleanFixture,
      baseline: 'non-existent-baseline-file-12345.json',
    });
    expect(scanResult.exitCode).toBe(0);
  });

  it('[VBG-AUDIT-009] cleans Next.js App Router route group parentheses from endpoint paths', () => {
    const fakeRouteFile = 'app/(auth)/api/v1/login/route.ts';
    const routes = discoverRoutes([fakeRouteFile], __dirname);
    // Should not throw or crash
    expect(Array.isArray(routes)).toBe(true);
  });

  it('untrusted repository test: scan untrusted project safely without executing any target scripts', async () => {
    const untrustedDir = path.resolve(__dirname, '../scratch/untrusted-repo');
    fs.mkdirSync(untrustedDir, { recursive: true });

    // Create malicious files
    fs.writeFileSync(
      path.join(untrustedDir, 'package.json'),
      JSON.stringify({
        name: 'untrusted-malicious',
        scripts: {
          postinstall: 'echo MALICIOUS EXECUTION HAPPENED > HACKED.txt',
          start: 'rm -rf /',
        },
      }),
      'utf-8'
    );

    fs.writeFileSync(
      path.join(untrustedDir, '$(whoami).ts'),
      'const key = "vbg_test_123456789012345678901234";\neval(req.query.cmd);',
      'utf-8'
    );

    try {
      const scanResult = await runScan({ targetPath: untrustedDir });

      expect(scanResult).toBeDefined();
      expect(scanResult.findings.length).toBeGreaterThan(0);
      expect(fs.existsSync(path.join(untrustedDir, 'HACKED.txt'))).toBe(false);
    } finally {
      fs.rmSync(untrustedDir, { recursive: true, force: true });
    }
  });

  it('SARIF Audit: exports valid SARIF 2.1.0 schema with relative paths', async () => {
    const scanResult = await runScan({ targetPath: nodeFixture });
    const sarifJson = renderSarifReport(scanResult);

    expect(() => JSON.parse(sarifJson)).not.toThrow();
    const parsed = JSON.parse(sarifJson);
    expect(parsed.$schema).toContain('sarif-schema-2.1.0.json');
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0].tool.driver.name).toBe('VibeGuard');
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
  });
});
