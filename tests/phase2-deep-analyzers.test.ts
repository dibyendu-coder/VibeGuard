import { describe, expect, it } from 'vitest';
import path from 'path';
import { runScan } from '../src/orchestrator/scanner.js';
import { SqlInjectionAnalyzer } from '../src/analyzers/sql-injection-analyzer.js';
import { CommandInjectionAnalyzer } from '../src/analyzers/command-injection-analyzer.js';
import { PathTraversalAnalyzer } from '../src/analyzers/path-traversal-analyzer.js';
import { SsrfAnalyzer } from '../src/analyzers/ssrf-analyzer.js';
import { XssAnalyzer } from '../src/analyzers/xss-analyzer.js';
import { AuthorizationAnalyzer } from '../src/analyzers/authorization-analyzer.js';
import { CorsSecurityAnalyzer } from '../src/analyzers/cors-security-analyzer.js';

describe('Phase 2 - Deep Security Analyzers', () => {
  it('detects SQL injection while ignoring safe parameterized queries', async () => {
    const fixture = path.resolve('fixtures/sql-injection');
    const result = await runScan({ targetPath: fixture, deep: true }, [new SqlInjectionAnalyzer()]);
    const sqlFindings = result.findings.filter(f => f.id === 'VBG-SQL-001');
    expect(sqlFindings.length).toBe(1);
  });

  it('detects command injection while ignoring static shell commands', async () => {
    const fixture = path.resolve('fixtures/command-injection');
    const result = await runScan({ targetPath: fixture, deep: true }, [new CommandInjectionAnalyzer()]);
    expect(result.findings.some(f => f.id === 'VBG-CMD-001')).toBe(true);
  });

  it('detects path traversal when user input reaches fs operations', async () => {
    const fixture = path.resolve('fixtures/path-traversal');
    const result = await runScan({ targetPath: fixture, deep: true }, [new PathTraversalAnalyzer()]);
    expect(result.findings.some(f => f.id === 'VBG-PATH-001')).toBe(true);
  });

  it('detects SSRF when user input flows to outbound HTTP requests', async () => {
    const fixture = path.resolve('fixtures/ssrf');
    const result = await runScan({ targetPath: fixture, deep: true }, [new SsrfAnalyzer()]);
    expect(result.findings.some(f => f.id === 'VBG-SSRF-001')).toBe(true);
  });

  it('detects XSS when user input reaches dangerous DOM sinks without sanitization', async () => {
    const fixture = path.resolve('fixtures/xss');
    const result = await runScan({ targetPath: fixture, deep: true }, [new XssAnalyzer()]);
    expect(result.findings.some(f => f.id === 'VBG-XSS-001')).toBe(true);
  });

  it('detects privilege escalation via client-controlled input', async () => {
    const fixture = path.resolve('fixtures/auth-bypass');
    const result = await runScan({ targetPath: fixture, deep: true }, [new AuthorizationAnalyzer()]);
    expect(result.findings.some(f => f.id === 'VBG-AUTHZ-001')).toBe(true);
  });

  it('detects permissive CORS configuration', async () => {
    const fixture = path.resolve('fixtures/insecure-cors');
    const result = await runScan({ targetPath: fixture, deep: true }, [new CorsSecurityAnalyzer()]);
    expect(result.findings.some(f => f.id === 'VBG-CORS-001')).toBe(true);
  });

  it('produces no high/critical findings on false-positive project', async () => {
    const fixture = path.resolve('fixtures/false-positive-project');
    const result = await runScan({ targetPath: fixture, deep: true });
    const highOrCritical = result.findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL');
    expect(highOrCritical.length).toBe(0);
  });
});
