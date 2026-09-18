import { describe, expect, it } from 'vitest';
import { UnsafeCodeAnalyzer } from '../src/analyzers/unsafe-code-analyzer.js';
import { DEFAULT_CONFIG } from '../src/config/loader.js';
import { ScanContext } from '../src/core/types.js';

describe('UnsafeCodeAnalyzer', () => {
  const analyzer = new UnsafeCodeAnalyzer();

  it('positive: detects SQL injection and dynamic command execution in node fixture', async () => {
    const nodeContext: ScanContext = {
      projectRoot: process.cwd() + '/fixtures/vulnerable-node',
      manifest: {
        rootDir: process.cwd() + '/fixtures/vulnerable-node',
        projectName: 'vulnerable-node',
        languages: ['JavaScript'],
        frameworks: [],
        packageManifests: ['package.json'],
        lockfiles: [],
        sourceDirectories: [],
        apiDirectories: [],
        authIndicators: [],
        databaseIndicators: [],
        ciCdConfigFiles: [],
        dockerFiles: [],
        envFiles: [],
        configFiles: [],
        routesCount: 3,
        databaseTablesCount: 0,
        sourceFilesCount: 1,
        totalFilesCount: 2,
      },
      config: DEFAULT_CONFIG,
      options: { targetPath: process.cwd() + '/fixtures/vulnerable-node' },
    };

    const findings = await analyzer.analyze(nodeContext);
    const ruleIds = findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-CODE-003'); // Dynamic child_process.exec
    expect(ruleIds).toContain('VBG-CODE-004'); // SQL string concatenation
  });

  it('positive: detects eval, subprocess shell=True, SQL f-string, and pickle in python fixture', async () => {
    const pythonContext: ScanContext = {
      projectRoot: process.cwd() + '/fixtures/vulnerable-python',
      manifest: {
        rootDir: process.cwd() + '/fixtures/vulnerable-python',
        projectName: 'vulnerable-python',
        languages: ['Python'],
        frameworks: [],
        packageManifests: ['requirements.txt'],
        lockfiles: [],
        sourceDirectories: [],
        apiDirectories: [],
        authIndicators: [],
        databaseIndicators: [],
        ciCdConfigFiles: [],
        dockerFiles: [],
        envFiles: [],
        configFiles: [],
        routesCount: 5,
        databaseTablesCount: 0,
        sourceFilesCount: 1,
        totalFilesCount: 2,
      },
      config: DEFAULT_CONFIG,
      options: { targetPath: process.cwd() + '/fixtures/vulnerable-python' },
    };

    const findings = await analyzer.analyze(pythonContext);
    const ruleIds = findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-CODE-006'); // eval in Python
    expect(ruleIds).toContain('VBG-CODE-007'); // subprocess shell=True
    expect(ruleIds).toContain('VBG-CODE-008'); // SQL f-string
    expect(ruleIds).toContain('VBG-CODE-009'); // Insecure pickle deserialization
  });

  it('negative: zero findings on clean-project', async () => {
    const cleanContext: ScanContext = {
      projectRoot: process.cwd() + '/fixtures/clean-project',
      manifest: {
        rootDir: process.cwd() + '/fixtures/clean-project',
        projectName: 'clean-project',
        languages: ['TypeScript'],
        frameworks: [],
        packageManifests: ['package.json'],
        lockfiles: ['package-lock.json'],
        sourceDirectories: ['src'],
        apiDirectories: [],
        authIndicators: [],
        databaseIndicators: [],
        ciCdConfigFiles: [],
        dockerFiles: [],
        envFiles: [],
        configFiles: [],
        routesCount: 1,
        databaseTablesCount: 0,
        sourceFilesCount: 1,
        totalFilesCount: 5,
      },
      config: DEFAULT_CONFIG,
      options: { targetPath: process.cwd() + '/fixtures/clean-project' },
    };

    const findings = await analyzer.analyze(cleanContext);
    expect(findings).toHaveLength(0);
  });
});
