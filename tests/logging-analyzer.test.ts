import { describe, expect, it } from 'vitest';
import { LoggingAnalyzer } from '../src/analyzers/logging-analyzer.js';
import { DEFAULT_CONFIG } from '../src/config/loader.js';
import { ScanContext } from '../src/core/types.js';

describe('LoggingAnalyzer', () => {
  const analyzer = new LoggingAnalyzer();

  it('positive: detects sensitive token logging and process.env dump in nextjs auth route', async () => {
    const nextjsContext: ScanContext = {
      projectRoot: process.cwd() + '/fixtures/vulnerable-nextjs',
      manifest: {
        rootDir: process.cwd() + '/fixtures/vulnerable-nextjs',
        projectName: 'vulnerable-nextjs',
        languages: ['TypeScript'],
        frameworks: [],
        packageManifests: ['package.json'],
        lockfiles: [],
        sourceDirectories: ['app'],
        apiDirectories: ['app/api'],
        authIndicators: [],
        databaseIndicators: [],
        ciCdConfigFiles: [],
        dockerFiles: [],
        envFiles: [],
        configFiles: [],
        routesCount: 2,
        databaseTablesCount: 0,
        sourceFilesCount: 4,
        totalFilesCount: 5,
      },
      config: DEFAULT_CONFIG,
      options: { targetPath: process.cwd() + '/fixtures/vulnerable-nextjs' },
    };

    const findings = await analyzer.analyze(nextjsContext);
    const ruleIds = findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-LOG-001'); // Token logging
    expect(ruleIds).toContain('VBG-LOG-003'); // Dumping process.env
  });

  it('positive: detects stack trace returned to client in node error handler', async () => {
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
    expect(ruleIds).toContain('VBG-LOG-002'); // Stack trace returned to client
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
