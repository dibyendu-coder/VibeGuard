import { describe, expect, it } from 'vitest';
import { ConfigAnalyzer } from '../src/analyzers/config-analyzer.js';
import { DEFAULT_CONFIG } from '../src/config/loader.js';
import { ScanContext } from '../src/core/types.js';

describe('ConfigAnalyzer', () => {
  const analyzer = new ConfigAnalyzer();

  it('positive: detects committed .env.production, localhost in prod, and debug mode', async () => {
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
        envFiles: ['.env.production'],
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
    expect(ruleIds).toContain('VBG-CONFIG-001'); // Committed .env.production
    expect(ruleIds).toContain('VBG-CONFIG-002'); // Localhost in production config
    expect(ruleIds).toContain('VBG-CONFIG-004'); // NEXT_PUBLIC_STRIPE_SECRET_KEY
  });

  it('positive: detects DEBUG = True in Python configuration', async () => {
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
    expect(ruleIds).toContain('VBG-CONFIG-003'); // DEBUG = True
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
