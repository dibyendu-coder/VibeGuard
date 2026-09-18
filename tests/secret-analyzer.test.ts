import { describe, expect, it } from 'vitest';
import { SecretAnalyzer } from '../src/analyzers/secret-analyzer.js';
import { DEFAULT_CONFIG } from '../src/config/loader.js';
import { ScanContext } from '../src/core/types.js';

function createMockContext(files: { path: string; content: string }[]): ScanContext {
  const fileMap = new Map(files.map((f) => [f.path, f.content]));

  return {
    projectRoot: '/mock/project',
    manifest: {
      rootDir: '/mock/project',
      projectName: 'mock-project',
      languages: ['TypeScript'],
      frameworks: [],
      packageManifests: [],
      lockfiles: [],
      sourceDirectories: ['src'],
      apiDirectories: [],
      authIndicators: [],
      databaseIndicators: [],
      ciCdConfigFiles: [],
      dockerFiles: [],
      envFiles: [],
      configFiles: [],
      routesCount: 0,
      databaseTablesCount: 0,
      sourceFilesCount: files.length,
      totalFilesCount: files.length,
    },
    config: DEFAULT_CONFIG,
    options: { targetPath: '/mock/project' },
  };
}

describe('SecretAnalyzer', () => {
  const analyzer = new SecretAnalyzer();

  it('positive: detects live API keys, private keys, connection strings, and client-exposed secrets', async () => {
    // We mock getScanFiles via inline tests on analyzer
    const mockContext = createMockContext([]);
    // Test detection regexes directly through analyzer.analyze against a real fixture or mock
    const fixtureContext: ScanContext = {
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

    const findings = await analyzer.analyze(fixtureContext);
    expect(findings.length).toBeGreaterThan(0);

    const ruleIds = findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-SECRET-001'); // Stripe secret
    expect(ruleIds).toContain('VBG-SECRET-003'); // Database connection string
    expect(ruleIds).toContain('VBG-SECRET-005'); // Client-exposed secret
  });

  it('negative: produces zero findings for clean project', async () => {
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
        totalFilesCount: 4,
      },
      config: DEFAULT_CONFIG,
      options: { targetPath: process.cwd() + '/fixtures/clean-project' },
    };

    const findings = await analyzer.analyze(cleanContext);
    expect(findings).toHaveLength(0);
  });

  it('false-positive reduction: ignores obvious placeholders like your_api_key_here', async () => {
    // Verified by running against clean project containing standard strings
    const findings = await analyzer.analyze({
      projectRoot: process.cwd() + '/fixtures/clean-project',
      manifest: {
        rootDir: process.cwd() + '/fixtures/clean-project',
        projectName: 'clean-project',
        languages: [],
        frameworks: [],
        packageManifests: [],
        lockfiles: [],
        sourceDirectories: [],
        apiDirectories: [],
        authIndicators: [],
        databaseIndicators: [],
        ciCdConfigFiles: [],
        dockerFiles: [],
        envFiles: [],
        configFiles: [],
        routesCount: 0,
        databaseTablesCount: 0,
        sourceFilesCount: 0,
        totalFilesCount: 0,
      },
      config: DEFAULT_CONFIG,
      options: { targetPath: process.cwd() + '/fixtures/clean-project' },
    });
    expect(findings).toHaveLength(0);
  });

  it('secret redaction: never exposes full secret in evidence or snippets', async () => {
    const fixtureContext: ScanContext = {
      projectRoot: process.cwd() + '/fixtures/vulnerable-nextjs',
      manifest: {
        rootDir: process.cwd() + '/fixtures/vulnerable-nextjs',
        projectName: 'vulnerable-nextjs',
        languages: ['TypeScript'],
        frameworks: [],
        packageManifests: [],
        lockfiles: [],
        sourceDirectories: [],
        apiDirectories: [],
        authIndicators: [],
        databaseIndicators: [],
        ciCdConfigFiles: [],
        dockerFiles: [],
        envFiles: ['.env.production'],
        configFiles: [],
        routesCount: 0,
        databaseTablesCount: 0,
        sourceFilesCount: 0,
        totalFilesCount: 0,
      },
      config: DEFAULT_CONFIG,
      options: { targetPath: process.cwd() + '/fixtures/vulnerable-nextjs' },
    };

    const findings = await analyzer.analyze(fixtureContext);
    for (const f of findings) {
      for (const ev of f.evidence) {
        expect(ev.snippet).not.toContain('fake99998888777766665555444433332222');
        expect(ev.snippet).not.toContain('fakePasswordSecret123');
        expect(ev.snippet).toContain('****');
      }
    }
  });
});
