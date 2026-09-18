import { describe, expect, it } from 'vitest';
import { AuthAnalyzer } from '../src/analyzers/auth-analyzer.js';
import { DEFAULT_CONFIG } from '../src/config/loader.js';
import { ScanContext } from '../src/core/types.js';

describe('AuthAnalyzer', () => {
  const analyzer = new AuthAnalyzer();

  it('positive: detects client-side-only authorization boundary in Next.js page', async () => {
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
    expect(ruleIds).toContain('VBG-AUTH-001'); // Client-side role check
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
