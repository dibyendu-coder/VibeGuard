import { describe, expect, it } from 'vitest';
import { DependencyAnalyzer } from '../src/analyzers/dependency-analyzer.js';
import { DEFAULT_CONFIG } from '../src/config/loader.js';
import { ScanContext } from '../src/core/types.js';

describe('DependencyAnalyzer', () => {
  const analyzer = new DependencyAnalyzer();

  it('builds dependency inventory and accurately flags missing lockfile', async () => {
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
    expect(nodeContext.manifest.dependencyInventory).toBeDefined();
    expect(nodeContext.manifest.dependencyInventory?.totalCount).toBeGreaterThan(0);
    expect(nodeContext.manifest.dependencyInventory?.advisoryStatus).toBe('NOT_CONFIGURED');

    const ruleIds = findings.map((f) => f.id);
    expect(ruleIds).toContain('VBG-DEP-001'); // Missing lockfile
  });

  it('correctly inventories lockfile with direct and transitive dependencies', async () => {
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
    expect(findings).toHaveLength(0); // Clean project has lockfile, no missing lockfile warning
    expect(cleanContext.manifest.dependencyInventory?.totalCount).toBeGreaterThan(0);
    expect(cleanContext.manifest.dependencyInventory?.directCount).toBeGreaterThan(0);
  });
});
