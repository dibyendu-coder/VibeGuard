import { ScanResult } from '../core/types.js';

export function renderJsonReport(result: ScanResult): string {
  const structuredOutput = {
    project: {
      name: result.manifest.projectName,
      root: result.manifest.rootDir,
      sourceFilesCount: result.manifest.sourceFilesCount,
      totalFilesCount: result.manifest.totalFilesCount,
      routesCount: result.manifest.routesCount,
      sourceDirectories: result.manifest.sourceDirectories,
      apiDirectories: result.manifest.apiDirectories,
    },
    scanMetadata: {
      version: result.version,
      timestamp: result.timestamp,
      durationMs: result.durationMs,
      targetPath: result.targetPath,
      exitCode: result.exitCode,
    },
    detectedTechnologies: {
      languages: result.manifest.languages,
      frameworks: result.manifest.frameworks,
      packageManager: result.manifest.packageManager,
      hasLockfile: result.manifest.hasLockfile,
      authIndicators: result.manifest.authIndicators,
      databaseIndicators: result.manifest.databaseIndicators,
      ciCdConfigFiles: result.manifest.ciCdConfigFiles,
      dockerFiles: result.manifest.dockerFiles,
    },
    dependencyInventory: result.manifest.dependencyInventory ?? {
      totalCount: 0,
      directCount: 0,
      transitiveCount: 0,
      dependencies: [],
      advisoryStatus: 'NOT_CONFIGURED',
    },
    routes: result.routes || [],
    graphSummary: result.graphSummary,
    baselineStatus: result.baselineStatus,
    findings: result.findings,
    scores: result.scores,
    analyzerStatus: result.analyzerStatuses,
    summary: {
      status: result.scores.status,
      overallScore: result.scores.overallScore,
      criticalCount: result.scores.criticalCount,
      highCount: result.scores.highCount,
      mediumCount: result.scores.mediumCount,
      lowCount: result.scores.lowCount,
      infoCount: result.scores.infoCount,
    },
  };

  // Strip any accidental ANSI control sequences
  const cleanResult = JSON.parse(
    JSON.stringify(structuredOutput, (_key, value) => {
      if (typeof value === 'string') {
        return value.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');
      }
      return value;
    })
  );

  return JSON.stringify(cleanResult, null, 2);
}
