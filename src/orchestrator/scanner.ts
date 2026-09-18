import path from 'path';
import { ApiSecurityAnalyzer } from '../analyzers/api-security-analyzer.js';
import { AuthAnalyzer } from '../analyzers/auth-analyzer.js';
import { AuthSecurityAnalyzer } from '../analyzers/auth-security-analyzer.js';
import { AuthorizationAnalyzer } from '../analyzers/authorization-analyzer.js';
import { Analyzer } from '../analyzers/base.js';
import { CommandInjectionAnalyzer } from '../analyzers/command-injection-analyzer.js';
import { ConfigAnalyzer } from '../analyzers/config-analyzer.js';
import { CorsSecurityAnalyzer } from '../analyzers/cors-security-analyzer.js';
import { DataExposureAnalyzer } from '../analyzers/data-exposure-analyzer.js';
import { DependencyAnalyzer } from '../analyzers/dependency-analyzer.js';
import { DeploymentAnalyzer } from '../analyzers/deployment-analyzer.js';
import { ErrorDisclosureAnalyzer } from '../analyzers/error-disclosure-analyzer.js';
import { HeadersSecurityAnalyzer } from '../analyzers/headers-security-analyzer.js';
import { LoggingAnalyzer } from '../analyzers/logging-analyzer.js';
import { MisconfigEngine } from '../analyzers/misconfig-engine.js';
import { ObservabilityAnalyzer } from '../analyzers/observability-analyzer.js';
import { PathTraversalAnalyzer } from '../analyzers/path-traversal-analyzer.js';
import { ReliabilityAnalyzer } from '../analyzers/reliability-analyzer.js';
import { SecretAnalyzer } from '../analyzers/secret-analyzer.js';
import { SqlInjectionAnalyzer } from '../analyzers/sql-injection-analyzer.js';
import { SsrfAnalyzer } from '../analyzers/ssrf-analyzer.js';
import { TestingAnalyzer } from '../analyzers/testing-analyzer.js';
import { UnsafeCodeAnalyzer } from '../analyzers/unsafe-code-analyzer.js';
import { getScanFiles } from '../analyzers/utils.js';
import { XssAnalyzer } from '../analyzers/xss-analyzer.js';

import { loadConfig } from '../config/loader.js';
import { filterFindingsWithBaseline, loadBaseline } from '../core/baseline.js';
import { filterSuppressedFindings } from '../core/suppression.js';
import {
  AnalyzerStatus,
  Finding,
  ScanContext,
  ScanOptions,
  ScanResult,
  Severity,
} from '../core/types.js';
import { discoverProject } from '../discovery/detector.js';
import { buildApplicationGraph } from '../graph/builder.js';
import { correlateGraphRisks } from '../graph/correlation.js';
import { analyzeDataFlows } from '../graph/flow-analyzer.js';
import { discoverRoutes } from '../graph/route-analyzer.js';
import { calculateExplainableScores } from '../scoring/engine.js';

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

export function computeExitCode(findings: Finding[], failThreshold: Severity): number {
  if (findings.length === 0) {
    return 0; // Clean
  }

  const thresholdRank = SEVERITY_RANK[failThreshold] ?? 3; // default HIGH = 3
  const hasBlockingFinding = findings.some(
    (f) => (SEVERITY_RANK[f.severity] ?? 0) >= thresholdRank
  );

  if (hasBlockingFinding) {
    return 2; // Policy failure threshold exceeded
  }

  return 1; // Findings exist but below fail threshold
}

export function getDefaultAnalyzers(): Analyzer[] {
  return [
    new SecretAnalyzer(),
    new ConfigAnalyzer(),
    new DependencyAnalyzer(),
    new ApiSecurityAnalyzer(),
    new AuthAnalyzer(),
    new UnsafeCodeAnalyzer(),
    new LoggingAnalyzer(),
    new SqlInjectionAnalyzer(),
    new CommandInjectionAnalyzer(),
    new PathTraversalAnalyzer(),
    new SsrfAnalyzer(),
    new XssAnalyzer(),
    new AuthorizationAnalyzer(),
    new AuthSecurityAnalyzer(),
    new CorsSecurityAnalyzer(),
    new HeadersSecurityAnalyzer(),
    new ErrorDisclosureAnalyzer(),
    new MisconfigEngine(),
    new ReliabilityAnalyzer(),
    new ObservabilityAnalyzer(),
    new DeploymentAnalyzer(),
    new TestingAnalyzer(),
    new DataExposureAnalyzer(),
  ];
}

export interface RunScanCallbacks {
  onDiscoveryComplete?: (manifest: any) => void;
  onAnalyzerStart?: (analyzer: Analyzer) => void;
  onAnalyzerComplete?: (analyzer: Analyzer, findings: Finding[]) => void;
  onAnalyzerFail?: (analyzer: Analyzer, error: any) => void;
}

export async function runScan(
  options: ScanOptions,
  customAnalyzers?: Analyzer[],
  callbacks?: RunScanCallbacks
): Promise<ScanResult> {
  const startTime = Date.now();

  const config = loadConfig(options.targetPath);
  const manifest = discoverProject(options.targetPath, config);

  if (callbacks?.onDiscoveryComplete) {
    callbacks.onDiscoveryComplete(manifest);
  }

  const context: ScanContext = {
    projectRoot: manifest.rootDir,
    manifest,
    config,
    options,
  };

  // Discover files for Graph construction
  const fileEntries = getScanFiles(context);
  const filePaths = fileEntries.map((f) => f.filePath);

  // Discover routes
  const routes = discoverRoutes(filePaths, manifest.rootDir);

  // Build application graph if deep mode is enabled or for deep route summary
  const appGraph = buildApplicationGraph(filePaths, manifest.rootDir);
  const dataFlows = analyzeDataFlows(filePaths, manifest.rootDir);

  context.appGraph = appGraph;
  context.routes = routes;

  const analyzersToRun = customAnalyzers ?? getDefaultAnalyzers();
  let findings: Finding[] = [];
  const analyzerStatuses: AnalyzerStatus[] = [];

  for (const analyzer of analyzersToRun) {
    const analyzerStart = Date.now();
    if (callbacks?.onAnalyzerStart) {
      callbacks.onAnalyzerStart(analyzer);
    }

    try {
      const analyzerFindings = await analyzer.analyze(context);
      findings.push(...analyzerFindings);

      analyzerStatuses.push({
        id: analyzer.id,
        name: analyzer.name,
        category: analyzer.category,
        status: 'completed',
        findingsCount: analyzerFindings.length,
        durationMs: Date.now() - analyzerStart,
      });

      if (callbacks?.onAnalyzerComplete) {
        callbacks.onAnalyzerComplete(analyzer, analyzerFindings);
      }
    } catch (err: any) {
      const errorMsg = err?.message || String(err);
      console.warn(`[VibeGuard] Warning: Analyzer '${analyzer.name}' (${analyzer.id}) failed:`, errorMsg);

      analyzerStatuses.push({
        id: analyzer.id,
        name: analyzer.name,
        category: analyzer.category,
        status: 'failed',
        findingsCount: 0,
        durationMs: Date.now() - analyzerStart,
        error: errorMsg,
      });

      if (callbacks?.onAnalyzerFail) {
        callbacks.onAnalyzerFail(analyzer, err);
      }
    }
  }

  // Correlate findings with graph
  const correlatedFindings = correlateGraphRisks(appGraph, findings);
  findings.push(...correlatedFindings);

  // Deduplicate findings by fingerprint
  const uniqueFindingsMap = new Map<string, Finding>();
  for (const f of findings) {
    if (!uniqueFindingsMap.has(f.fingerprint)) {
      uniqueFindingsMap.set(f.fingerprint, f);
    }
  }
  let deduplicatedFindings = Array.from(uniqueFindingsMap.values());

  // Apply .vibeguardignore and inline comment suppressions
  const suppression = filterSuppressedFindings(deduplicatedFindings, manifest.rootDir);
  deduplicatedFindings = suppression.activeFindings;

  // Category filter
  if (options.category) {
    const targetCat = options.category.toLowerCase();
    deduplicatedFindings = deduplicatedFindings.filter(
      (f) => f.category.toLowerCase() === targetCat
    );
  }

  // Severity filter
  if (options.severity) {
    const targetSevRank = SEVERITY_RANK[options.severity] ?? 0;
    deduplicatedFindings = deduplicatedFindings.filter(
      (f) => SEVERITY_RANK[f.severity] >= targetSevRank
    );
  }

  // Baseline filtering
  let baselineStatus: any = undefined;
  if (options.baseline) {
    const baselineSet = loadBaseline(options.baseline);
    if (baselineSet) {
      const totalBefore = deduplicatedFindings.length;
      const { newFindings, existingCount } = filterFindingsWithBaseline(
        deduplicatedFindings,
        baselineSet
      );
      baselineStatus = {
        baselinePath: options.baseline,
        totalFindings: totalBefore,
        newFindings: newFindings.length,
        suppressedFindings: existingCount + suppression.suppressedCount,
      };
      deduplicatedFindings = newFindings;
    }
  } else if (suppression.suppressedCount > 0) {
    baselineStatus = {
      totalFindings: deduplicatedFindings.length + suppression.suppressedCount,
      newFindings: deduplicatedFindings.length,
      suppressedFindings: suppression.suppressedCount,
    };
  }

  const scores = calculateExplainableScores(deduplicatedFindings);
  const exitCode = computeExitCode(deduplicatedFindings, config.failThreshold);
  const durationMs = Date.now() - startTime;

  return {
    version: '0.1.0',
    timestamp: new Date().toISOString(),
    durationMs,
    targetPath: manifest.rootDir,
    manifest,
    findings: deduplicatedFindings,
    scores,
    analyzerStatuses,
    exitCode,
    routes,
    correlatedFindings,
    graphSummary: {
      routesCount: routes.length,
      modulesCount: appGraph.modulesCount,
      externalCallsCount: appGraph.externalCallsCount,
      databaseOpsCount: appGraph.databaseOpsCount,
    },
    baselineStatus,
  };
}
