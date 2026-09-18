export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type Category =
  | 'Secrets'
  | 'Authentication'
  | 'Authorization'
  | 'API'
  | 'Database'
  | 'Configuration'
  | 'Dependencies'
  | 'Reliability'
  | 'Privacy'
  | 'Production'
  | 'Security'
  | 'Deployment'
  | 'Observability'
  | 'Testing'
  | 'Data Safety';

export interface Evidence {
  filePath: string;
  line?: number;
  column?: number;
  snippet?: string;
  isSecretMasked?: boolean;
}

export interface DataFlowStep {
  file: string;
  line: number;
  type: 'source' | 'transform' | 'sink';
  description: string;
}

export interface Finding {
  id: string; // e.g. VBG-SECRET-001
  rule_id?: string;
  title: string;
  category: Category;
  subcategory?: string;
  analyzer?: string;
  severity: Severity;
  confidence: Confidence;
  exploitability?: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  impact: string;
  evidence: Evidence[];
  file?: string;
  line?: number;
  remediation: string;
  references: string[];
  fingerprint: string;
  affected_route?: string;
  affected_component?: string;
  data_flow?: DataFlowStep[];
  related_findings?: string[];
  tags?: string[];
  production_impact?: string;
  confidence_reason?: string;
  detection_reason?: string;
}

export interface DetectedFramework {
  name: string;
  version?: string;
  confidence: Confidence;
  evidence: string;
}

export interface DependencyItem {
  name: string;
  version?: string;
  type: 'direct' | 'transitive';
  sourceFile: string;
}

export interface DependencyInventory {
  totalCount: number;
  directCount: number;
  transitiveCount: number;
  dependencies: DependencyItem[];
  advisoryStatus: 'NOT_CONFIGURED' | 'CONFIGURED';
}

export interface ProjectManifest {
  rootDir: string;
  projectName: string;
  languages: string[];
  frameworks: DetectedFramework[];
  packageManager?: string;
  hasLockfile: boolean;
  packageManifests: string[];
  lockfiles: string[];
  sourceDirectories: string[];
  apiDirectories: string[];
  authIndicators: string[];
  databaseIndicators: string[];
  ciCdConfigFiles: string[];
  dockerFiles: string[];
  envFiles: string[];
  configFiles: string[];
  routesCount: number;
  databaseTablesCount: number;
  sourceFilesCount: number;
  totalFilesCount: number;
  dependencyInventory?: DependencyInventory;
}

export interface VibeGuardConfig {
  ignoredPaths: string[];
  failThreshold: Severity;
  enabledRules?: string[];
  disabledRules?: string[];
  privacy: {
    telemetry: boolean;
    aiOptIn: boolean;
  };
}

export interface ScanOptions {
  targetPath: string;
  json?: boolean;
  noColor?: boolean;
  noBanner?: boolean;
  deep?: boolean;
  security?: boolean;
  production?: boolean;
  category?: string;
  severity?: Severity;
  sarif?: boolean;
  baseline?: string;
}

export interface ScanContext {
  projectRoot: string;
  manifest: ProjectManifest;
  config: VibeGuardConfig;
  options: ScanOptions;
  appGraph?: any;
  routes?: any[];
}

export interface ScoreContribution {
  ruleId: string;
  title: string;
  category: string;
  deduction: number;
  severity: Severity;
  confidence: Confidence;
}

export interface CategoryScore {
  category: Category;
  score: number; // 0-100
  findingsCount: number;
}

export type ReadinessStatus = 'READY' | 'NEEDS_ATTENTION' | 'NOT_READY';
export type DimensionStatus = 'READY' | 'GOOD' | 'NEEDS_ATTENTION' | 'NOT_READY' | 'REVIEW' | 'LIMITED' | 'MISSING' | 'RISKY' | 'INSECURE' | 'NONE' | 'OUTDATED' | 'UNKNOWN';

export interface ProductionReadinessDimensions {
  security: DimensionStatus;
  reliability: DimensionStatus;
  configuration: DimensionStatus;
  dependencies: DimensionStatus;
  deployment: DimensionStatus;
  observability: DimensionStatus;
  testing: DimensionStatus;
  apiReadiness?: DimensionStatus;
  dataSafety?: DimensionStatus;
}

export interface ScoreResult {
  overallScore: number;
  securityScore: number;
  reliabilityScore: number;
  configScore: number;
  dependencyScore: number;
  architectureScore: number;
  productionScore: number;
  status: ReadinessStatus;
  categoryScores: CategoryScore[];
  explanations: Record<string, ScoreContribution[]>;
  readinessDimensions?: ProductionReadinessDimensions;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
}

export type AnalyzerExecutionStatus = 'detected' | 'suspected' | 'skipped' | 'unavailable' | 'completed' | 'failed';

export interface AnalyzerStatus {
  id: string;
  name: string;
  category: string;
  status: AnalyzerExecutionStatus;
  findingsCount: number;
  durationMs: number;
  error?: string;
}

export interface ScanResult {
  version: string;
  timestamp: string;
  durationMs: number;
  targetPath: string;
  manifest: ProjectManifest;
  findings: Finding[];
  scores: ScoreResult;
  analyzerStatuses: AnalyzerStatus[];
  exitCode: number;
  routes?: any[];
  correlatedFindings?: any[];
  graphSummary?: {
    routesCount: number;
    modulesCount: number;
    externalCallsCount: number;
    databaseOpsCount: number;
  };
  baselineStatus?: {
    baselinePath?: string;
    totalFindings: number;
    newFindings: number;
    suppressedFindings: number;
  };
}

