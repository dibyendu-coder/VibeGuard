import {
  Confidence,
  Finding,
  ReadinessStatus,
  ScoreContribution,
  ScoreResult,
  Severity,
} from '../core/types.js';

const SEVERITY_BASE_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 20,
  HIGH: 10,
  MEDIUM: 5,
  LOW: 2,
  INFO: 0,
};

const CONFIDENCE_MULTIPLIERS: Record<Confidence, number> = {
  HIGH: 1.0,
  MEDIUM: 0.8,
  LOW: 0.5,
};

export function calculateDeduction(severity: Severity, confidence: Confidence): number {
  const base = SEVERITY_BASE_WEIGHTS[severity] ?? 0;
  const mult = CONFIDENCE_MULTIPLIERS[confidence] ?? 1.0;
  return Math.round(base * mult);
}

export function calculateExplainableScores(findings: Finding[]): ScoreResult {
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let infoCount = 0;

  const deductions: Record<string, number> = {
    Security: 0,
    Reliability: 0,
    Configuration: 0,
    Dependencies: 0,
    Architecture: 0,
    Production: 0,
  };

  const explanations: Record<string, ScoreContribution[]> = {
    Security: [],
    Reliability: [],
    Configuration: [],
    Dependencies: [],
    Architecture: [],
    Production: [],
  };

  for (const finding of findings) {
    switch (finding.severity) {
      case 'CRITICAL':
        criticalCount++;
        break;
      case 'HIGH':
        highCount++;
        break;
      case 'MEDIUM':
        mediumCount++;
        break;
      case 'LOW':
        lowCount++;
        break;
      case 'INFO':
        infoCount++;
        break;
    }

    const points = calculateDeduction(finding.severity, finding.confidence);
    if (points === 0) continue;

    const contrib: ScoreContribution = {
      ruleId: finding.id,
      title: finding.title,
      category: finding.category,
      deduction: points,
      severity: finding.severity,
      confidence: finding.confidence,
    };

    // Attribute to primary score categories
    if (
      finding.category === 'Secrets' ||
      finding.category === 'Security' ||
      finding.category === 'Authentication' ||
      finding.category === 'Authorization' ||
      finding.category === 'Privacy'
    ) {
      deductions.Security += points;
      explanations.Security.push(contrib);
    }

    if (finding.category === 'Configuration') {
      deductions.Configuration += points;
      explanations.Configuration.push(contrib);
    }

    if (finding.category === 'Dependencies') {
      deductions.Dependencies += points;
      explanations.Dependencies.push(contrib);
    }

    if (finding.category === 'API' || finding.category === 'Database' || finding.category === 'Authorization') {
      deductions.Architecture += points;
      explanations.Architecture.push(contrib);
    }

    if (
      finding.category === 'Reliability' ||
      (finding.category === 'Security' && (finding.id === 'VBG-CODE-001' || finding.id === 'VBG-CODE-006'))
    ) {
      deductions.Reliability += points;
      explanations.Reliability.push(contrib);
    }

    // Production readiness is affected by configuration, critical/high security, and unpinned dependencies
    if (
      finding.category === 'Configuration' ||
      finding.severity === 'CRITICAL' ||
      finding.severity === 'HIGH'
    ) {
      const prodPoints = Math.round(points * 0.75);
      deductions.Production += prodPoints;
      explanations.Production.push({
        ...contrib,
        deduction: prodPoints,
      });
    }
  }

  const securityScore = Math.max(0, 100 - deductions.Security);
  const reliabilityScore = Math.max(0, 100 - deductions.Reliability);
  const configScore = Math.max(0, 100 - deductions.Configuration);
  const dependencyScore = Math.max(0, 100 - deductions.Dependencies);
  const architectureScore = Math.max(0, 100 - deductions.Architecture);
  const productionScore = Math.max(0, 100 - deductions.Production);

  const overallScore = Math.round(
    securityScore * 0.3 +
      productionScore * 0.2 +
      configScore * 0.15 +
      architectureScore * 0.15 +
      dependencyScore * 0.1 +
      reliabilityScore * 0.1
  );

  let status: ReadinessStatus = 'READY';
  if (criticalCount > 0 || highCount > 2 || overallScore < 70) {
    status = 'NOT_READY';
  } else if (highCount > 0 || mediumCount > 3 || overallScore < 85) {
    status = 'NEEDS_ATTENTION';
  }

  // Compute status-based dimensions for Phase 3 UI summary
  const securityDimension = securityScore >= 90 ? 'READY' : securityScore >= 70 ? 'NEEDS_ATTENTION' : 'NOT_READY';
  const reliabilityDimension = reliabilityScore >= 90 ? 'GOOD' : reliabilityScore >= 75 ? 'NEEDS_ATTENTION' : 'LIMITED';
  const configDimension = configScore >= 90 ? 'GOOD' : configScore >= 75 ? 'NEEDS_ATTENTION' : 'INSECURE';
  const dependencyDimension = dependencyScore >= 90 ? 'GOOD' : dependencyScore >= 75 ? 'REVIEW' : 'OUTDATED';
  
  // Deployment & Observability & Testing specific finding checks
  const depFindings = findings.filter((f) => f.category === 'Deployment');
  const obsFindings = findings.filter((f) => f.category === 'Observability');
  const tstFindings = findings.filter((f) => f.category === 'Testing');

  const deploymentDimension = depFindings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    ? 'RISKY'
    : depFindings.length > 0
    ? 'LIMITED'
    : 'GOOD';

  const observabilityDimension = obsFindings.some((f) => f.severity === 'HIGH')
    ? 'MISSING'
    : obsFindings.length > 0
    ? 'LIMITED'
    : 'GOOD';

  const testingDimension = tstFindings.some((f) => f.id === 'VBG-TST-001')
    ? 'NONE'
    : tstFindings.length > 0
    ? 'LIMITED'
    : 'GOOD';

  return {
    overallScore,
    securityScore,
    reliabilityScore,
    configScore,
    dependencyScore,
    architectureScore,
    productionScore,
    status,
    categoryScores: [
      { category: 'Secrets', score: securityScore, findingsCount: explanations.Security.length },
      { category: 'Reliability', score: reliabilityScore, findingsCount: explanations.Reliability.length },
      { category: 'Configuration', score: configScore, findingsCount: explanations.Configuration.length },
      { category: 'Dependencies', score: dependencyScore, findingsCount: explanations.Dependencies.length },
      { category: 'Production', score: productionScore, findingsCount: explanations.Production.length },
    ],
    explanations,
    readinessDimensions: {
      security: securityDimension,
      reliability: reliabilityDimension,
      configuration: configDimension,
      dependencies: dependencyDimension,
      deployment: deploymentDimension,
      observability: observabilityDimension,
      testing: testingDimension,
    },
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
  };
}
