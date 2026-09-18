import { describe, expect, it } from 'vitest';
import { Finding } from '../src/core/types.js';
import { calculateExplainableScores } from '../src/scoring/engine.js';

describe('Explainable Scoring Engine', () => {
  it('returns perfect 100 score and READY status when findings array is empty', () => {
    const scores = calculateExplainableScores([]);
    expect(scores.overallScore).toBe(100);
    expect(scores.securityScore).toBe(100);
    expect(scores.reliabilityScore).toBe(100);
    expect(scores.configScore).toBe(100);
    expect(scores.dependencyScore).toBe(100);
    expect(scores.architectureScore).toBe(100);
    expect(scores.productionScore).toBe(100);
    expect(scores.status).toBe('READY');
    expect(scores.criticalCount).toBe(0);
    expect(scores.highCount).toBe(0);
  });

  it('accurately computes itemized contributors and changes status to NOT_READY on CRITICAL finding', () => {
    const criticalFinding: Finding = {
      id: 'VBG-SECRET-001',
      title: 'Hardcoded API Key',
      category: 'Secrets',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      description: 'Test secret',
      impact: 'High impact',
      evidence: [],
      remediation: 'Rotate key',
      references: [],
      fingerprint: 'test-fp-1',
    };

    const scores = calculateExplainableScores([criticalFinding]);
    expect(scores.criticalCount).toBe(1);
    expect(scores.status).toBe('NOT_READY');
    expect(scores.securityScore).toBe(80); // 100 - 20
    expect(scores.explanations.Security).toHaveLength(1);
    expect(scores.explanations.Security[0].ruleId).toBe('VBG-SECRET-001');
    expect(scores.explanations.Security[0].deduction).toBe(20);
  });

  it('scales score deductions by confidence level', () => {
    const highMedConfFinding: Finding = {
      id: 'VBG-API-001',
      title: 'Potential IDOR',
      category: 'API',
      severity: 'HIGH',
      confidence: 'MEDIUM', // 10 base * 0.8 = 8 pts
      description: 'Test api',
      impact: 'Medium impact',
      evidence: [],
      remediation: 'Check owner',
      references: [],
      fingerprint: 'test-fp-2',
    };

    const scores = calculateExplainableScores([highMedConfFinding]);
    expect(scores.architectureScore).toBe(92); // 100 - 8
    expect(scores.explanations.Architecture[0].deduction).toBe(8);
  });
});
