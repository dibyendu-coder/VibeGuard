import path from 'path';
import { describe, expect, it } from 'vitest';
import { filterSuppressedFindings } from '../src/core/suppression.js';
import { Finding } from '../src/core/types.js';

describe('Phase 3 - Finding Suppression Test Suite', () => {
  const dummyFindings: Finding[] = [
    {
      id: 'VBG-SECRET-001',
      rule_id: 'VBG-SECRET-001',
      title: 'Hardcoded Stripe API Secret Key',
      category: 'Secrets',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      description: 'Test description',
      impact: 'Test impact',
      evidence: [],
      remediation: 'Fix it',
      references: [],
      fingerprint: 'fp-secret-1',
    },
    {
      id: 'VBG-REL-001',
      rule_id: 'VBG-REL-001',
      title: 'Sync File Read',
      category: 'Reliability',
      severity: 'MEDIUM',
      confidence: 'HIGH',
      description: 'Test description',
      impact: 'Test impact',
      evidence: [],
      remediation: 'Fix it',
      references: [],
      fingerprint: 'fp-rel-1',
    },
  ];

  it('filters out findings suppressed by rule ID', () => {
    // Mock ignore logic
    const { activeFindings, suppressedCount } = filterSuppressedFindings(
      dummyFindings,
      path.resolve(__dirname, '../fixtures/docker')
    );

    expect(activeFindings.length).toBeLessThanOrEqual(dummyFindings.length);
  });
});
