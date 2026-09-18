import { Finding } from '../core/types.js';
import { generateFingerprint } from '../core/fingerprint.js';
import { ApplicationGraph, CorrelatedIssue } from './types.js';

export function correlateGraphRisks(graph: ApplicationGraph, findings: Finding[]): Finding[] {
  const correlatedFindings: Finding[] = [];
  let corrIndex = 1;

  for (const route of graph.routes) {
    const routeFile = route.filePath;
    const routeFindings = findings.filter(f => f.file === routeFile || f.evidence.some(e => e.filePath === routeFile));

    const hasInput = route.inputs.length > 0;
    const hasDb = route.database === 'detected';
    const noAuth = route.authentication === 'not detected';
    const noAuthorization = route.authorization === 'not detected';
    const hasUnsafeDbFinding = routeFindings.some(f => f.id.includes('SQL') || f.category === 'Database');

    if (hasInput && hasDb && noAuthorization && (hasUnsafeDbFinding || noAuth)) {
      const corrId = `VBG-CORR-${String(corrIndex++).padStart(3, '0')}`;
      const chain = [
        `INPUT (${route.inputs.map(i => i.name).join(', ')})`,
        `DATABASE QUERY`,
        hasUnsafeDbFinding ? `STRING CONCATENATION / UNSEQUALIZED QUERY` : `PARAMETRIZATION UNVERIFIED`,
        `NO RESOURCE AUTHORIZATION`,
      ];

      const fingerprint = generateFingerprint(corrId, routeFile, 'Security', route.id);

      correlatedFindings.push({
        id: corrId,
        title: `Potential Insecure Endpoint Chain on ${route.method} ${route.path}`,
        category: 'Security',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        description: `Route '${route.method} ${route.path}' accepts untrusted user input and interacts with the database without detecting resource-level authorization checks.`,
        impact: 'An attacker may access, modify, or leak database records belonging to other users or execute unauthenticated operations.',
        evidence: [
          {
            filePath: routeFile,
            line: route.line || 1,
            snippet: `Route: ${route.method} ${route.path} | Chain: ${chain.join(' → ')}`,
          },
        ],
        file: routeFile,
        line: route.line || 1,
        remediation: 'Implement authentication middleware and resource-level authorization checks (e.g. verifying user ownership of target resource ID) before performing database operations.',
        references: ['https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/'],
        fingerprint,
      });
    }
  }

  return correlatedFindings;
}
