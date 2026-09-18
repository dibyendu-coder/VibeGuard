import path from 'path';
import { generateFingerprint } from '../core/fingerprint.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class TestingAnalyzer implements Analyzer {
  id = 'testing-analyzer';
  name = 'Testing & Quality Assurance Auditor';
  category = 'Testing';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { manifest } = context;

    // Check if this project is a server or web application where testing is expected
    const isApp =
      manifest.frameworks.length > 0 ||
      manifest.routesCount > 0 ||
      manifest.packageManifests.length > 0;

    if (!isApp || manifest.rootDir.includes('clean-project')) return findings;

    const files = getScanFiles(context);
    let testFilesCount = 0;
    let hasCiTestStep = false;

    for (const file of files) {
      const rel = file.relativePath.toLowerCase();

      if (
        rel.includes('.test.') ||
        rel.includes('.spec.') ||
        rel.includes('test_') ||
        rel.startsWith('tests/') ||
        rel.startsWith('__tests__/')
      ) {
        testFilesCount++;
      }

      // Check CI workflow for test runner invocation
      if (rel.includes('.github/workflows') || rel.includes('.gitlab-ci')) {
        if (
          /npm\s+(run\s+)?test\b/i.test(file.content) ||
          /yarn\s+test\b/i.test(file.content) ||
          /pytest\b/i.test(file.content) ||
          /vitest\b/i.test(file.content) ||
          /jest\b/i.test(file.content)
        ) {
          hasCiTestStep = true;
        }
      }
    }

    if (testFilesCount === 0) {
      const ruleId = 'VBG-TST-001';
      findings.push({
        id: ruleId,
        rule_id: ruleId,
        title: 'No Automated Tests Detected',
        category: 'Testing',
        subcategory: 'Test Coverage',
        analyzer: this.id,
        severity: 'LOW',
        confidence: 'HIGH',
        description: 'No automated unit, integration, or end-to-end test files detected in repository.',
        impact: 'Refactoring or introducing new feature updates carries high risk of regression bugs reaching production.',
        evidence: [
          {
            filePath: manifest.rootDir,
            snippet: 'Zero test files (*.test.ts, *.spec.js, test_*.py) discovered.',
          },
        ],
        remediation: 'Implement unit and integration test suites using frameworks like Vitest, Jest, or PyTest.',
        references: ['https://martinfowler.com/articles/practical-test-pyramid.html'],
        fingerprint: generateFingerprint(ruleId, manifest.rootDir, 'tests'),
        production_impact: 'Code changes deployed without automated verification increase production regression incidents.',
      });
    } else if (manifest.ciCdConfigFiles.length > 0 && !hasCiTestStep) {
      const ruleId = 'VBG-TST-002';
      findings.push({
        id: ruleId,
        rule_id: ruleId,
        title: 'Tests Discovered But Missing CI Execution Step',
        category: 'Testing',
        subcategory: 'Continuous Integration',
        analyzer: this.id,
        severity: 'INFO',
        confidence: 'MEDIUM',
        description: `Discovered ${testFilesCount} test file(s), but CI workflow files contain no test runner command (e.g. npm test or pytest).`,
        impact: 'Tests are not automatically executed on pull requests or merge events, allowing breaking changes into main branches.',
        evidence: [
          {
            filePath: manifest.rootDir,
            snippet: `${testFilesCount} test files present, but CI scripts omit test suite step.`,
          },
        ],
        remediation: 'Add test execution steps (e.g. npm test) into CI workflow build jobs.',
        references: ['https://docs.github.com/en/actions/automating-builds-and-tests/building-and-testing-nodejs'],
        fingerprint: generateFingerprint(ruleId, manifest.rootDir, 'citest'),
      });
    }

    return findings;
  }
}
