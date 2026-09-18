import path from 'path';
import { generateFingerprint } from '../core/fingerprint.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class DeploymentAnalyzer implements Analyzer {
  id = 'deployment-analyzer';
  name = 'Deployment & Container Auditor';
  category = 'Deployment';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getScanFiles(context);

    for (const file of files) {
      const fileName = path.basename(file.filePath);
      const isDockerfile = fileName.toLowerCase().includes('dockerfile');
      const isCompose = fileName.toLowerCase().includes('docker-compose') || fileName.toLowerCase().includes('compose.yaml');
      const isCiWorkflow = file.relativePath.includes('.github/workflows') || file.relativePath.includes('.gitlab-ci');

      // 1. Dockerfile Analysis
      if (isDockerfile) {
        let hasUserDirective = false;
        let hasHealthcheck = false;

        file.lines.forEach((lineText, idx) => {
          const lineNum = idx + 1;

          if (/^USER\s+/.test(lineText.trim())) {
            hasUserDirective = true;
            if (/^USER\s+(root|0)\b/i.test(lineText.trim())) {
              const ruleId = 'VBG-DEP-001';
              findings.push({
                id: ruleId,
                rule_id: ruleId,
                title: 'Container Configured to Run as Root User',
                category: 'Deployment',
                subcategory: 'Container Security',
                analyzer: this.id,
                severity: 'HIGH',
                confidence: 'HIGH',
                description: 'Dockerfile explicitly configures process execution under the privileged root user.',
                impact: 'Container breakouts or web application command injections grant full root access on container host.',
                evidence: [{ filePath: file.relativePath, line: lineNum, snippet: lineText.trim() }],
                file: file.relativePath,
                line: lineNum,
                remediation: 'Create and switch to a non-root system user (e.g. USER node or USER appuser).',
                references: ['https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user'],
                fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
                production_impact: 'Attacker compromising application acquires host root access via container escape.',
              });
            }
          }

          if (/^HEALTHCHECK\s+/.test(lineText.trim())) {
            hasHealthcheck = true;
          }

          if (/^FROM\s+[\w./-]+:(latest)\b/i.test(lineText.trim())) {
            const ruleId = 'VBG-DEP-002';
            findings.push({
              id: ruleId,
              rule_id: ruleId,
              title: 'Unpinned Floating Docker Base Image Tag (:latest)',
              category: 'Deployment',
              subcategory: 'Reproducibility',
              analyzer: this.id,
              severity: 'LOW',
              confidence: 'HIGH',
              description: 'Dockerfile uses unpinned floating tag :latest for base container image.',
              impact: 'Upstream image updates can break production builds unpredictably or introduce zero-day vulnerabilities.',
              evidence: [{ filePath: file.relativePath, line: lineNum, snippet: lineText.trim() }],
              file: file.relativePath,
              line: lineNum,
              remediation: 'Pin base image to specific semantic version tags or explicit SHA256 digests.',
              references: ['https://docs.docker.com/develop/develop-images/dockerfile_best-practices/'],
              fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
            });
          }

          if (/^(COPY|ADD)\s+.*\.env\b/i.test(lineText.trim())) {
            const ruleId = 'VBG-DEP-003';
            findings.push({
              id: ruleId,
              rule_id: ruleId,
              title: 'Environment Secret File Copied into Container Image',
              category: 'Deployment',
              subcategory: 'Secret Hygiene',
              analyzer: this.id,
              severity: 'CRITICAL',
              confidence: 'HIGH',
              description: 'Dockerfile copies local .env secret files directly into image layers.',
              impact: 'Committed image layers embed sensitive API credentials into immutable registry artifacts.',
              evidence: [{ filePath: file.relativePath, line: lineNum, snippet: lineText.trim() }],
              file: file.relativePath,
              line: lineNum,
              remediation: 'Exclude .env files in .dockerignore and inject secrets dynamically via orchestrator environment config.',
              references: ['https://docs.docker.com/engine/reference/builder/#dockerignore-file'],
              fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
              production_impact: 'Docker registry image leaks secret keys to anyone with pull access.',
            });
          }
        });

        if (!hasUserDirective) {
          const ruleId = 'VBG-DEP-001';
          findings.push({
            id: ruleId,
            rule_id: ruleId,
            title: 'Missing Non-Root USER Directive in Dockerfile',
            category: 'Deployment',
            subcategory: 'Container Security',
            analyzer: this.id,
            severity: 'MEDIUM',
            confidence: 'MEDIUM',
            description: 'Dockerfile omits USER directive, defaulting container execution to privileged root user.',
            impact: 'Container processes execute with elevated host kernel privileges.',
            evidence: [{ filePath: file.relativePath, line: 1, snippet: 'No USER directive specified in Dockerfile.' }],
            file: file.relativePath,
            line: 1,
            remediation: 'Add non-root USER instruction prior to CMD/ENTRYPOINT execution.',
            references: ['https://cisecurity.org/benchmark/docker'],
            fingerprint: generateFingerprint(ruleId, file.relativePath, 1),
          });
        }

        if (!hasHealthcheck) {
          const ruleId = 'VBG-DEP-004';
          findings.push({
            id: ruleId,
            rule_id: ruleId,
            title: 'Missing Container HEALTHCHECK Instruction',
            category: 'Deployment',
            subcategory: 'Container Health',
            analyzer: this.id,
            severity: 'INFO',
            confidence: 'HIGH',
            description: 'Dockerfile lacks HEALTHCHECK instruction for container runtime liveness verification.',
            impact: 'Docker daemon cannot verify whether internal process is healthy or deadlocked.',
            evidence: [{ filePath: file.relativePath, line: 1, snippet: 'No HEALTHCHECK directive in Dockerfile.' }],
            file: file.relativePath,
            line: 1,
            remediation: 'Add HEALTHCHECK instruction verifying application response (e.g. HEALTHCHECK CMD curl -f http://localhost:3000/healthz || exit 1).',
            references: ['https://docs.docker.com/engine/reference/builder/#healthcheck'],
            fingerprint: generateFingerprint(ruleId, file.relativePath, 1),
          });
        }
      }

      // 2. Docker Compose Analysis
      if (isCompose) {
        file.lines.forEach((lineText, idx) => {
          const lineNum = idx + 1;
          if (/privileged:\s*true/i.test(lineText) || /network_mode:\s*["']?host["']?/i.test(lineText)) {
            const ruleId = 'VBG-DEP-005';
            findings.push({
              id: ruleId,
              rule_id: ruleId,
              title: 'Privileged Flag or Host Networking Enabled in Docker Compose',
              category: 'Deployment',
              subcategory: 'Container Security',
              analyzer: this.id,
              severity: 'HIGH',
              confidence: 'HIGH',
              description: 'Compose configuration disables container isolation privileges or attaches directly to host network.',
              impact: 'Removes container containment isolation, exposing host system devices and interfaces.',
              evidence: [{ filePath: file.relativePath, line: lineNum, snippet: lineText.trim() }],
              file: file.relativePath,
              line: lineNum,
              remediation: 'Remove privileged flag and restrict network access to dedicated bridge networks.',
              references: ['https://docs.docker.com/compose/compose-file/'],
              fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
            });
          }
        });
      }

      // 3. CI/CD Workflow Analysis
      if (isCiWorkflow) {
        file.lines.forEach((lineText, idx) => {
          const lineNum = idx + 1;

          // Secrets printed in CI logs
          if (/echo\s+.*(\$\{\{\s*secrets\.|\$SECRET|\$PASSWORD|\$TOKEN)/i.test(lineText)) {
            const ruleId = 'VBG-DEP-006';
            findings.push({
              id: ruleId,
              rule_id: ruleId,
              title: 'Potential Printing of Secrets in CI/CD Workflow Logs',
              category: 'Deployment',
              subcategory: 'CI/CD Pipeline Security',
              analyzer: this.id,
              severity: 'HIGH',
              confidence: 'HIGH',
              description: 'CI workflow step explicitly echoes environment secret variables into execution build logs.',
              impact: 'Plaintext secret values recorded in publicly or organizationally accessible build logs.',
              evidence: [{ filePath: file.relativePath, line: lineNum, snippet: lineText.trim() }],
              file: file.relativePath,
              line: lineNum,
              remediation: 'Remove echo commands referencing secret values or utilize secret masking parameters.',
              references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'],
              fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
            });
          }

          // Unpinned GitHub Actions
          if (/uses:\s*[\w-]+\/[\w-]+@(v[0-9]+|main|master)\b/.test(lineText.trim())) {
            const ruleId = 'VBG-DEP-007';
            findings.push({
              id: ruleId,
              rule_id: ruleId,
              title: 'Third-Party Action Pinned to Mutable Tag or Branch',
              category: 'Deployment',
              subcategory: 'Supply Chain Security',
              analyzer: this.id,
              severity: 'LOW',
              confidence: 'HIGH',
              description: 'GitHub Action dependency references mutable release tag or branch rather than full commit SHA.',
              impact: 'Upstream maintainer account takeover allows malicious modification of action code without version bump.',
              evidence: [{ filePath: file.relativePath, line: lineNum, snippet: lineText.trim() }],
              file: file.relativePath,
              line: lineNum,
              remediation: 'Pin third-party GitHub Actions to explicit 40-character commit SHAs.',
              references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions'],
              fingerprint: generateFingerprint(ruleId, file.relativePath, lineNum),
            });
          }
        });
      }
    }

    return findings;
  }
}
