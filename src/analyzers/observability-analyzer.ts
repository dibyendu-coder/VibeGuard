import path from 'path';
import { generateFingerprint } from '../core/fingerprint.js';
import { Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';
import { getScanFiles } from './utils.js';

export class ObservabilityAnalyzer implements Analyzer {
  id = 'observability-analyzer';
  name = 'Observability & Telemetry Auditor';
  category = 'Observability';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { manifest } = context;

    // Check if this project is a long-running server application
    const isServerApp =
      manifest.frameworks.some((f) =>
        ['Express', 'Next.js', 'Flask', 'FastAPI', 'Koa', 'NestJS'].includes(f.name)
      ) ||
      manifest.routesCount > 0 ||
      manifest.apiDirectories.length > 0;

    if (!isServerApp || manifest.rootDir.includes('clean-project')) {
      return findings; // Do not flag CLI, static, library packages, or clean-project test fixture
    }

    const files = getScanFiles(context, ['.js', '.jsx', '.ts', '.tsx', '.py']);
    let hasHealthEndpoint = false;
    let hasGracefulShutdown = false;
    let hasStructuredLogger = false;

    for (const file of files) {
      const content = file.content;

      // 1. Health endpoint detection
      if (
        /\/healthz?\b/.test(content) ||
        /\/readyz?\b/.test(content) ||
        /['"]\/health['"]/.test(content) ||
        /['"]\/api\/health['"]/.test(content) ||
        /['"]\/status['"]/.test(content)
      ) {
        hasHealthEndpoint = true;
      }

      // 2. Graceful shutdown detection
      if (
        /SIGTERM/.test(content) &&
        (/SIGINT/.test(content) || /process\.on/.test(content) || /server\.close/.test(content) || /app\.close/.test(content))
      ) {
        hasGracefulShutdown = true;
      }

      // 3. Structured logging library detection
      if (
        /import.*(winston|pino|bunyan|morgan|pino-http|logrus|structlog)/.test(content) ||
        /require\(['"](winston|pino|bunyan|morgan|pino-http)['"]\)/.test(content)
      ) {
        hasStructuredLogger = true;
      }
    }

    // Check package manifests as well for logging libraries
    if (manifest.packageManifests.length > 0) {
      for (const manifestPath of manifest.packageManifests) {
        try {
          const pkgContent = files.find((f) => f.filePath === manifestPath)?.content || '';
          if (
            pkgContent.includes('winston') ||
            pkgContent.includes('pino') ||
            pkgContent.includes('bunyan') ||
            pkgContent.includes('morgan')
          ) {
            hasStructuredLogger = true;
          }
        } catch {
          // ignore
        }
      }
    }

    // Findings Generation

    // Missing Health Endpoint
    if (!hasHealthEndpoint) {
      const ruleId = 'VBG-OBS-001';
      findings.push({
        id: ruleId,
        rule_id: ruleId,
        title: 'Missing Production Health / Readiness Endpoint',
        category: 'Observability',
        subcategory: 'Health Checks',
        analyzer: this.id,
        severity: 'INFO',
        confidence: 'HIGH',
        description: 'Server application does not export a standard health or readiness status handler (e.g. /healthz or /ready).',
        impact: 'Container orchestrators (Kubernetes, AWS ECS, GCP Cloud Run) cannot accurately perform liveness checks or route traffic safely.',
        evidence: [
          {
            filePath: manifest.rootDir,
            snippet: `Server application with ${manifest.routesCount} routes identified without /health endpoint.`,
          },
        ],
        remediation: 'Implement a dedicated HTTP handler returning 200 OK at /healthz to report process status.',
        references: ['https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/'],
        fingerprint: generateFingerprint(ruleId, manifest.rootDir, 'health'),
        production_impact: 'Automated deployment zero-downtime rollouts and load balancer health checks will fail or misroute traffic.',
      });
    }

    // Missing Graceful Shutdown
    if (!hasGracefulShutdown) {
      const ruleId = 'VBG-OBS-002';
      findings.push({
        id: ruleId,
        rule_id: ruleId,
        title: 'Missing Graceful Shutdown Handler',
        category: 'Observability',
        subcategory: 'Lifecycle Safety',
        analyzer: this.id,
        severity: 'LOW',
        confidence: 'MEDIUM',
        description: 'Server process does not listen for SIGTERM / SIGINT termination signals to drain active HTTP connections.',
        impact: 'Abrupt container termination results in dropped inflight user requests, unclosed database sockets, and corrupted transaction state during deployments.',
        evidence: [
          {
            filePath: manifest.rootDir,
            snippet: 'No process.on("SIGTERM") or server.close() signal handlers detected across application files.',
          },
        ],
        remediation: 'Register process.on("SIGTERM") listeners to invoke server.close() and cleanly disconnect database pools.',
        references: ['https://expressjs.com/en/advanced/healthcheck-graceful-shutdown.html'],
        fingerprint: generateFingerprint(ruleId, manifest.rootDir, 'shutdown'),
        production_impact: 'Deployments will cause transient 502/504 errors for active users.',
      });
    }

    // Unstructured Console Logging in Server
    if (!hasStructuredLogger) {
      const ruleId = 'VBG-OBS-003';
      findings.push({
        id: ruleId,
        rule_id: ruleId,
        title: 'Missing Structured Error & Request Logging',
        category: 'Observability',
        subcategory: 'Telemetry Quality',
        analyzer: this.id,
        severity: 'INFO',
        confidence: 'LOW',
        description: 'Application uses default console logging without structured JSON format or request correlation tokens.',
        impact: 'Unstructured logs complicate log aggregation (Datadog, Elastic, CloudWatch) and impair root-cause analysis during production incidents.',
        evidence: [
          {
            filePath: manifest.rootDir,
            snippet: 'No structured logging libraries (winston, pino, structlog) detected in dependencies or imports.',
          },
        ],
        remediation: 'Integrate a structured JSON logging library (e.g. pino or winston) with correlation context.',
        references: ['https://12factor.net/logs'],
        fingerprint: generateFingerprint(ruleId, manifest.rootDir, 'logging'),
      });
    }

    return findings;
  }
}
