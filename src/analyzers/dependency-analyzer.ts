import fs from 'fs';
import path from 'path';
import { generateFingerprint } from '../core/fingerprint.js';
import { DependencyInventory, DependencyItem, Finding, ScanContext } from '../core/types.js';
import { Analyzer } from './base.js';

export class DependencyAnalyzer implements Analyzer {
  id = 'dependency-analyzer';
  name = 'Dependency Inventory & Advisory Analyzer';
  category = 'Dependencies';

  async analyze(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { projectRoot, manifest } = context;

    const inventory: DependencyInventory = {
      totalCount: 0,
      directCount: 0,
      transitiveCount: 0,
      dependencies: [],
      advisoryStatus: 'NOT_CONFIGURED',
    };

    const directDepNames = new Set<string>();

    // 1. Parse package.json
    const packageJsonPath = path.join(projectRoot, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        const deps = pkg.dependencies || {};
        const devDeps = pkg.devDependencies || {};

        for (const [name, version] of Object.entries({ ...deps, ...devDeps })) {
          directDepNames.add(name);
          inventory.dependencies.push({
            name,
            version: String(version),
            type: 'direct',
            sourceFile: 'package.json',
          });
        }
      } catch {
        // Ignore package.json parsing error
      }
    }

    // 2. Parse package-lock.json if present
    const packageLockPath = path.join(projectRoot, 'package-lock.json');
    if (fs.existsSync(packageLockPath)) {
      try {
        const lock = JSON.parse(fs.readFileSync(packageLockPath, 'utf-8'));
        // npm v7+ packages format
        if (lock.packages && typeof lock.packages === 'object') {
          for (const [pkgPath, pkgData] of Object.entries<any>(lock.packages)) {
            if (!pkgPath || pkgPath === '') continue;
            const name = (pkgData.name as string) || pkgPath.replace(/^node_modules\//, '');
            const version = pkgData.version as string;
            const isDirect = directDepNames.has(name);
            inventory.dependencies.push({
              name,
              version,
              type: isDirect ? 'direct' : 'transitive',
              sourceFile: 'package-lock.json',
            });
          }
        } else if (lock.dependencies && typeof lock.dependencies === 'object') {
          for (const [name, depData] of Object.entries<any>(lock.dependencies)) {
            const isDirect = directDepNames.has(name);
            inventory.dependencies.push({
              name,
              version: depData.version,
              type: isDirect ? 'direct' : 'transitive',
              sourceFile: 'package-lock.json',
            });
          }
        }
      } catch {
        // Ignore package-lock parsing error
      }
    }

    // 3. Parse requirements.txt if present
    const reqPath = path.join(projectRoot, 'requirements.txt');
    if (fs.existsSync(reqPath)) {
      try {
        const reqContent = fs.readFileSync(reqPath, 'utf-8');
        reqContent.split(/\r?\n/).forEach((line) => {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) {
            const match = trimmed.match(/^([a-zA-Z0-9_\-\.]+)(?:([=<>~!]+)(.+))?$/);
            if (match) {
              const [, name, , version] = match;
              inventory.dependencies.push({
                name,
                version: version ? version.trim() : undefined,
                type: 'direct',
                sourceFile: 'requirements.txt',
              });
            }
          }
        });
      } catch {
        // Ignore requirements read error
      }
    }

    // Deduplicate dependencies by name:version:type
    const uniqueMap = new Map<string, DependencyItem>();
    for (const item of inventory.dependencies) {
      const key = `${item.name}:${item.version || ''}:${item.type}`;
      if (!uniqueMap.has(key)) {
        uniqueMap.set(key, item);
      }
    }
    inventory.dependencies = Array.from(uniqueMap.values());

    // Calculate direct vs transitive counts
    inventory.directCount = inventory.dependencies.filter((d) => d.type === 'direct').length;
    inventory.transitiveCount = inventory.dependencies.filter((d) => d.type === 'transitive').length;
    inventory.totalCount = inventory.dependencies.length;

    // Attach to manifest for terminal and JSON reporting
    manifest.dependencyInventory = inventory;

    // Rule 1: Missing lockfile for package manifest (VBG-DEP-001)
    if (manifest.packageManifests.length > 0 && manifest.lockfiles.length === 0) {
      const manifestFile = manifest.packageManifests[0];
      const fp = generateFingerprint('VBG-DEP-001', manifestFile, 1, 'No lockfile found');
      findings.push({
        id: 'VBG-DEP-001',
        title: 'Missing package lockfile for tracked dependency manifest',
        category: 'Dependencies',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        description: `The project contains '${manifestFile}' but no corresponding lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, etc.) was detected.`,
        impact: 'Without a committed lockfile, installations are non-deterministic, creating risk of supply-chain drifts or broken builds when upstream packages release breaking changes.',
        file: manifestFile,
        line: 1,
        evidence: [
          {
            filePath: manifestFile,
            line: 1,
            snippet: `Manifest present without lockfile: ${manifestFile}`,
          },
        ],
        remediation: 'Generate and commit a package lockfile (e.g. npm install, pnpm install, or poetry lock) into version control.',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html'],
        fingerprint: fp,
      });
    }

    // Rule 2: Dangerous or known insecure package pinned (VBG-DEP-002)
    const dangerousPackages = [
      { name: 'node-serialize', reason: 'known arbitrary remote code execution via untrusted deserialization' },
      { name: 'serialize-javascript', reason: 'historic regex DOS and XSS when used without careful options' },
    ];

    for (const dep of inventory.dependencies) {
      const dangerous = dangerousPackages.find((p) => p.name.toLowerCase() === dep.name.toLowerCase());
      if (dangerous) {
        const fp = generateFingerprint('VBG-DEP-002', dep.sourceFile, 1, dep.name);
        findings.push({
          id: 'VBG-DEP-002',
          title: `Potentially dangerous dependency pinned: ${dep.name}`,
          category: 'Dependencies',
          severity: 'HIGH',
          confidence: 'HIGH',
          description: `The dependency '${dep.name}' is included in ${dep.sourceFile} (${dangerous.reason}).`,
          impact: 'Including inherently unsafe libraries exposes the application to severe remote code execution or injection vulnerabilities.',
          file: dep.sourceFile,
          line: 1,
          evidence: [
            {
              filePath: dep.sourceFile,
              line: 1,
              snippet: `${dep.name}: ${dep.version || 'unpinned'}`,
            },
          ],
          remediation: `Replace '${dep.name}' with a safe alternative library.`,
          references: ['https://cwe.mitre.org/data/definitions/502.html'],
          fingerprint: fp,
        });
      }

      // Rule 3: Wildcard or Unpinned Dependency Version (VBG-DEP-011)
      if (dep.version === '*' || dep.version === 'latest') {
        const fp = generateFingerprint('VBG-DEP-011', dep.sourceFile, 1, dep.name);
        findings.push({
          id: 'VBG-DEP-011',
          title: `Wildcard or Unpinned Dependency Version: ${dep.name}`,
          category: 'Dependencies',
          subcategory: 'Supply Chain',
          analyzer: this.id,
          severity: 'LOW',
          confidence: 'HIGH',
          description: `Dependency '${dep.name}' uses wildcard or 'latest' version specification (${dep.version}).`,
          impact: 'Automatic adoption of arbitrary upstream major updates introduces breaking API changes and unreviewed code.',
          file: dep.sourceFile,
          line: 1,
          evidence: [{ filePath: dep.sourceFile, line: 1, snippet: `${dep.name}: ${dep.version}` }],
          remediation: 'Pin dependency to exact or semver-bounded version constraint.',
          references: ['https://docs.npmjs.com/about-semantic-versioning'],
          fingerprint: fp,
        });
      }

      // Rule 4: Git or Local Path Dependency (VBG-DEP-012)
      if (dep.version && (dep.version.startsWith('file:') || dep.version.startsWith('git+') || dep.version.startsWith('http'))) {
        const fp = generateFingerprint('VBG-DEP-012', dep.sourceFile, 1, dep.name);
        findings.push({
          id: 'VBG-DEP-012',
          title: `Unverified Git or Local Path Dependency: ${dep.name}`,
          category: 'Dependencies',
          subcategory: 'Supply Chain',
          analyzer: this.id,
          severity: 'LOW',
          confidence: 'HIGH',
          description: `Dependency '${dep.name}' specifies local filesystem path or unverified URL source (${dep.version}).`,
          impact: 'Non-standard dependency sources bypass registry audit verification and cause build failures in clean CI/CD environments.',
          file: dep.sourceFile,
          line: 1,
          evidence: [{ filePath: dep.sourceFile, line: 1, snippet: `${dep.name}: ${dep.version}` }],
          remediation: 'Publish dependency to standard npm/PyPI registry or private authenticated artifact repository.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html'],
          fingerprint: fp,
        });
      }
    }

    return findings;
  }
}
