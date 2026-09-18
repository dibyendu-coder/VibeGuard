import { ScanResult, Severity } from '../core/types.js';

export function renderSarifReport(scanResult: ScanResult): string {
  const rulesMap = new Map<string, any>();

  for (const finding of scanResult.findings) {
    if (!rulesMap.has(finding.id)) {
      rulesMap.set(finding.id, {
        id: finding.id,
        name: finding.id.replace(/[^a-zA-Z0-9]/g, ''),
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        defaultConfiguration: {
          level: mapSeverityToSarifLevel(finding.severity),
        },
        help: {
          text: `${finding.description}\n\nImpact:\n${finding.impact}\n\nRemediation:\n${finding.remediation}`,
        },
      });
    }
  }

  const rules = Array.from(rulesMap.values());

  const results = scanResult.findings.map((finding) => {
    const primaryEvidence = finding.evidence[0];
    const relFile = (finding.file || primaryEvidence?.filePath || 'UNKNOWN').replace(/\\/g, '/');
    const lineNum = finding.line || primaryEvidence?.line || 1;

    return {
      ruleId: finding.id,
      message: {
        text: `${finding.title}: ${finding.description}`,
      },
      level: mapSeverityToSarifLevel(finding.severity),
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: relFile,
            },
            region: {
              startLine: lineNum,
            },
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: finding.fingerprint,
      },
    };
  });

  const sarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'VibeGuard',
            semanticVersion: scanResult.version,
            informationUri: 'https://github.com/vibeguard/vibeguard',
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarifLog, null, 2);
}

function mapSeverityToSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
    default:
      return 'note';
  }
}
