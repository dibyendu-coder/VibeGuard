import { Command } from 'commander';
import path from 'path';
import pc from 'picocolors';
import { runScan } from './orchestrator/scanner.js';
import { renderBanner } from './reporter/banner.js';
import { renderJsonReport } from './reporter/json.js';
import { renderSarifReport } from './reporter/sarif.js';
import { renderApiSurface, renderTerminalReport } from './reporter/terminal.js';
import { createBaseline } from './core/baseline.js';

const program = new Command();

program
  .name('vibeguard')
  .description('Terminal-first pre-production security and production-readiness auditor for AI/vibe-coded applications')
  .version('0.1.0', '-v, --version', 'Output the current version of VibeGuard');

program
  .command('scan [target]')
  .description('Perform a pre-production audit of a project directory')
  .option('--json', 'Output results as machine-readable JSON')
  .option('--sarif', 'Output results as SARIF format')
  .option('--no-color', 'Disable colored terminal output')
  .option('--no-banner', 'Disable full startup banner')
  .option('--deep', 'Perform deep multi-file analysis & application graph audit')
  .option('--security', 'Run security audit rules only')
  .option('--production', 'Run production readiness rules only')
  .option('--category <category>', 'Filter findings by category')
  .option('--severity <severity>', 'Filter findings by minimum severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)')
  .option('--baseline <file>', 'Use baseline file to suppress existing findings')
  .action(async (targetArg = '.', options) => {
    try {
      const targetPath = path.resolve(targetArg);
      const isNoColor = options.color === false || process.env.NO_COLOR !== undefined;

      // Print Startup Banner if interactive terminal & not suppressed
      if (!options.json && !options.sarif && options.banner !== false) {
        console.log(renderBanner({ noColor: isNoColor }));
      }

      const scanResult = await runScan({
        targetPath,
        json: options.json,
        sarif: options.sarif,
        noColor: isNoColor,
        noBanner: options.banner === false,
        deep: options.deep,
        security: options.security,
        production: options.production,
        category: options.category,
        severity: options.severity,
        baseline: options.baseline,
      });

      if (options.json) {
        console.log(renderJsonReport(scanResult));
      } else if (options.sarif) {
        console.log(renderSarifReport(scanResult));
      } else {
        console.log(renderTerminalReport(scanResult, isNoColor));
      }

      process.exit(scanResult.exitCode);
    } catch (err: any) {
      if (options.json) {
        console.error(
          JSON.stringify({
            error: err.message || 'Scan error occurred',
            exitCode: 3,
          })
        );
      } else {
        console.error(`\n${pc.red('✗ Scan Error:')} ${err.message || err}\n`);
      }
      process.exit(3);
    }
  });

program
  .command('routes [target]')
  .description('Display discovered API routes and endpoints')
  .option('--no-color', 'Disable colored terminal output')
  .action(async (targetArg = '.', options) => {
    try {
      const targetPath = path.resolve(targetArg);
      const isNoColor = options.color === false || process.env.NO_COLOR !== undefined;
      const scanResult = await runScan({ targetPath, noColor: isNoColor });
      console.log(renderApiSurface(scanResult.routes || [], isNoColor));
      process.exit(0);
    } catch (err: any) {
      console.error(`\n${pc.red('✗ Error:')} ${err.message || err}\n`);
      process.exit(3);
    }
  });

program
  .command('findings [target]')
  .description('Display findings list for target project')
  .option('--no-color', 'Disable colored terminal output')
  .action(async (targetArg = '.', options) => {
    try {
      const targetPath = path.resolve(targetArg);
      const isNoColor = options.color === false || process.env.NO_COLOR !== undefined;
      const scanResult = await runScan({ targetPath, noColor: isNoColor });
      console.log(`\nFINDINGS (${scanResult.findings.length})\n`);
      scanResult.findings.forEach((f) => {
        console.log(`[${f.severity}] ${f.id} ${f.title} (${f.file || 'unknown'}:${f.line || 1})`);
      });
      process.exit(0);
    } catch (err: any) {
      console.error(`\n${pc.red('✗ Error:')} ${err.message || err}\n`);
      process.exit(3);
    }
  });

program
  .command('summary [target]')
  .description('Display production readiness summary table and metric overview')
  .option('--no-color', 'Disable colored terminal output')
  .action(async (targetArg = '.', options) => {
    try {
      const targetPath = path.resolve(targetArg);
      const isNoColor = options.color === false || process.env.NO_COLOR !== undefined;
      const scanResult = await runScan({ targetPath, noColor: isNoColor, noBanner: true });
      console.log(renderTerminalReport(scanResult, isNoColor));
      process.exit(0);
    } catch (err: any) {
      console.error(`\n${pc.red('✗ Error:')} ${err.message || err}\n`);
      process.exit(3);
    }
  });

program
  .command('explain <findingId>')
  .description('Provide structured explanation and remediation guidance for a finding ID')
  .option('--no-color', 'Disable colored terminal output')
  .option('--target <target>', 'Target project path', '.')
  .action(async (findingId, options) => {
    try {
      const targetPath = path.resolve(options.target || '.');
      const isNoColor = options.color === false || process.env.NO_COLOR !== undefined;
      const scanResult = await runScan({ targetPath, noColor: isNoColor, noBanner: true });

      const targetFinding = scanResult.findings.find(
        (f) => f.id.toLowerCase() === findingId.toLowerCase() || (f.rule_id && f.rule_id.toLowerCase() === findingId.toLowerCase())
      );

      if (!targetFinding) {
        console.error(`\n${pc.red('✗ Finding not found:')} '${findingId}' across project audit results.\n`);
        process.exit(1);
      }

      const { explainFinding } = await import('./core/explain.js');
      console.log(explainFinding(targetFinding, isNoColor));
      process.exit(0);
    } catch (err: any) {
      console.error(`\n${pc.red('✗ Error:')} ${err.message || err}\n`);
      process.exit(3);
    }
  });

const baselineCmd = program.command('baseline').description('Manage scan baseline files');

baselineCmd
  .command('create [target]')
  .description('Create a baseline file from current scan findings')
  .option('-o, --output <file>', 'Output baseline file path', '.vibeguard-baseline.json')
  .action(async (targetArg = '.', options) => {
    try {
      const targetPath = path.resolve(targetArg);
      const scanResult = await runScan({ targetPath });
      const baseline = createBaseline(scanResult.findings, options.output);
      console.log(`\n✓ Created baseline file '${options.output}' with ${baseline.findingsCount} fingerprints.\n`);
      process.exit(0);
    } catch (err: any) {
      console.error(`\n${pc.red('✗ Baseline Error:')} ${err.message || err}\n`);
      process.exit(3);
    }
  });

// Handle unknown commands gracefully
program.on('command:*', () => {
  console.error(`\n${pc.red('✗ Invalid command:')} ${program.args.join(' ')}`);
  console.error('Run `vibeguard --help` for available commands.\n');
  process.exit(4);
});

program.parse(process.argv);
