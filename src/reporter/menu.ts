import pc from 'picocolors';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import fs from 'fs';
import path from 'path';
import { runScan } from '../orchestrator/scanner.js';
import { renderBanner } from './banner.js';
import { renderTerminalReport, renderApiSurface } from './terminal.js';
import { explainFinding } from '../core/explain.js';
import { createBaseline } from '../core/baseline.js';

function resolveTarget(targetArg: string = '.'): string {
  const resolved = path.resolve(targetArg);
  if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
    return path.dirname(resolved);
  }
  return resolved;
}

export interface MenuOptions {
  noColor?: boolean;
}

export function renderFeatureList(isNoColor = false): string {
  if (isNoColor) {
    return [
      '======================================================================',
      '                     VIBEGUARD FEATURE MENU                           ',
      '======================================================================',
      '',
      '  [1] Scan Project (Standard)        - Full security & production readiness scan',
      '  [2] Scan Project (Deep Analysis)   - Multi-file graph & dataflow taint tracking',
      '  [3] Readiness Summary Table        - Categorized readiness scores & metrics',
      '  [4] API Surface & Routes           - Discovered endpoints, methods & handlers',
      '  [5] Vulnerabilities & Findings     - Quick list of detected vulnerabilities',
      '  [6] Explain Finding & Fix          - Detailed remediation guidance for an issue',
      '  [7] Security Rules Only            - Scan secrets, injections, XSS, SSRF, auth',
      '  [8] Production Readiness Only      - Scan resilience, logging, container config',
      '  [9] Create Baseline File           - Suppress legacy findings with fingerprinting',
      '  [W] Interactive Web Dashboard      - Open professional web report in browser',
      '  [0] Exit                           - Quit VibeGuard',
      '',
      '  ------------------------------------------------------------------',
      '  Direct command shortcuts (run anytime):',
      '    vibeguard scan .                 vibeguard scan . --deep',
      '    vibeguard summary .              vibeguard routes .',
      '    vibeguard findings .             vibeguard explain <id>',
      '  ------------------------------------------------------------------',
    ].join('\n');
  }

  const border = pc.cyan('═'.repeat(70));
  const title = `  ${pc.bold(pc.white('🛡️  VIBEGUARD INTERACTIVE CONTROL CENTER'))}`;
  const sub = `  ${pc.dim('Select a feature number below, or press Ctrl+C to cancel')}\n`;

  const items = [
    `  ${pc.cyan(pc.bold('[1]'))} ${pc.bold('Standard Pre-Production Audit')} ${pc.dim('→')} ${pc.white('vibeguard scan .')}\n      ${pc.dim('Full static security & production-readiness audit')}`,
    `  ${pc.cyan(pc.bold('[2]'))} ${pc.bold('Deep Multi-File & Graph Audit')}  ${pc.dim('→')} ${pc.white('vibeguard scan . --deep')}\n      ${pc.dim('Cross-file tainted dataflow & endpoint graph analysis')}`,
    `  ${pc.cyan(pc.bold('[3]'))} ${pc.bold('Production Readiness Summary')}   ${pc.dim('→')} ${pc.white('vibeguard summary .')}\n      ${pc.dim('Category scorecards, status grades & production blockers')}`,
    `  ${pc.cyan(pc.bold('[4]'))} ${pc.bold('API Surface & Endpoints Map')}    ${pc.dim('→')} ${pc.white('vibeguard routes .')}\n      ${pc.dim('Discovered HTTP routes, frameworks & parameter sinks')}`,
    `  ${pc.cyan(pc.bold('[5]'))} ${pc.bold('List Findings & Issues')}         ${pc.dim('→')} ${pc.white('vibeguard findings .')}\n      ${pc.dim('Compact listing of all detected warnings & vulnerabilities')}`,
    `  ${pc.cyan(pc.bold('[6]'))} ${pc.bold('Explain Finding & Remediation')}    ${pc.dim('→')} ${pc.white('vibeguard explain <id>')}\n      ${pc.dim('Deterministic WHAT, WHERE, WHY, HOW, and fix instructions')}`,
    `  ${pc.cyan(pc.bold('[7]'))} ${pc.bold('Security Audit Rules Only')}       ${pc.dim('→')} ${pc.white('vibeguard scan . --security')}\n      ${pc.dim('Filter to secrets, injections, XSS, SSRF, CORS & auth')}`,
    `  ${pc.cyan(pc.bold('[8]'))} ${pc.bold('Production Readiness Rules Only')} ${pc.dim('→')} ${pc.white('vibeguard scan . --production')}\n      ${pc.dim('Filter to reliability, containers, configuration & logging')}`,
    `  ${pc.cyan(pc.bold('[9]'))} ${pc.bold('Create Scan Baseline')}            ${pc.dim('→')} ${pc.white('vibeguard baseline create')}\n      ${pc.dim('Save current findings fingerprint to suppress legacy debt')}`,
    `  ${pc.green(pc.bold('[W]'))} ${pc.bold('Interactive Web Dashboard')}       ${pc.dim('→')} ${pc.white('vibeguard dashboard .')}\n      ${pc.dim('Launch professional browser dashboard with charts, filters & guide')}`,
    `  ${pc.yellow(pc.bold('[0]'))} ${pc.dim('Exit')}`,
  ];

  const shortcuts = [
    pc.dim('  ─'.repeat(35)),
    `  ${pc.dim('Tip:')} Run any feature directly at any time: ${pc.cyan('vibeguard scan .')}`,
  ].join('\n');

  return `\n${border}\n${title}\n${sub}\n${items.join('\n\n')}\n\n${shortcuts}\n${border}\n`;
}

export async function runInteractiveMenu(options: MenuOptions = {}): Promise<void> {
  const isNoColor = options.noColor || process.env.NO_COLOR !== undefined;

  // Print Banner prominently
  console.log(renderBanner({ noColor: isNoColor }));
  console.log(renderFeatureList(isNoColor));

  // If non-interactive stdin, stop here gracefully
  if (!process.stdin.isTTY) {
    return;
  }

  const rl = readline.createInterface({ input, output });

  try {
    const answer = await rl.question(
      isNoColor
        ? '\nEnter choice [0-9] (default: 1): '
        : `\n${pc.bold(pc.green('?'))} ${pc.bold('Enter choice')} ${pc.dim('[0-9]')} ${pc.cyan('(default: 1)')}: `
    );

    const choice = answer.trim() || '1';

    switch (choice) {
      case '1': {
        const targetPrompt = await rl.question(
          isNoColor ? 'Target folder (default: .): ' : `${pc.dim('Target directory')} ${pc.cyan('(default: .)')}: `
        );
        const targetPath = resolveTarget(targetPrompt.trim() || '.');
        console.log(isNoColor ? `\nRunning standard audit on ${targetPath}...` : `\n${pc.cyan('◆')} Running standard audit on ${pc.bold(targetPath)}...\n`);
        const result = await runScan({ targetPath, noColor: isNoColor, noBanner: true });
        console.log(renderTerminalReport(result, isNoColor));
        break;
      }

      case '2': {
        const targetPrompt = await rl.question(
          isNoColor ? 'Target folder (default: .): ' : `${pc.dim('Target directory')} ${pc.cyan('(default: .)')}: `
        );
        const targetPath = resolveTarget(targetPrompt.trim() || '.');
        console.log(isNoColor ? `\nRunning deep graph audit on ${targetPath}...` : `\n${pc.cyan('◆')} Running deep graph audit on ${pc.bold(targetPath)}...\n`);
        const result = await runScan({ targetPath, deep: true, noColor: isNoColor, noBanner: true });
        console.log(renderTerminalReport(result, isNoColor));
        break;
      }

      case '3': {
        const targetPrompt = await rl.question(
          isNoColor ? 'Target folder (default: .): ' : `${pc.dim('Target directory')} ${pc.cyan('(default: .)')}: `
        );
        const targetPath = resolveTarget(targetPrompt.trim() || '.');
        const result = await runScan({ targetPath, noColor: isNoColor, noBanner: true });
        console.log(renderTerminalReport(result, isNoColor));
        break;
      }

      case '4': {
        const targetPrompt = await rl.question(
          isNoColor ? 'Target folder (default: .): ' : `${pc.dim('Target directory')} ${pc.cyan('(default: .)')}: `
        );
        const targetPath = resolveTarget(targetPrompt.trim() || '.');
        const result = await runScan({ targetPath, noColor: isNoColor, noBanner: true });
        console.log(renderApiSurface(result.routes || [], isNoColor));
        break;
      }

      case '5': {
        const targetPrompt = await rl.question(
          isNoColor ? 'Target folder (default: .): ' : `${pc.dim('Target directory')} ${pc.cyan('(default: .)')}: `
        );
        const targetPath = resolveTarget(targetPrompt.trim() || '.');
        const result = await runScan({ targetPath, noColor: isNoColor, noBanner: true });
        console.log(`\nFINDINGS (${result.findings.length})\n`);
        result.findings.forEach((f) => {
          console.log(`[${f.severity}] ${f.id} ${f.title} (${f.file || 'unknown'}:${f.line || 1})`);
        });
        break;
      }

      case '6': {
        const idPrompt = await rl.question(
          isNoColor ? 'Enter Finding ID (e.g. VBG-SECRET-001): ' : `${pc.dim('Enter Finding ID')} ${pc.cyan('(e.g. VBG-SECRET-001)')}: `
        );
        const findingId = idPrompt.trim();
        if (!findingId) {
          console.log(isNoColor ? 'No finding ID provided.' : pc.yellow('No finding ID provided.'));
          break;
        }
        const targetPath = path.resolve('.');
        const result = await runScan({ targetPath, noColor: isNoColor, noBanner: true });
        const targetFinding = result.findings.find(
          (f) => f.id.toLowerCase() === findingId.toLowerCase() || (f.rule_id && f.rule_id.toLowerCase() === findingId.toLowerCase())
        );

        if (!targetFinding) {
          console.log(
            isNoColor
              ? `\nFinding '${findingId}' was not found in current project scan.`
              : `\n${pc.yellow('✗')} Finding ${pc.bold(findingId)} was not found in current project scan.`
          );
        } else {
          console.log(explainFinding(targetFinding, isNoColor));
        }
        break;
      }

      case '7': {
        const targetPrompt = await rl.question(
          isNoColor ? 'Target folder (default: .): ' : `${pc.dim('Target directory')} ${pc.cyan('(default: .)')}: `
        );
        const targetPath = resolveTarget(targetPrompt.trim() || '.');
        console.log(isNoColor ? `\nRunning security-only audit on ${targetPath}...` : `\n${pc.cyan('◆')} Running security-only audit on ${pc.bold(targetPath)}...\n`);
        const result = await runScan({ targetPath, security: true, noColor: isNoColor, noBanner: true });
        console.log(renderTerminalReport(result, isNoColor));
        break;
      }

      case '8': {
        const targetPrompt = await rl.question(
          isNoColor ? 'Target folder (default: .): ' : `${pc.dim('Target directory')} ${pc.cyan('(default: .)')}: `
        );
        const targetPath = resolveTarget(targetPrompt.trim() || '.');
        console.log(isNoColor ? `\nRunning production-readiness audit on ${targetPath}...` : `\n${pc.cyan('◆')} Running production-readiness audit on ${pc.bold(targetPath)}...\n`);
        const result = await runScan({ targetPath, production: true, noColor: isNoColor, noBanner: true });
        console.log(renderTerminalReport(result, isNoColor));
        break;
      }

      case '9': {
        const targetPrompt = await rl.question(
          isNoColor ? 'Target folder (default: .): ' : `${pc.dim('Target directory')} ${pc.cyan('(default: .)')}: `
        );
        const targetPath = resolveTarget(targetPrompt.trim() || '.');
        const filePrompt = await rl.question(
          isNoColor ? 'Baseline output file (default: .vibeguard-baseline.json): ' : `${pc.dim('Baseline output file')} ${pc.cyan('(default: .vibeguard-baseline.json)')}: `
        );
        const outputFile = filePrompt.trim() || '.vibeguard-baseline.json';
        const result = await runScan({ targetPath, noColor: isNoColor, noBanner: true });
        const baseline = createBaseline(result.findings, outputFile);
        console.log(
          isNoColor
            ? `\nCreated baseline file '${outputFile}' with ${baseline.findingsCount} fingerprints.\n`
            : `\n${pc.green('✓')} Created baseline file ${pc.bold(outputFile)} with ${pc.cyan(String(baseline.findingsCount))} fingerprints.\n`
        );
        break;
      }

      case 'w':
      case 'W':
      case 'dashboard': {
        const targetPrompt = await rl.question(
          isNoColor ? 'Target folder (default: .): ' : `${pc.dim('Target directory')} ${pc.cyan('(default: .)')}: `
        );
        const targetPath = resolveTarget(targetPrompt.trim() || '.');
        const { launchDashboard } = await import('./server.js');
        await launchDashboard(targetPath, { noColor: isNoColor });
        break;
      }

      case '0':
      case 'q':
      case 'exit': {
        console.log(isNoColor ? 'Goodbye!' : pc.dim('Goodbye!'));
        break;
      }

      default: {
        console.log(isNoColor ? `Invalid option: ${choice}` : pc.red(`Invalid option: ${choice}`));
        break;
      }
    }
  } finally {
    rl.close();
  }
}

