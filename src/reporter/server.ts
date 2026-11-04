import http from 'http';
import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';
import pc from 'picocolors';
import { runScan } from '../orchestrator/scanner.js';
import { renderHtmlDashboard } from './html.js';

export interface DashboardServerOptions {
  port?: number;
  openBrowser?: boolean;
  noColor?: boolean;
  deep?: boolean;
  outputFile?: string;
}

export async function launchDashboard(
  targetPath: string,
  options: DashboardServerOptions = {}
): Promise<void> {
  const isNoColor = options.noColor || process.env.NO_COLOR !== undefined;
  const port = options.port || 4200;

  if (!isNoColor) {
    console.log(`\n${pc.cyan('◆')} ${pc.bold('Auditing')} ${pc.white(targetPath)} for Web Dashboard...`);
  } else {
    console.log(`\nAuditing ${targetPath} for Web Dashboard...`);
  }

  const scanResult = await runScan({
    targetPath,
    deep: options.deep ?? true,
    noBanner: true,
  });

  const htmlContent = renderHtmlDashboard(scanResult);

  // Write static copy to disk
  const reportPath = options.outputFile
    ? path.resolve(options.outputFile)
    : path.resolve(targetPath, 'vibeguard-report.html');

  try {
    fs.writeFileSync(reportPath, htmlContent, 'utf-8');
    if (!isNoColor) {
      console.log(`${pc.green('✓')} Static report saved: ${pc.cyan(reportPath)}`);
    } else {
      console.log(`Static report saved: ${reportPath}`);
    }
  } catch (err) {
    // Non-fatal if disk write fails
  }

  // Create lightweight local server
  const server = http.createServer((req, res) => {
    if (req.url === '/api/data') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(scanResult));
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(htmlContent);
  });

  server.on('error', (err: any) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`Port ${port} in use, trying ${port + 1}...`);
      launchDashboard(targetPath, { ...options, port: port + 1 });
    } else {
      console.error('Dashboard server error:', err.message);
    }
  });

  server.listen(port, () => {
    const url = `http://localhost:${port}`;
    if (!isNoColor) {
      console.log(`\n${pc.bold(pc.green('🚀 VibeGuard Web Dashboard is live at:'))} ${pc.bold(pc.underline(pc.cyan(url)))}\n`);
      console.log(`  ${pc.dim('Press Ctrl+C to stop the dashboard server')}\n`);
    } else {
      console.log(`\nVibeGuard Web Dashboard is live at: ${url}`);
      console.log(`Press Ctrl+C to stop the dashboard server\n`);
    }

    if (options.openBrowser !== false) {
      const openCmd =
        process.platform === 'win32'
          ? `start ${url}`
          : process.platform === 'darwin'
          ? `open ${url}`
          : `xdg-open ${url}`;

      exec(openCmd, () => {
        // Suppress browser open errors
      });
    }
  });
}

