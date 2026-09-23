import fs from 'fs';
import path from 'path';
import { ScanContext } from '../core/types.js';

export interface FileContentEntry {
  filePath: string;
  relativePath: string;
  content: string;
  lines: string[];
}

const MAX_FILE_SIZE_BYTES = 1024 * 1024; // 1 MB limit to prevent huge-file memory crashes

export function getScanFiles(
  context: ScanContext,
  extensions?: string[]
): FileContentEntry[] {
  const { projectRoot, config } = context;
  const results: FileContentEntry[] = [];
  const ignored = new Set(config.ignoredPaths);

  function walk(dir: string, relDir: string = '') {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const relPath = relDir ? path.join(relDir, entry.name).replace(/\\/g, '/') : entry.name;
      const baseName = entry.name;

      const normRel = relPath.replace(/\\/g, '/');
      if (ignored.has(baseName) || ignored.has(normRel)) {
        continue;
      }
      let shouldSkip = false;
      for (const pattern of ignored) {
        const normPattern = pattern.replace(/\\/g, '/').replace(/^\//, '').replace(/\/$/, '');
        if (!normPattern) continue;
        if (normRel === normPattern || normRel.startsWith(normPattern + '/')) {
          shouldSkip = true;
          break;
        }
      }
      if (shouldSkip) continue;

      const fullPath = path.join(dir, entry.name);

      if (entry.isSymbolicLink()) {
        try {
          const real = fs.realpathSync(fullPath);
          if (!real.startsWith(projectRoot)) continue;
        } catch {
          continue;
        }
      }

      if (entry.isDirectory()) {
        walk(fullPath, relPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extensions && extensions.length > 0 && !extensions.includes(ext) && !extensions.includes(entry.name)) {
          continue;
        }

        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > MAX_FILE_SIZE_BYTES) {
            continue; // Skip oversized files
          }
          const content = fs.readFileSync(fullPath, 'utf-8');
          results.push({
            filePath: fullPath,
            relativePath: relPath,
            content,
            lines: content.split(/\r?\n/),
          });
        } catch {
          // Ignore unreadable or binary files
        }
      }
    }
  }

  walk(projectRoot);
  return results;
}
