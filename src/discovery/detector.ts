import fs from 'fs';
import path from 'path';
import { DetectedFramework, ProjectManifest, VibeGuardConfig } from '../core/types.js';

export function discoverProject(targetDir: string, config: VibeGuardConfig): ProjectManifest {
  const absoluteRoot = path.resolve(targetDir);
  const projectName = path.basename(absoluteRoot) || 'root';

  if (!fs.existsSync(absoluteRoot)) {
    throw new Error(`Target directory does not exist: ${targetDir}`);
  }

  const stat = fs.statSync(absoluteRoot);
  if (!stat.isDirectory()) {
    throw new Error(`Target path is not a directory: ${targetDir}`);
  }

  const languages = new Set<string>();
  const frameworks: DetectedFramework[] = [];
  const envFiles: string[] = [];
  const configFiles: string[] = [];
  const packageManifests: string[] = [];
  const lockfiles: string[] = [];
  const sourceDirectories = new Set<string>();
  const apiDirectories = new Set<string>();
  const authIndicators = new Set<string>();
  const databaseIndicators = new Set<string>();
  const ciCdConfigFiles: string[] = [];
  const dockerFiles: string[] = [];

  let packageManager: string | undefined = undefined;
  let hasLockfile = false;
  let routesCount = 0;
  let databaseTablesCount = 0;
  let sourceFilesCount = 0;
  let totalFilesCount = 0;

  let hasTypeScript = false;
  let hasJavaScript = false;

  // Build ignored patterns
  const ignoredPatterns = new Set<string>(config.ignoredPaths);
  const gitignorePath = path.join(absoluteRoot, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    try {
      const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');
      gitignoreContent.split(/\r?\n/).forEach((line) => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          ignoredPatterns.add(trimmed.replace(/^\//, '').replace(/\/$/, ''));
        }
      });
    } catch {
      // ignore gitignore read error
    }
  }

  function shouldIgnore(relativePath: string, basename: string): boolean {
    if (ignoredPatterns.has(basename) || ignoredPatterns.has(relativePath)) {
      return true;
    }
    for (const pattern of ignoredPatterns) {
      if (relativePath === pattern || relativePath.startsWith(pattern + path.sep) || relativePath.startsWith(pattern + '/')) {
        return true;
      }
    }
    return false;
  }

  function walk(currentDir: string, relativeDir: string = '') {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const relativePath = relativeDir ? path.join(relativeDir, entry.name).replace(/\\/g, '/') : entry.name;

      if (shouldIgnore(relativePath, entry.name)) {
        continue;
      }

      const fullPath = path.join(currentDir, entry.name);

      if (entry.isSymbolicLink()) {
        try {
          const realPath = fs.realpathSync(fullPath);
          if (!realPath.startsWith(absoluteRoot)) {
            continue;
          }
        } catch {
          continue;
        }
      }

      if (entry.isDirectory()) {
        // Recognize source directories
        const dirName = entry.name.toLowerCase();
        if (['src', 'app', 'pages', 'lib', 'components'].includes(dirName)) {
          sourceDirectories.add(relativePath);
        }

        // Recognize API directories
        if (
          relativePath === 'api' ||
          relativePath === 'app/api' ||
          relativePath === 'pages/api' ||
          relativePath === 'routes' ||
          relativePath === 'controllers' ||
          relativePath.endsWith('/api') ||
          relativePath.endsWith('/routes')
        ) {
          apiDirectories.add(relativePath);
        }

        // Database / Migration directories
        if (dirName === 'prisma') {
          databaseIndicators.add('Prisma (prisma/ directory)');
        }
        if (dirName === 'drizzle') {
          databaseIndicators.add('Drizzle ORM (drizzle/ directory)');
        }
        if (dirName === 'alembic' || dirName === 'migrations') {
          databaseIndicators.add(`Migrations directory (${relativePath})`);
        }
        if (dirName === 'supabase') {
          frameworks.push({
            name: 'Supabase',
            confidence: 'HIGH',
            evidence: 'supabase/ directory found',
          });
          databaseIndicators.add('Supabase (supabase/ directory)');
        }

        walk(fullPath, relativePath);
      } else if (entry.isFile()) {
        totalFilesCount++;

        // Environment files
        if (entry.name.startsWith('.env')) {
          envFiles.push(relativePath);
        }

        // Config files
        if (
          entry.name.endsWith('.config.js') ||
          entry.name.endsWith('.config.ts') ||
          entry.name.endsWith('.config.mjs') ||
          entry.name.endsWith('.config.cjs') ||
          entry.name === 'tsconfig.json' ||
          entry.name === 'jsconfig.json' ||
          entry.name === 'settings.py'
        ) {
          configFiles.push(relativePath);
        }

        // Docker files
        if (entry.name === 'Dockerfile' || entry.name === 'docker-compose.yml' || entry.name === 'docker-compose.yaml' || entry.name === '.dockerignore') {
          dockerFiles.push(relativePath);
          if (entry.name === 'Dockerfile' || entry.name.startsWith('docker-compose')) {
            frameworks.push({
              name: 'Docker',
              confidence: 'HIGH',
              evidence: `${entry.name} configuration present`,
            });
          }
        }

        // CI/CD files
        if (relativePath.startsWith('.github/workflows') || relativePath === '.gitlab-ci.yml' || relativePath === '.circleci/config.yml') {
          ciCdConfigFiles.push(relativePath);
        }

        // Package Manifests & Lockfiles
        if (entry.name === 'package.json') {
          packageManifests.push(relativePath);
        } else if (entry.name === 'requirements.txt' || entry.name === 'pyproject.toml' || entry.name === 'Pipfile') {
          packageManifests.push(relativePath);
        }

        if (entry.name === 'package-lock.json') {
          lockfiles.push(relativePath);
          packageManager = packageManager || 'npm';
          hasLockfile = true;
        } else if (entry.name === 'yarn.lock') {
          lockfiles.push(relativePath);
          packageManager = packageManager || 'yarn';
          hasLockfile = true;
        } else if (entry.name === 'pnpm-lock.yaml') {
          lockfiles.push(relativePath);
          packageManager = packageManager || 'pnpm';
          hasLockfile = true;
        } else if (entry.name === 'bun.lockb' || entry.name === 'bun.lock') {
          lockfiles.push(relativePath);
          packageManager = packageManager || 'bun';
          hasLockfile = true;
        } else if (entry.name === 'poetry.lock') {
          lockfiles.push(relativePath);
          packageManager = packageManager || 'poetry';
          hasLockfile = true;
        } else if (entry.name === 'Pipfile.lock') {
          lockfiles.push(relativePath);
          packageManager = packageManager || 'pipenv';
          hasLockfile = true;
        }

        // Language & Route detection by file extension
        const ext = path.extname(entry.name).toLowerCase();
        if (ext === '.ts' || ext === '.tsx') {
          hasTypeScript = true;
          sourceFilesCount++;
          if (
            relativePath.includes('api/') ||
            relativePath.includes('routes/') ||
            entry.name === 'route.ts' ||
            entry.name === 'route.tsx'
          ) {
            routesCount++;
          }
        } else if (ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs') {
          hasJavaScript = true;
          sourceFilesCount++;
          if (
            relativePath.includes('api/') ||
            relativePath.includes('routes/') ||
            entry.name === 'route.js' ||
            entry.name === 'route.jsx'
          ) {
            routesCount++;
          }
        } else if (ext === '.py') {
          languages.add('Python');
          sourceFilesCount++;
          if (relativePath.includes('api') || relativePath.includes('routes') || relativePath.includes('views')) {
            routesCount++;
          }
        } else if (ext === '.sql') {
          languages.add('SQL');
          databaseTablesCount++;
          databaseIndicators.add(`SQL schemas (${relativePath})`);
        }
      }
    }
  }

  walk(absoluteRoot);

  if (hasTypeScript) {
    languages.add('TypeScript');
  }
  if (hasJavaScript) {
    languages.add('JavaScript');
  }

  // Inspect package.json
  const packageJsonPath = path.join(absoluteRoot, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    try {
      const pkgContent = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      if (!packageManager && !hasLockfile) {
        packageManager = 'npm (inferred)';
      }

      const allDeps: Record<string, string> = {
        ...(pkgContent.dependencies || {}),
        ...(pkgContent.devDependencies || {}),
      };

      if (allDeps['typescript'] || fs.existsSync(path.join(absoluteRoot, 'tsconfig.json'))) {
        languages.add('TypeScript');
      }
      if (!hasTypeScript && !languages.has('TypeScript')) {
        languages.add('JavaScript');
      }

      if (allDeps['next']) {
        frameworks.push({
          name: 'Next.js',
          version: allDeps['next'],
          confidence: 'HIGH',
          evidence: `package.json dependency next@${allDeps['next']}`,
        });
      }
      if (allDeps['react']) {
        frameworks.push({
          name: 'React',
          version: allDeps['react'],
          confidence: 'HIGH',
          evidence: `package.json dependency react@${allDeps['react']}`,
        });
      }
      if (allDeps['express']) {
        frameworks.push({
          name: 'Express',
          version: allDeps['express'],
          confidence: 'HIGH',
          evidence: `package.json dependency express@${allDeps['express']}`,
        });
      }
      if (allDeps['@supabase/supabase-js']) {
        frameworks.push({
          name: 'Supabase JS',
          version: allDeps['@supabase/supabase-js'],
          confidence: 'HIGH',
          evidence: `package.json dependency @supabase/supabase-js@${allDeps['@supabase/supabase-js']}`,
        });
        databaseIndicators.add('@supabase/supabase-js client');
      }

      // PostgreSQL indicators in JS/TS
      if (allDeps['pg'] || allDeps['postgres'] || allDeps['@types/pg']) {
        databaseIndicators.add(`PostgreSQL driver (${allDeps['pg'] ? 'pg' : 'postgres'})`);
        frameworks.push({
          name: 'PostgreSQL',
          confidence: 'HIGH',
          evidence: `PostgreSQL client (${allDeps['pg'] ? 'pg' : 'postgres'}) in package.json`,
        });
      }
      if (allDeps['prisma'] || allDeps['@prisma/client']) {
        databaseIndicators.add('Prisma ORM');
      }
      if (allDeps['drizzle-orm']) {
        databaseIndicators.add('Drizzle ORM');
      }
      if (allDeps['typeorm']) {
        databaseIndicators.add('TypeORM');
      }
      if (allDeps['mongoose']) {
        databaseIndicators.add('Mongoose (MongoDB)');
      }

      // Auth indicators in JS/TS
      if (allDeps['next-auth'] || allDeps['@auth/core']) {
        authIndicators.add(`NextAuth / Auth.js (${allDeps['next-auth'] ? 'next-auth' : '@auth/core'})`);
      }
      if (allDeps['@clerk/nextjs'] || allDeps['@clerk/clerk-sdk-node']) {
        authIndicators.add('Clerk Authentication');
      }
      if (allDeps['passport']) {
        authIndicators.add('Passport.js');
      }
      if (allDeps['jsonwebtoken'] || allDeps['jose']) {
        authIndicators.add(`JWT verification library (${allDeps['jsonwebtoken'] ? 'jsonwebtoken' : 'jose'})`);
      }
      if (allDeps['firebase-admin'] || allDeps['firebase']) {
        authIndicators.add('Firebase Auth');
      }
    } catch {
      // Ignore package.json parsing error
    }
  }

  // Inspect requirements.txt
  const reqPath = path.join(absoluteRoot, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const reqContent = fs.readFileSync(reqPath, 'utf-8');
      languages.add('Python');
      if (!packageManager && !hasLockfile) {
        packageManager = 'pip';
      }

      if (reqContent.match(/fastapi/i)) {
        frameworks.push({
          name: 'FastAPI',
          confidence: 'HIGH',
          evidence: 'fastapi specified in requirements.txt',
        });
      }
      if (reqContent.match(/flask/i)) {
        frameworks.push({
          name: 'Flask',
          confidence: 'HIGH',
          evidence: 'flask specified in requirements.txt',
        });
      }
      if (reqContent.match(/psycopg2|asyncpg/i)) {
        databaseIndicators.add('PostgreSQL Python driver (psycopg2/asyncpg)');
        frameworks.push({
          name: 'PostgreSQL',
          confidence: 'HIGH',
          evidence: 'PostgreSQL driver (psycopg2/asyncpg) in requirements.txt',
        });
      }
      if (reqContent.match(/sqlalchemy/i)) {
        databaseIndicators.add('SQLAlchemy ORM');
      }
      if (reqContent.match(/pyjwt|python-jose/i)) {
        authIndicators.add('Python JWT handling (pyjwt/python-jose)');
      }
      if (reqContent.match(/passlib/i)) {
        authIndicators.add('Passlib password hashing');
      }
    } catch {
      // Ignore requirements read error
    }
  }

  // Inspect pyproject.toml
  const pyprojectPath = path.join(absoluteRoot, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath)) {
    try {
      const pyContent = fs.readFileSync(pyprojectPath, 'utf-8');
      languages.add('Python');
      if (!packageManager && !hasLockfile) {
        packageManager = 'poetry/pip';
      }
      if (pyContent.includes('fastapi')) {
        frameworks.push({
          name: 'FastAPI',
          confidence: 'HIGH',
          evidence: 'fastapi in pyproject.toml',
        });
      }
      if (pyContent.includes('flask')) {
        frameworks.push({
          name: 'Flask',
          confidence: 'HIGH',
          evidence: 'flask in pyproject.toml',
        });
      }
    } catch {
      // Ignore pyproject read error
    }
  }

  // Deduplicate frameworks
  const uniqueFrameworks = Array.from(
    new Map(frameworks.map((f) => [`${f.name}:${f.version || ''}`, f])).values()
  );

  return {
    rootDir: absoluteRoot,
    projectName,
    languages: Array.from(languages),
    frameworks: uniqueFrameworks,
    packageManager,
    hasLockfile,
    packageManifests,
    lockfiles,
    sourceDirectories: Array.from(sourceDirectories),
    apiDirectories: Array.from(apiDirectories),
    authIndicators: Array.from(authIndicators),
    databaseIndicators: Array.from(databaseIndicators),
    ciCdConfigFiles,
    dockerFiles,
    envFiles,
    configFiles,
    routesCount,
    databaseTablesCount,
    sourceFilesCount,
    totalFilesCount,
  };
}
