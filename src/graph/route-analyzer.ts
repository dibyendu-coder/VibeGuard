import fs from 'fs';
import path from 'path';
import { RouteDefinition, RouteInput, TriState } from './types.js';

export function discoverRoutes(files: string[], rootDir: string): RouteDefinition[] {
  const routes: RouteDefinition[] = [];

  for (const filePath of files) {
    const relPath = path.relative(rootDir, filePath).replace(/\\/g, '/');

    // 1. Next.js App Router (app/**/route.ts or route.js)
    if (relPath.match(/^app\/(.+)\/route\.[jt]sx?$/)) {
      const routePath = '/' + relPath.replace(/^app\//, '').replace(/\/route\.[jt]sx?$/, '');
      const content = readFileSafe(filePath);
      if (content) {
        const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
        for (const method of methods) {
          const regex = new RegExp(`export\\s+(async\\s+)?function\\s+${method}\\b|export\\s+const\\s+${method}\\b`, 'i');
          if (regex.test(content)) {
            const inputs = extractNextJsAppInputs(content, filePath);
            const auth = detectAuth(content);
            const authorization = detectAuthorization(content);
            const database = detectDatabase(content);
            const externalCalls = detectExternalCalls(content);
            routes.push({
              id: `${method} ${routePath}`,
              method,
              path: routePath,
              filePath: relPath,
              framework: 'Next.js App Router',
              inputs,
              authentication: auth,
              authorization,
              database,
              externalCalls,
              riskFlags: buildRiskFlags(auth, authorization, database),
            });
          }
        }
      }
      continue;
    }

    // 2. Next.js Pages Router (pages/api/**/*.ts or js)
    if (relPath.match(/^pages\/api\/(.+)\.[jt]sx?$/)) {
      const subPath = relPath.replace(/^pages\/api\//, '').replace(/\.[jt]sx?$/, '');
      const routePath = `/api/${subPath === 'index' ? '' : subPath}`;
      const content = readFileSafe(filePath);
      if (content) {
        const methods = detectPagesRouterMethods(content);
        const inputs = extractJsInputs(content, filePath);
        const auth = detectAuth(content);
        const authorization = detectAuthorization(content);
        const database = detectDatabase(content);
        const externalCalls = detectExternalCalls(content);
        for (const method of methods) {
          routes.push({
            id: `${method} ${routePath}`,
            method,
            path: routePath,
            filePath: relPath,
            framework: 'Next.js Pages Router',
            inputs,
            authentication: auth,
            authorization,
            database,
            externalCalls,
            riskFlags: buildRiskFlags(auth, authorization, database),
          });
        }
      }
      continue;
    }

    // 3. Express / Node Frameworks
    if (filePath.endsWith('.js') || filePath.endsWith('.ts') || filePath.endsWith('.mjs') || filePath.endsWith('.cjs')) {
      const content = readFileSafe(filePath);
      if (content) {
        // Look for app.get('/path', ...), router.post('/path', ...)
        const expressRegex = /(app|router|server)\.(get|post|put|delete|patch|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
        let match;
        while ((match = expressRegex.exec(content)) !== null) {
          const method = match[2].toUpperCase();
          const routePath = match[3];
          const line = getLineNumber(content, match.index);
          const blockContent = extractCodeBlockAround(content, match.index);
          const inputs = extractJsInputs(blockContent, filePath, line);
          const auth = detectAuth(blockContent);
          const authorization = detectAuthorization(blockContent);
          const database = detectDatabase(blockContent);
          const externalCalls = detectExternalCalls(blockContent);
          routes.push({
            id: `${method} ${routePath}`,
            method,
            path: routePath,
            filePath: relPath,
            line,
            framework: 'Express',
            inputs,
            authentication: auth,
            authorization,
            database,
            externalCalls,
            riskFlags: buildRiskFlags(auth, authorization, database),
          });
        }
      }
    }

    // 4. Python (FastAPI / Flask)
    if (filePath.endsWith('.py')) {
      const content = readFileSafe(filePath);
      if (content) {
        // FastAPI / Flask decorators: @app.get("/path"), @router.post("/path"), @app.route("/path", methods=["GET", "POST"])
        const pyRegex = /@(app|router)\.(get|post|put|delete|patch|route)\s*\(\s*['"`]([^'"`]+)['"`](?:\s*,\s*methods=\[([^\]]+)\])?/gi;
        let match;
        while ((match = pyRegex.exec(content)) !== null) {
          let method = match[2].toUpperCase();
          const routePath = match[3];
          const line = getLineNumber(content, match.index);

          if (method === 'ROUTE' && match[4]) {
            const methodsStr = match[4].replace(/['"\s]/g, '').toUpperCase();
            const pyMethods = methodsStr.split(',');
            for (const pm of pyMethods) {
              const blockContent = extractCodeBlockAround(content, match.index);
              const inputs = extractPyInputs(blockContent, filePath, line);
              const auth = detectAuth(blockContent);
              const authorization = detectAuthorization(blockContent);
              const database = detectDatabase(blockContent);
              const externalCalls = detectExternalCalls(blockContent);
              routes.push({
                id: `${pm} ${routePath}`,
                method: pm,
                path: routePath,
                filePath: relPath,
                line,
                framework: 'Flask / FastAPI',
                inputs,
                authentication: auth,
                authorization,
                database,
                externalCalls,
                riskFlags: buildRiskFlags(auth, authorization, database),
              });
            }
          } else {
            if (method === 'ROUTE') method = 'GET';
            const blockContent = extractCodeBlockAround(content, match.index);
            const inputs = extractPyInputs(blockContent, filePath, line);
            const auth = detectAuth(blockContent);
            const authorization = detectAuthorization(blockContent);
            const database = detectDatabase(blockContent);
            const externalCalls = detectExternalCalls(blockContent);
            routes.push({
              id: `${method} ${routePath}`,
              method,
              path: routePath,
              filePath: relPath,
              line,
              framework: 'FastAPI / Flask',
              inputs,
              authentication: auth,
              authorization,
              database,
              externalCalls,
              riskFlags: buildRiskFlags(auth, authorization, database),
            });
          }
        }
      }
    }
  }

  return routes;
}

function readFileSafe(filePath: string): string | null {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) return null; // Skip files > 2MB
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

function extractCodeBlockAround(content: string, index: number): string {
  const start = Math.max(0, index - 200);
  const end = Math.min(content.length, index + 1500);
  return content.substring(start, end);
}

function detectAuth(code: string): TriState {
  if (
    /auth\s*\(|authenticate|passport\.authenticate|jwt\.verify|verifyToken|isAuth|getSession|getServerSession|useSession|login_required|Depends\(.*auth/i.test(
      code
    )
  ) {
    return 'detected';
  }
  return 'not detected';
}

function detectAuthorization(code: string): TriState {
  if (
    /checkRole|hasPermission|authorize|isAdmin|user\.role|user\.id\s*===|ownership|user_id\s*==|check_permission/i.test(
      code
    )
  ) {
    return 'detected';
  }
  return 'not detected';
}

function detectDatabase(code: string): TriState {
  if (
    /db\.(query|execute|select|insert|update|delete)|prisma\.|sequelize\.|mongoose\.|knex|db\.collection|session\.query|SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM/i.test(
      code
    )
  ) {
    return 'detected';
  }
  return 'not detected';
}

function detectExternalCalls(code: string): TriState {
  if (/fetch\s*\(|axios\.|http\.request|https\.request|requests\.(get|post|put|delete)|urllib/i.test(code)) {
    return 'detected';
  }
  return 'not detected';
}

function buildRiskFlags(auth: TriState, authorization: TriState, db: TriState): string[] {
  const flags: string[] = [];
  if (auth === 'not detected') flags.push('NO_AUTH');
  if (authorization === 'not detected') flags.push('NO_AUTHORIZATION');
  if (db === 'detected' && authorization === 'not detected') flags.push('UNPROTECTED_DB_ACCESS');
  return flags;
}

function detectPagesRouterMethods(code: string): string[] {
  const methods: string[] = [];
  if (/req\.method\s*===\s*['"]POST['"]/i.test(code)) methods.push('POST');
  if (/req\.method\s*===\s*['"]GET['"]/i.test(code)) methods.push('GET');
  if (/req\.method\s*===\s*['"]PUT['"]/i.test(code)) methods.push('PUT');
  if (/req\.method\s*===\s*['"]DELETE['"]/i.test(code)) methods.push('DELETE');
  return methods.length > 0 ? methods : ['GET', 'POST'];
}

function extractNextJsAppInputs(code: string, file: string): RouteInput[] {
  const inputs: RouteInput[] = [];
  if (/searchParams|req\.nextUrl\.searchParams/i.test(code)) {
    inputs.push({ name: 'searchParams', source: 'query', file });
  }
  if (/params\./i.test(code)) {
    inputs.push({ name: 'params', source: 'params', file });
  }
  if (/req(uest)?\.json\s*\(/i.test(code)) {
    inputs.push({ name: 'body', source: 'body', file });
  }
  if (/req(uest)?\.headers|headers\(\)/i.test(code)) {
    inputs.push({ name: 'headers', source: 'headers', file });
  }
  if (/cookies\(\)/i.test(code)) {
    inputs.push({ name: 'cookies', source: 'cookies', file });
  }
  return inputs;
}

function extractJsInputs(code: string, file: string, line?: number): RouteInput[] {
  const inputs: RouteInput[] = [];
  if (/req\.params/i.test(code)) inputs.push({ name: 'req.params', source: 'params', file, line });
  if (/req\.query/i.test(code)) inputs.push({ name: 'req.query', source: 'query', file, line });
  if (/req\.body/i.test(code)) inputs.push({ name: 'req.body', source: 'body', file, line });
  if (/req\.headers/i.test(code)) inputs.push({ name: 'req.headers', source: 'headers', file, line });
  if (/req\.cookies/i.test(code)) inputs.push({ name: 'req.cookies', source: 'cookies', file, line });
  return inputs;
}

function extractPyInputs(code: string, file: string, line?: number): RouteInput[] {
  const inputs: RouteInput[] = [];
  if (/request\.args/i.test(code)) inputs.push({ name: 'request.args', source: 'query', file, line });
  if (/request\.form/i.test(code)) inputs.push({ name: 'request.form', source: 'body', file, line });
  if (/request\.json/i.test(code)) inputs.push({ name: 'request.json', source: 'body', file, line });
  if (/request\.headers/i.test(code)) inputs.push({ name: 'request.headers', source: 'headers', file, line });
  if (/request\.cookies/i.test(code)) inputs.push({ name: 'request.cookies', source: 'cookies', file, line });
  return inputs;
}
