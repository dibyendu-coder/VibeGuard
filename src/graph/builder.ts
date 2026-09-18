import fs from 'fs';
import path from 'path';
import { discoverRoutes } from './route-analyzer.js';
import { ApplicationGraph, GraphEdge, GraphNode, RouteDefinition } from './types.js';

export function buildApplicationGraph(files: string[], rootDir: string): ApplicationGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  let externalCallsCount = 0;
  let databaseOpsCount = 0;
  let modulesCount = 0;

  // Discover routes
  const routes: RouteDefinition[] = discoverRoutes(files, rootDir);

  // 1. Process Files and Modules
  for (const filePath of files) {
    const relPath = path.relative(rootDir, filePath).replace(/\\/g, '/');
    const fileId = `file:${relPath}`;

    nodes.set(fileId, {
      id: fileId,
      type: 'file',
      name: path.basename(filePath),
      filePath: relPath,
    });

    const isModule = relPath.match(/\.(js|ts|jsx|tsx|py|json)$/);
    if (isModule) {
      modulesCount++;
      const modId = `mod:${relPath}`;
      nodes.set(modId, {
        id: modId,
        type: 'module',
        name: relPath,
        filePath: relPath,
      });

      edges.push({
        sourceId: fileId,
        targetId: modId,
        relationship: 'contains',
        confidence: 'HIGH',
      });

      // Quick scan file content for operations
      const content = readFileSafe(filePath);
      if (content) {
        // Detect DB ops
        if (/db\.(query|execute|select|insert|update|delete)|prisma\.|sequelize\.|mongoose\.|knex|session\.query/i.test(content)) {
          databaseOpsCount++;
          const dbNodeId = `db:${relPath}`;
          nodes.set(dbNodeId, {
            id: dbNodeId,
            type: 'db_op',
            name: `Database Operation (${path.basename(filePath)})`,
            filePath: relPath,
          });
          edges.push({
            sourceId: modId,
            targetId: dbNodeId,
            relationship: 'queries_db',
            confidence: 'HIGH',
          });
        }

        // Detect External network calls
        if (/fetch\s*\(|axios\.|http\.request|requests\.(get|post|put|delete)|urllib/i.test(content)) {
          externalCallsCount++;
          const netNodeId = `net:${relPath}`;
          nodes.set(netNodeId, {
            id: netNodeId,
            type: 'network_op',
            name: `External Call (${path.basename(filePath)})`,
            filePath: relPath,
          });
          edges.push({
            sourceId: modId,
            targetId: netNodeId,
            relationship: 'fetches_network',
            confidence: 'HIGH',
          });
        }
      }
    }
  }

  // 2. Add Routes into Graph
  for (const route of routes) {
    const routeNodeId = `route:${route.id}`;
    nodes.set(routeNodeId, {
      id: routeNodeId,
      type: 'route',
      name: route.id,
      filePath: route.filePath,
      line: route.line,
      metadata: { ...route },
    });

    const modId = `mod:${route.filePath}`;
    if (nodes.has(modId)) {
      edges.push({
        sourceId: modId,
        targetId: routeNodeId,
        relationship: 'handles_route',
        confidence: 'HIGH',
      });
    }

    // Connect inputs
    for (const input of route.inputs) {
      const inputNodeId = `input:${route.id}:${input.name}`;
      nodes.set(inputNodeId, {
        id: inputNodeId,
        type: 'input',
        name: `${input.name} (${input.source})`,
        filePath: route.filePath,
        line: input.line,
      });

      edges.push({
        sourceId: routeNodeId,
        targetId: inputNodeId,
        relationship: 'accepts_input',
        confidence: 'HIGH',
      });
    }
  }

  return {
    nodes,
    edges,
    routes,
    modulesCount,
    filesCount: files.length,
    externalCallsCount,
    databaseOpsCount,
  };
}

function readFileSafe(filePath: string): string | null {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) return null;
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}
