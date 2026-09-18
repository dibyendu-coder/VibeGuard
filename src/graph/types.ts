import { Confidence, Severity } from '../core/types.js';

export type TriState = 'detected' | 'not detected' | 'unknown';

export interface RouteInput {
  name: string;
  source: 'params' | 'query' | 'body' | 'headers' | 'cookies' | 'unknown';
  file?: string;
  line?: number;
}

export interface RouteDefinition {
  id: string; // e.g. "GET /api/orders/:id"
  method: string; // GET, POST, PUT, DELETE, etc.
  path: string; // e.g. "/api/orders/:id"
  filePath: string;
  line?: number;
  framework: string; // Express, Next.js App Router, Next.js Pages Router, FastAPI, Flask, etc.
  inputs: RouteInput[];
  authentication: TriState;
  authorization: TriState;
  database: TriState;
  externalCalls: TriState;
  responseBehavior?: string;
  riskFlags: string[];
}

export interface GraphNode {
  id: string;
  type:
    | 'file'
    | 'module'
    | 'function'
    | 'class'
    | 'route'
    | 'input'
    | 'auth_check'
    | 'authorization_check'
    | 'db_op'
    | 'fs_op'
    | 'network_op'
    | 'redirect'
    | 'response'
    | 'config'
    | 'secret'
    | 'dependency';
  name: string;
  filePath: string;
  line?: number;
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  sourceId: string;
  targetId: string;
  relationship:
    | 'contains'
    | 'imports'
    | 'calls'
    | 'handles_route'
    | 'accepts_input'
    | 'validates'
    | 'authenticates'
    | 'authorizes'
    | 'queries_db'
    | 'reads_fs'
    | 'writes_fs'
    | 'fetches_network'
    | 'returns_response'
    | 'uses_secret'
    | 'uses_config'
    | 'flows_to'
    | 'unknown';
  confidence: Confidence;
}

export interface ApplicationGraph {
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
  routes: RouteDefinition[];
  modulesCount: number;
  filesCount: number;
  externalCallsCount: number;
  databaseOpsCount: number;
}

export interface DataFlowPath {
  id: string;
  source: {
    expression: string;
    filePath: string;
    line: number;
    kind: string;
  };
  sink: {
    expression: string;
    filePath: string;
    line: number;
    kind: 'sql' | 'exec' | 'eval' | 'fs' | 'ssrf' | 'xss' | 'redirect' | 'other';
  };
  transformations: Array<{
    expression: string;
    line: number;
  }>;
  confidence: Confidence;
  isSanitized: boolean;
}

export interface CorrelatedIssue {
  id: string; // e.g. VBG-CORR-001
  title: string;
  severity: Severity;
  confidence: Confidence;
  description: string;
  chain: string[]; // e.g. ["INPUT (req.query.id)", "DATABASE QUERY", "NO PARAMETERIZATION", "NO AUTHORIZATION"]
  filePath: string;
  line?: number;
  impact: string;
  remediation: string;
}
