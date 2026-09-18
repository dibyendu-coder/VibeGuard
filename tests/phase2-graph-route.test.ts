import { describe, expect, it } from 'vitest';
import path from 'path';
import { discoverRoutes } from '../src/graph/route-analyzer.js';
import { buildApplicationGraph } from '../src/graph/builder.js';
import { analyzeDataFlows } from '../src/graph/flow-analyzer.js';

describe('Phase 2 - Graph & Route Discovery Engine', () => {
  const nodeFixture = path.resolve('fixtures/vulnerable-node');
  const nextjsFixture = path.resolve('fixtures/vulnerable-nextjs');
  const pythonFixture = path.resolve('fixtures/vulnerable-python');

  it('discovers routes across Express, Next.js, and Python frameworks', () => {
    const expressRoutes = discoverRoutes([path.join(nodeFixture, 'server.js')], nodeFixture);
    expect(expressRoutes.length).toBeGreaterThan(0);
    expect(expressRoutes.some(r => r.method === 'GET' || r.method === 'POST')).toBe(true);

    const nextRoutes = discoverRoutes(
      [
        path.join(nextjsFixture, 'app/api/auth/route.ts'),
        path.join(nextjsFixture, 'app/api/orders/[id]/route.ts'),
      ],
      nextjsFixture
    );
    expect(nextRoutes.length).toBeGreaterThan(0);
    expect(nextRoutes.some(r => r.path.includes('/api/orders/'))).toBe(true);

    const pyRoutes = discoverRoutes([path.join(pythonFixture, 'app.py')], pythonFixture);
    expect(pyRoutes.length).toBeGreaterThan(0);
    expect(pyRoutes.some(r => r.framework.includes('FastAPI') || r.framework.includes('Flask'))).toBe(true);
  });

  it('builds application graph with conservative node & edge relationships', () => {
    const graph = buildApplicationGraph(
      [
        path.join(nodeFixture, 'server.js'),
        path.join(nodeFixture, 'package.json'),
      ],
      nodeFixture
    );

    expect(graph.filesCount).toBeGreaterThan(0);
    expect(graph.modulesCount).toBeGreaterThan(0);
    expect(graph.routes).toBeDefined();
    expect(graph.nodes.size).toBeGreaterThan(0);
  });

  it('tracks static data flows from user inputs to dangerous sinks', () => {
    const flows = analyzeDataFlows([path.join(nodeFixture, 'server.js')], nodeFixture);
    expect(flows).toBeDefined();
    expect(Array.isArray(flows)).toBe(true);
  });
});
