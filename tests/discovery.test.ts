import path from 'path';
import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../src/config/loader.ts';
import { discoverProject } from '../src/discovery/detector.ts';

describe('Project Discovery Engine', () => {
  it('detects Next.js, React, and Supabase in sample-nextjs fixture', () => {
    const fixtureDir = path.resolve(__dirname, '../fixtures/sample-nextjs');
    const manifest = discoverProject(fixtureDir, DEFAULT_CONFIG);

    expect(manifest.projectName).toBe('sample-nextjs');
    expect(manifest.languages).toContain('JavaScript');
    expect(manifest.frameworks.map((f) => f.name)).toContain('Next.js');
    expect(manifest.frameworks.map((f) => f.name)).toContain('React');
    expect(manifest.frameworks.map((f) => f.name)).toContain('Supabase JS');
    expect(manifest.envFiles).toContain('.env');
    expect(manifest.packageManifests).toContain('package.json');
  });

  it('detects FastAPI in sample-python fixture', () => {
    const fixtureDir = path.resolve(__dirname, '../fixtures/sample-python');
    const manifest = discoverProject(fixtureDir, DEFAULT_CONFIG);

    expect(manifest.languages).toContain('Python');
    expect(manifest.frameworks.map((f) => f.name)).toContain('FastAPI');
  });

  it('handles empty fixture without crashing', () => {
    const fixtureDir = path.resolve(__dirname, '../fixtures/sample-empty');
    const manifest = discoverProject(fixtureDir, DEFAULT_CONFIG);

    expect(manifest.projectName).toBe('sample-empty');
    expect(manifest.frameworks).toHaveLength(0);
  });
});
