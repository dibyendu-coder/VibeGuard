import fs from 'fs';
import path from 'path';
import { z } from 'zod';
import { Severity, VibeGuardConfig } from '../core/types.js';

const SeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

export const VibeGuardConfigSchema = z.object({
  ignoredPaths: z.array(z.string()).default([
    'node_modules',
    '.git',
    'dist',
    'build',
    '.next',
    '.cache',
    'coverage',
    '.vibeguard',
  ]),
  failThreshold: SeveritySchema.default('HIGH'),
  enabledRules: z.array(z.string()).optional(),
  disabledRules: z.array(z.string()).optional(),
  privacy: z
    .object({
      telemetry: z.boolean().default(false),
      aiOptIn: z.boolean().default(false),
    })
    .default({ telemetry: false, aiOptIn: false }),
});

export const DEFAULT_CONFIG: VibeGuardConfig = {
  ignoredPaths: [
    'node_modules',
    '.git',
    'dist',
    'build',
    '.next',
    '.cache',
    'coverage',
    '.vibeguard',
  ],
  failThreshold: 'HIGH',
  privacy: {
    telemetry: false,
    aiOptIn: false,
  },
};

export function loadConfig(targetDir: string): VibeGuardConfig {
  const possibleFiles = [
    path.join(targetDir, '.vibeguardrc'),
    path.join(targetDir, 'vibeguard.config.json'),
    path.join(targetDir, '.vibeguardrc.json'),
  ];

  for (const configFile of possibleFiles) {
    if (fs.existsSync(configFile)) {
      try {
        const rawContent = fs.readFileSync(configFile, 'utf-8');
        const parsedJson = JSON.parse(rawContent);
        const validated = VibeGuardConfigSchema.parse(parsedJson);
        return validated;
      } catch (err) {
        // If config is malformed, fallback to default but don't fail discovery
        console.warn(`[VibeGuard] Warning: Failed to parse config at ${configFile}. Using defaults.`);
      }
    }
  }

  return DEFAULT_CONFIG;
}
