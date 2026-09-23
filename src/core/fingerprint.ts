import crypto from 'crypto';

/**
 * Computes a deterministic SHA-256 fingerprint for a finding based on
 * rule ID, normalized file path, category, and normalized snippet.
 * Line number is intentionally excluded from fingerprint calculation
 * so minor source code line shifts do not create duplicate findings.
 */
export function generateFingerprint(
  ruleId: string,
  filePath: string,
  categoryOrLine?: string | number,
  snippet?: string | number
): string {
  const normalizedPath = (filePath || '').replace(/\\/g, '/');
  const snippetStr = typeof snippet === 'string' ? snippet : typeof snippet === 'number' ? String(snippet) : '';
  const normalizedSnippet = snippetStr.trim().replace(/\s+/g, ' ');
  const category = typeof categoryOrLine === 'string' ? categoryOrLine : '';
  const raw = `${ruleId}:${normalizedPath}:${category}:${normalizedSnippet}`;
  return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);
}
