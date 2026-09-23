const KNOWN_PREFIXES = [
  'vbg_test_',
  'sk_live_',
  'sk_test_',
  'pk_live_',
  'pk_test_',
  'sk-ant-',
  'sk-',
  'ghp_',
  'gho_',
  'ghu_',
  'ghs_',
  'ghr_',
  'xoxb-',
  'xoxp-',
  'xoxa-',
  'xoxr-',
  'AIza',
  'AKIA',
  'SG.',
];

/**
 * Masks a secret string safely, preserving a short recognizable prefix
 * and replacing the sensitive portion with asterisks.
 * e.g. sk_live_123456789abcdef -> sk_live_****************
 */
export function maskSecret(val: string): string {
  if (!val) return '******';
  const trimmed = val.trim();
  if (trimmed.length <= 6) {
    return '******';
  }

  // Handle URL with embedded password e.g. postgres://user:password@host:port/db
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)(.*)$/);
  if (schemeMatch) {
    const [, protocol, body] = schemeMatch;
    const lastAtIdx = body.lastIndexOf('@');
    if (lastAtIdx > 0) {
      const creds = body.substring(0, lastAtIdx);
      const rest = body.substring(lastAtIdx);
      const firstColonIdx = creds.indexOf(':');
      if (firstColonIdx > 0) {
        const user = creds.substring(0, firstColonIdx);
        return `${protocol}${user}:********${rest}`;
      }
    }
  }

  // Check known prefixes
  for (const prefix of KNOWN_PREFIXES) {
    if (trimmed.startsWith(prefix)) {
      const restLen = Math.max(6, trimmed.length - prefix.length);
      return `${prefix}${'*'.repeat(restLen)}`;
    }
  }

  // Generic prefix masking
  const visiblePrefixLen = Math.min(4, Math.floor(trimmed.length / 3));
  const prefix = trimmed.slice(0, visiblePrefixLen);
  return `${prefix}${'*'.repeat(Math.max(6, trimmed.length - visiblePrefixLen))}`;
}

/**
 * Searches code snippets and masks potential credentials/tokens within them.
 */
export function maskSnippet(snippet: string): string {
  if (!snippet) return '';

  let result = snippet;

  // Mask known secret formats inside snippet
  // 1. Connection strings
  result = result.replace(
    /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^:\s'"`]+):([^@\s'"`]+)(@[^\s'"`]+)/g,
    (_match, proto, user, _pass, rest) => `${proto}${user}:********${rest}`
  );

  // 2. Known token formats
  for (const prefix of KNOWN_PREFIXES) {
    const escaped = prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escaped})([A-Za-z0-9_\\-]{6,})`, 'g');
    result = result.replace(regex, (_match, pfx, rest) => `${pfx}${'*'.repeat(Math.max(6, rest.length))}`);
  }

  // 3. Key/secret assignments: e.g. API_KEY="sk_live_..." or secret: "..."
  result = result.replace(
    /((?:key|secret|token|password|passwd|api[_-]?key|auth[_-]?token)\s*[:=]\s*["'])([^"'\s]{6,})(["'])/gi,
    (_match, leader, secretVal, trailer) => `${leader}${maskSecret(secretVal)}${trailer}`
  );

  return result;
}
