import { describe, expect, it } from 'vitest';
import { renderBanner, renderCompactStatusMark } from '../src/reporter/banner.ts';
import { maskSecret } from '../src/reporter/terminal.ts';

describe('Banner and Terminal Utilities', () => {
  it('renders ASCII logo when noColor is set to true', () => {
    const banner = renderBanner({ noColor: true, terminalWidth: 100 });
    expect(banner).toContain('AI APPLICATION SECURITY AGENT');
    expect(banner).toContain('___');
  });

  it('renders compact logo for narrow terminals (< 70 columns)', () => {
    const compactBanner = renderBanner({ noColor: false, terminalWidth: 60 });
    expect(compactBanner).toContain('VIBEGUARD');
    expect(compactBanner).not.toContain('██╗');
  });

  it('renders plain text compact status mark in noColor mode', () => {
    const statusMark = renderCompactStatusMark('Running scan', true);
    expect(statusMark).toBe('[VIBEGUARD] Running scan');
  });

  it('masks secret values correctly without exposing full keys', () => {
    const masked = maskSecret('sk_live_1234567890abcdef');
    expect(masked).toBe('sk_live_****************');
    expect(masked).not.toContain('1234567890abcdef');
  });
});
