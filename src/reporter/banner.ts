import pc from 'picocolors';

export interface BannerOptions {
  noColor?: boolean;
  compact?: boolean;
  terminalWidth?: number;
}

export const ASCII_LOGO = `
  _   _ ___ ___  ___   ___ _   _   _   ___  ___ 
 | | | |_ _| _ \\| __| / __| | | | /_\\ | _ \\|   \\
 | |_| || || _ <| _| | (_ | |_| |/ _ \\|   /| |) |
  \\___/|___|___/|___| \\___|\\___//_/ \\_\\_|_\\|____/
`.trim();

export const BLOCK_LOGO_WHITE = [
  "  ██╗   ██╗██╗██████╗ ███████╗██████╗ ██╗   ██║ █████╗ ██████╗ ██████╗ ",
  "  ██║   ██║██║██╔══██╗██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗",
  "  ██║   ██║██║██████╔╝█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║",
  "  ╚██╗ ██╔╝██║██╔══██╗██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║",
  "   ╚████╔╝ ██║██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝",
  "    ╚═══╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
];

export function renderBanner(options: BannerOptions = {}): string {
  const isNoColor = options.noColor || process.env.NO_COLOR !== undefined;
  const width = options.terminalWidth || process.stdout.columns || 80;

  // Narrow terminal (< 70 chars) or compact option: use compact logo
  if (options.compact || width < 70) {
    if (isNoColor) {
      return `[VIBEGUARD] AI Application Security Agent\n${'─'.repeat(40)}`;
    }
    return `${pc.cyan('◆')} ${pc.bold(pc.white('VIBEGUARD'))} ${pc.dim('│ AI Application Security Agent')}\n${pc.dim('─'.repeat(45))}`;
  }

  // Plain / no-color mode
  if (isNoColor) {
    return `${ASCII_LOGO}\n\n  AI APPLICATION SECURITY AGENT\n  ${'─'.repeat(30)}`;
  }

  // Modern Glitch ANSI Render (Cyan & Magenta offset layers + High contrast white core)
  const glitchBannerLines = BLOCK_LOGO_WHITE.map((line, idx) => {
    // Add subtle chromatic glitch offset to alternate lines
    if (idx % 2 === 0) {
      return `${pc.cyan(' ')}${pc.bold(pc.white(line))}`;
    } else {
      return `${pc.magenta(' ')}${pc.bold(pc.white(line))}`;
    }
  });

  const header = glitchBannerLines.join('\n');
  const tag = `  ${pc.bold(pc.cyan('AI APPLICATION SECURITY AGENT'))}`;
  const divider = `  ${pc.dim('─'.repeat(32))}`;

  return `\n${header}\n\n${tag}\n${divider}\n`;
}

export function renderCompactStatusMark(status: string, isNoColor = false): string {
  if (isNoColor) {
    return `[VIBEGUARD] ${status}`;
  }
  return `${pc.cyan('◆')} ${pc.bold('VibeGuard')} ${pc.dim('│')} ${status}`;
}
