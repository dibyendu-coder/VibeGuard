import { Finding, ScanContext, ScanResult } from '../core/types.js';

export interface Analyzer {
  id: string;
  name: string;
  category: string;
  supportedLanguages?: string[];
  supportedFrameworks?: string[];
  analyze(context: ScanContext): Promise<Finding[]>;
}

export interface AIProviderAdapter {
  id: string;
  name: string;
  isConfigured(): boolean;
  explain(finding: Finding, context: ScanContext): Promise<string>;
  summarize(scanResult: ScanResult): Promise<string>;
  recommend(finding: Finding, context: ScanContext): Promise<string>;
}
