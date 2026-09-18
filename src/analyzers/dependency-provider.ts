import { DependencyItem, Finding } from '../core/types.js';

export interface DependencyProvider {
  id: string;
  name: string;
  isAvailable(): boolean;
  checkVulnerabilities(dependencies: DependencyItem[]): Promise<Finding[]>;
}

export class LocalStaticDependencyProvider implements DependencyProvider {
  id = 'local-static-provider';
  name = 'Local Static Vulnerability Inventory Provider';

  isAvailable(): boolean {
    // Offline / static mode available by default
    return false; // Returns false for live database availability to indicate advisory database NOT AVAILABLE
  }

  async checkVulnerabilities(_dependencies: DependencyItem[]): Promise<Finding[]> {
    return [];
  }
}
