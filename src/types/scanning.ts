/**
 * Common severity levels for issues
 */
export type OutdatedTechnologySeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Represents an outdated technology detected in scans
 */
export interface OutdatedTechnology {
  id: string;
  technology: string;
  filePath: string;
  lineNumber?: number;
  lineContent?: string;
  severity: OutdatedTechnologySeverity;
  message: string;
  recommendedVersion: string;
  remediationSteps: string;
  ruleId: string;
  detectedAt: Date;
}

/**
 * Represents an outdated dependency detected in scans
 */
export interface OutdatedDependency {
  name: string;
  currentVersion: string;
  latestVersion: string;
  packageManager: 'npm' | 'yarn' | 'pnpm' | 'pip' | 'gem' | 'composer' | 'maven' | 'gradle' | 'other';
  filePath: string;
  isDirectDependency: boolean;
  isDev: boolean;
  isDeprecated?: boolean;
  severity: OutdatedTechnologySeverity;
  breakingChanges?: boolean;
  remediationSteps: string;
  releaseDate?: Date;
  detectedAt: Date;
}

/**
 * Represents a security vulnerability detected in scans
 */
export interface SecurityVulnerability {
  id: string;
  packageName: string;
  version: string;
  title: string;
  description: string;
  cve: string[];
  cvss?: number;
  fixedIn?: string;
  exploitAvailable: boolean;
  severity: OutdatedTechnologySeverity;
  publicationDate?: Date;
  remediationSteps: string;
  references: string[];
  detectedAt: Date;
}

/**
 * Represents an outdated browser extension detected in scans
 */
export interface OutdatedExtension {
  id: string;
  name: string;
  browser: 'chrome' | 'firefox' | 'safari' | 'edge';
  currentVersion: string;
  latestVersion: string;
  manifestPath: string;
  severity: OutdatedTechnologySeverity;
  hasSecurityIssues: boolean;
  hasCompatibilityIssues: boolean;
  isDeprecated: boolean;
  updateUrl?: string;
  detectedAt: Date;
}

/**
 * Represents a result of a scan
 */
export interface ScanResult {
  id: string;
  scanType: 'dependency' | 'technology' | 'security' | 'extension' | 'all';
  startedAt: Date;
  completedAt?: Date;
  findings: number;
  scanStatus: 'running' | 'completed' | 'failed';
  errorMessage?: string;
}

/**
 * Represents the output of a technological currency report
 */
export interface TechnologyCurrencyReport {
  scanId: string;
  scanDate: Date;
  outdatedTechnologies: OutdatedTechnology[];
  outdatedDependencies: OutdatedDependency[];
  securityVulnerabilities: SecurityVulnerability[];
  outdatedExtensions: OutdatedExtension[];
  summary: {
    totalIssues: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    outdatedTechnologiesCount: number;
    outdatedDependenciesCount: number;
    securityVulnerabilitiesCount: number;
    outdatedExtensionsCount: number;
  };
}

/**
 * Represents a webhook notification payload
 */
export interface WebhookNotificationPayload {
  scanId: string;
  scanDate: Date;
  summary: {
    totalIssues: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  criticalIssues: Array<OutdatedTechnology | OutdatedDependency | SecurityVulnerability | OutdatedExtension>;
  highIssues: Array<OutdatedTechnology | OutdatedDependency | SecurityVulnerability | OutdatedExtension>;
}
