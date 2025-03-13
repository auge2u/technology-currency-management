/**
 * Represents an outdated technology detected in the codebase
 */
export interface OutdatedTechnology {
  /** Unique identifier for the finding */
  id: string;
  /** Name of the technology or pattern detected */
  technology: string;
  /** Path to the file where the outdated technology was found */
  filePath: string;
  /** Line number in the file */
  lineNumber: number;
  /** Content of the line where the issue was found */
  lineContent: string;
  /** Severity level of the issue */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Description of why this is an issue */
  message: string;
  /** Recommended version to upgrade to */
  recommendedVersion: string;
  /** Steps to remediate the issue */
  remediationSteps: string;
  /** ID of the rule that detected this issue */
  ruleId: string;
  /** When the issue was detected */
  detectedAt: Date;
}

/**
 * Represents an outdated dependency in package.json, requirements.txt, etc.
 */
export interface OutdatedDependency {
  /** Unique identifier for the finding */
  id: string;
  /** Name of the dependency package */
  packageName: string;
  /** Current version being used */
  currentVersion: string;
  /** Latest available version */
  latestVersion: string;
  /** Version difference type (patch, minor, major) */
  updateType: 'patch' | 'minor' | 'major' | 'unknown';
  /** Path to the file defining this dependency */
  filePath: string;
  /** When the dependency was last updated */
  lastUpdated?: Date;
  /** Number of versions behind latest */
  versionsBehind?: number;
  /** Severity level based on how outdated and critical the package is */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Whether the outdated version has known security vulnerabilities */
  hasSecurityIssues: boolean;
  /** Steps to update the dependency */
  updateSteps: string;
  /** When the issue was detected */
  detectedAt: Date;
}

/**
 * Represents a security vulnerability found in dependencies
 */
export interface SecurityVulnerability {
  /** Unique identifier for the vulnerability */
  id: string;
  /** CVE ID if available */
  cveId?: string;
  /** Name of the affected dependency */
  packageName: string;
  /** Version range affected by the vulnerability */
  affectedVersions: string;
  /** Severity of the vulnerability */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Brief description of the vulnerability */
  description: string;
  /** URL to vulnerability details */
  infoUrl?: string;
  /** Versions that fix the vulnerability */
  patchedVersions: string;
  /** Path to the file defining this dependency */
  filePath: string;
  /** Steps to remediate the vulnerability */
  remediationSteps: string;
  /** When the vulnerability was published */
  publishedDate?: Date;
  /** When the issue was detected */
  detectedAt: Date;
}

/**
 * Represents an outdated or problematic browser extension
 */
export interface BrowserExtensionIssue {
  /** Unique identifier for the finding */
  id: string;
  /** Name of the browser extension */
  extensionName: string;
  /** Current version of the extension */
  currentVersion: string;
  /** Latest available version */
  latestVersion: string;
  /** Browser(s) the extension is used in */
  browsers: Array<'Chrome' | 'Firefox' | 'Safari' | 'Edge'>;
  /** Type of issue with the extension */
  issueType: 'outdated' | 'deprecated' | 'security' | 'compatibility';
  /** Severity level of the issue */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Description of the issue */
  description: string;
  /** Steps to update or replace the extension */
  remediationSteps: string;
  /** When the issue was detected */
  detectedAt: Date;
}

/**
 * Configuration for running scans
 */
export interface ScanConfig {
  /** Root directory to scan */
  rootDir: string;
  /** Whether to include node_modules */
  includeNodeModules: boolean;
  /** Whether to include dev dependencies */
  includeDevDependencies: boolean;
  /** Maximum depth for directory traversal */
  maxDepth?: number;
  /** File patterns to include */
  includePatterns: string[];
  /** File patterns to exclude */
  excludePatterns: string[];
  /** Minimum severity level to report */
  minSeverity: 'low' | 'medium' | 'high' | 'critical';
  /** Types of scans to run */
  scanTypes: Array<'technology' | 'dependency' | 'security' | 'browser-extension'>;
}

/**
 * Combined scan results across all scan types
 */
export interface ScanResult {
  /** Unique identifier for this scan */
  scanId: string;
  /** When the scan was started */
  startTime: Date;
  /** When the scan was completed */
  endTime: Date;
  /** Configuration used for the scan */
  config: ScanConfig;
  /** Technology patterns detected */
  technologies: OutdatedTechnology[];
  /** Outdated dependencies detected */
  dependencies: OutdatedDependency[];
  /** Security vulnerabilities detected */
  vulnerabilities: SecurityVulnerability[];
  /** Browser extension issues detected */
  browserExtensions: BrowserExtensionIssue[];
  /** Total issues found */
  totalIssues: number;
  /** Issues by severity */
  issuesBySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** Issues by type */
  issuesByType: {
    technology: number;
    dependency: number;
    security: number;
    browserExtension: number;
  };
}
