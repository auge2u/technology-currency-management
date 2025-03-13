/**
 * Types for scanning functionalities
 */

/**
 * Represents a common structure for all detected issues
 */
export interface BaseIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Risk level of the issue
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Tags for categorizing and filtering issues
  tags: string[];
  
  // Recommendation for resolving the issue
  recommendation: string;
}

/**
 * Issue related to outdated or vulnerable dependencies
 */
export interface DependencyIssue extends BaseIssue {
  // Name of the package
  packageName: string;
  
  // Current installed version
  currentVersion: string;
  
  // Latest available version (if known)
  latestVersion?: string;
  
  // Package manager for this dependency
  packageManager: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget';
  
  // Whether this is a direct dependency
  isDirect: boolean;
  
  // Whether the dependency is outdated
  isOutdated: boolean;
  
  // Whether the dependency has security vulnerabilities
  isVulnerable: boolean;
  
  // Details about detected vulnerabilities
  vulnerabilities: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    fixedInVersion?: string;
    url?: string;
  }>;
  
  // Files that depend on this package
  dependentFiles: string[];
  
  // Assessment of the impact of updating
  updateImpact: {
    breakingChanges: boolean;
    affectedComponents?: string[];
    estimatedEffort: 'low' | 'medium' | 'high';
  };
}

/**
 * Issue related to outdated or deprecated technologies
 */
export interface TechnologyIssue extends BaseIssue {
  // Name of the technology
  name: string;
  
  // Category of technology
  category: 'framework' | 'library' | 'language' | 'runtime' | 'platform' | 'api' | 'other';
  
  // Current version being used
  currentVersion: string;
  
  // Latest available version (if known)
  latestVersion?: string;
  
  // Whether the technology is deprecated
  isDeprecated: boolean;
  
  // Whether the technology is outdated
  isOutdated: boolean;
  
  // End of life date (if known)
  endOfLifeDate?: Date;
  
  // Remaining time until end of life (in days)
  daysUntilEndOfLife?: number;
  
  // Status of support
  supportStatus: 'active' | 'maintenance' | 'security-only' | 'end-of-life' | 'unknown';
  
  // Known issues or limitations with the current version
  knownIssues?: string[];
  
  // Files using this technology
  affectedFiles: string[];
  
  // Alternative technologies that could be used
  alternatives?: string[];
  
  // Assessment of the impact of updating/replacing
  updateImpact: {
    breakingChanges: boolean;
    affectedComponents?: string[];
    estimatedEffort: 'low' | 'medium' | 'high';
    estimatedTimeInDays?: number;
  };
}

/**
 * Issue related to outdated or deprecated browser extensions
 */
export interface BrowserExtensionIssue extends BaseIssue {
  // Name of the extension
  extensionName: string;
  
  // ID of the extension in the browser store
  extensionId?: string;
  
  // Browser this extension is for
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'multiple';
  
  // Current installed version
  currentVersion: string;
  
  // Latest available version (if known)
  latestVersion?: string;
  
  // Is the extension outdated
  isOutdated: boolean;
  
  // Is the extension deprecated by the developer
  isDeprecated: boolean;
  
  // Is the extension no longer compatible with browser updates
  isIncompatible: boolean;
  
  // Does the extension have security vulnerabilities
  hasSecurityIssues: boolean;
  
  // Details about security vulnerabilities
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
  }>;
  
  // Last update date
  lastUpdated?: Date;
  
  // Is the extension still maintained
  isMaintained: boolean;
  
  // Alternative extensions that could be used
  alternatives?: string[];
  
  // Assessment of the impact of updating/replacing
  updateImpact: {
    userImpact: 'low' | 'medium' | 'high';
    businessProcessesAffected?: string[];
    estimatedEffort: 'low' | 'medium' | 'high';
  };
}

/**
 * Configuration for a technology scanner
 */
export interface ScannerConfig {
  // ID of the scan
  scanId?: string;
  
  // Base directory to scan
  rootDir: string;
  
  // Scan name
  scanName?: string;
  
  // Output directory for reports
  outputDir?: string;
  
  // Paths to exclude from scanning
  excludePaths?: string[];
  
  // Maximum file size to scan (in bytes)
  maxFileSizeBytes?: number;
  
  // Timeout for scans (in milliseconds)
  timeoutMs?: number;
  
  // Output formats
  outputFormats?: Array<'json' | 'html' | 'csv' | 'markdown'>;
  
  // Scan only files modified since date
  modifiedSince?: Date;
  
  // Minimum risk level to report
  minRiskLevel?: 'low' | 'medium' | 'high' | 'critical';
  
  // Whether to scan dependencies
  includeDependencies?: boolean;
  
  // Whether to scan technologies
  includeTechnologies?: boolean;
  
  // Whether to scan browser extensions
  includeBrowserExtensions?: boolean;
  
  // Settings for the notification system
  notifications?: {
    // Whether to send notifications
    enabled: boolean;
    // Channels to send notifications to
    channels?: Array<'email' | 'slack' | 'teams' | 'webhook'>;
    // Email settings
    email?: {
      recipients: string[];
      subject?: string;
    };
    // Slack settings
    slack?: {
      webhookUrl: string;
      channel?: string;
    };
    // Teams settings
    teams?: {
      webhookUrl: string;
    };
    // Custom webhook settings
    webhook?: {
      url: string;
      headers?: Record<string, string>;
    };
  };
  
  // Custom rules to override default behavior
  customRules?: {
    // Rules to ignore specific issues
    ignoreIssues?: Array<{
      type: 'dependency' | 'technology' | 'browser-extension';
      name: string;
      reason: string;
      expirationDate?: Date;
    }>;
    // Rules to override risk levels
    riskLevelOverrides?: Array<{
      type: 'dependency' | 'technology' | 'browser-extension';
      name: string;
      riskLevel: 'low' | 'medium' | 'high' | 'critical';
      reason: string;
    }>;
  };
}

/**
 * Result of a scan operation
 */
export interface ScanResult {
  // ID of the scan
  scanId: string;
  
  // When the scan started
  startTime: Date;
  
  // When the scan completed
  endTime: Date;
  
  // Duration of the scan in milliseconds
  durationMs: number;
  
  // Number of files scanned
  filesScanned: number;
  
  // Number of issues found
  totalIssuesFound: number;
  
  // Statistics about issues by risk level
  issuesByRiskLevel: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  
  // Dependency issues found
  dependencyIssues: DependencyIssue[];
  
  // Technology issues found
  technologyIssues: TechnologyIssue[];
  
  // Browser extension issues found
  browserExtensionIssues: BrowserExtensionIssue[];
  
  // Files that could not be scanned
  unscannableFiles?: Array<{
    path: string;
    reason: string;
  }>;
  
  // Error details if the scan failed
  error?: {
    message: string;
    stack?: string;
  };
  
  // Scan configuration used
  config: ScannerConfig;
  
  // Paths to generated reports
  reportPaths?: Record<string, string>;
}

/**
 * Interface for scanner module implementations
 */
export interface Scanner {
  /**
   * Configure the scanner
   * @param config Scanner configuration
   */
  configure(config: ScannerConfig): Promise<void>;
  
  /**
   * Run the scan
   * @returns Scan result
   */
  scan(): Promise<ScanResult>;
  
  /**
   * Generate reports from scan results
   * @param result Scan result
   * @param formats Output formats
   * @returns Paths to generated reports
   */
  generateReports(
    result: ScanResult,
    formats: Array<'json' | 'html' | 'csv' | 'markdown'>
  ): Promise<Record<string, string>>;
}
