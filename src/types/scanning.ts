/**
 * Types for technology currency scanning
 */

/**
 * Base issue interface with common properties
 */
export interface BaseIssue {
  // Name of the technology/component
  name: string;
  
  // Current version
  currentVersion?: string;
  
  // Latest available version
  latestVersion?: string;
  
  // Whether the component is outdated
  isOutdated?: boolean;
  
  // Whether the component is deprecated
  isDeprecated?: boolean;
  
  // Location in the system
  location: string;
  
  // When the issue was detected
  detectedAt: Date;
  
  // Vulnerabilities associated with this issue
  vulnerabilities?: VulnerabilityInfo[];
  
  // Business impact score (1-5)
  businessImpact?: number;
  
  // Security impact score (1-5)
  securityImpact?: number;
  
  // Estimated migration effort (1-5)
  migrationEffort?: number;
  
  // Recommended migration path
  migrationPath?: string;
  
  // Specific recommendation to fix the issue
  recommendation?: string;
  
  // Tags for categorization
  tags?: string[];
}

/**
 * Framework or technology issue
 */
export interface FrameworkIssue extends BaseIssue {
  // Framework category
  category: 'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other';
  
  // Framework type (e.g., 'js-framework', 'php-cms', 'database')
  type: string;
  
  // End of life date
  endOfLifeDate?: Date;
  
  // End of support date
  endOfSupportDate?: Date;
}

/**
 * Browser extension issue
 */
export interface BrowserExtensionIssue extends BaseIssue {
  // Extension ID
  id: string;
  
  // Browser this extension is for
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera';
  
  // Whether the extension has been removed from the store
  isRemovedFromStore?: boolean;
  
  // Whether the extension has security issues
  hasSecurityIssues?: boolean;
  
  // Store URL
  storeUrl?: string;
}

/**
 * Dependency issue
 */
export interface DependencyIssue extends BaseIssue {
  // Dependency type
  type: 'npm' | 'pip' | 'gem' | 'composer' | 'maven' | 'gradle' | 'nuget' | 'cargo' | 'go';
  
  // Whether it's unused
  isUnused?: boolean;
  
  // License compliance issue
  licenseIssue?: {
    issue: string;
    severity: 'low' | 'medium' | 'high';
  };
}

/**
 * System component issue
 */
export interface SystemComponentIssue extends BaseIssue {
  // Component type
  type: 'os' | 'runtime' | 'database' | 'container' | 'vm' | 'library' | 'api' | 'other';
  
  // Environment
  environment: 'development' | 'testing' | 'staging' | 'production' | 'other';
  
  // Whether it's a critical component
  isCritical?: boolean;
  
  // End of life date
  endOfLifeDate?: Date;
  
  // End of support date
  endOfSupportDate?: Date;
}

/**
 * API issue
 */
export interface ApiIssue extends BaseIssue {
  // API type
  type: 'rest' | 'graphql' | 'grpc' | 'soap' | 'other';
  
  // API version
  version: string;
  
  // Provider of the API
  provider: string;
  
  // Whether it's a critical API
  isCritical?: boolean;
  
  // End of life date
  endOfLifeDate?: Date;
}

/**
 * Vulnerability information
 */
export interface VulnerabilityInfo {
  // Vulnerability ID (e.g., CVE)
  id: string;
  
  // Severity level
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // CVSS score
  cvssScore?: number;
  
  // Vulnerability title
  title: string;
  
  // Detailed description
  description: string;
  
  // URL for more information
  infoUrl?: string;
  
  // Published date
  publishedDate?: Date;
  
  // Affected versions
  affectedVersions?: string;
  
  // Patched versions
  patchedVersions?: string;
  
  // Recommendation to fix
  recommendation?: string;
}

/**
 * Scan result
 */
export interface ScanResult {
  // Scan timestamp
  timestamp: Date;
  
  // Scan ID
  id: string;
  
  // Framework issues
  frameworkIssues: FrameworkIssue[];
  
  // Browser extension issues
  extensionIssues: BrowserExtensionIssue[];
  
  // Dependency issues
  dependencyIssues: DependencyIssue[];
  
  // System component issues
  systemIssues: SystemComponentIssue[];
  
  // API issues
  apiIssues: ApiIssue[];
  
  // Summary metrics
  summary: {
    // Total issues found
    totalIssues: number;
    
    // Issues by severity
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
    
    // Issues by category
    frameworkIssuesCount: number;
    extensionIssuesCount: number;
    dependencyIssuesCount: number;
    systemIssuesCount: number;
    apiIssuesCount: number;
    
    // Vulnerabilities
    vulnerabilitiesCount: number;
    
    // Technical debt score (calculated from all issues)
    technicalDebtScore: number;
  };
  
  // Scan configuration
  config: {
    scanTypes: string[];
    targetDirectory: string;
    scanDepth: 'shallow' | 'normal' | 'deep';
    includedPatterns: string[];
    excludedPatterns: string[];
  };
}

/**
 * Report configuration
 */
export interface ReportConfig {
  // Report format
  format: 'html' | 'pdf' | 'json' | 'csv' | 'markdown';
  
  // Report title
  title: string;
  
  // Include executive summary
  includeExecutiveSummary: boolean;
  
  // Include recommendations
  includeRecommendations: boolean;
  
  // Include detailed issues
  includeDetailedIssues: boolean;
  
  // Include vulnerability details
  includeVulnerabilities: boolean;
  
  // Include charts and visualizations
  includeCharts: boolean;
  
  // Group issues by
  groupBy: 'severity' | 'type' | 'location' | 'none';
  
  // Minimum severity to include
  minimumSeverity: 'low' | 'medium' | 'high' | 'critical';
  
  // Output path
  outputPath: string;
}

/**
 * Notification configuration
 */
export interface NotificationConfig {
  // Enable notifications
  enabled: boolean;
  
  // Notification channels
  channels: Array<'email' | 'slack' | 'teams' | 'webhook'>;
  
  // Notification recipients
  recipients: string[];
  
  // Minimum severity to notify
  minimumSeverity: 'low' | 'medium' | 'high' | 'critical';
  
  // Include vulnerability details
  includeVulnerabilities: boolean;
  
  // Include recommendations
  includeRecommendations: boolean;
  
  // Channel-specific configuration
  channelConfig: {
    email?: {
      smtpServer: string;
      smtpPort: number;
      fromAddress: string;
      subject: string;
      useTls: boolean;
    };
    slack?: {
      webhookUrl: string;
      channel: string;
    };
    teams?: {
      webhookUrl: string;
    };
    webhook?: {
      url: string;
      headers: Record<string, string>;
      method: 'POST' | 'PUT';
    };
  };
}
