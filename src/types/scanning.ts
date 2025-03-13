/**
 * Base issue interface that all specific issues extend
 */
export interface BaseIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Business impact score (1-5)
  businessImpact?: number;
  
  // Recommended action
  recommendation?: string;
  
  // Categorization tags
  tags?: string[];
  
  // Where the issue was found
  location: string;
}

/**
 * Dependency issue (npm packages, pip packages, gems, etc.)
 */
export interface DependencyIssue extends BaseIssue {
  // Name of the dependency
  name: string;
  
  // Type of dependency (npm, pip, etc.)
  type: string;
  
  // Current version installed
  currentVersion: string;
  
  // Latest version available
  latestVersion: string;
  
  // Whether the dependency is outdated
  isOutdated: boolean;
  
  // Whether the dependency is deprecated
  isDeprecated: boolean;
  
  // Whether the dependency is unused
  isUnused?: boolean;
  
  // License issue if any
  licenseIssue?: {
    issue: string;
    severity: 'low' | 'medium' | 'high';
  };
  
  // Security vulnerabilities
  vulnerabilities?: VulnerabilityInfo[];
  
  // Security impact score (1-5)
  securityImpact?: number;
  
  // Migration effort score (1-5)
  migrationEffort?: number;
}

/**
 * Browser extension issue
 */
export interface ExtensionIssue extends BaseIssue {
  // Extension identifier
  id: string;
  
  // Extension name
  name: string;
  
  // Browser (chrome, firefox, edge, safari)
  browser: string;
  
  // Current version installed
  currentVersion: string;
  
  // Latest version available
  latestVersion: string;
  
  // Whether the extension is outdated
  isOutdated: boolean;
  
  // Whether the extension is deprecated
  isDeprecated: boolean;
  
  // Whether the extension has been removed from the store
  isRemoved: boolean;
  
  // Number of users
  userCount?: number;
  
  // Rating in extension store
  rating?: number;
  
  // Link to extension in store
  storeUrl?: string;
  
  // Last update timestamp
  lastUpdated?: Date;
  
  // When the latest version was released
  latestUpdateDate?: Date;
  
  // Security vulnerabilities
  vulnerabilities?: Array<{
    id: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
  }>;
}

/**
 * Framework, language or platform issue
 */
export interface FrameworkIssue extends BaseIssue {
  // Framework name
  name: string;
  
  // Framework type (nodejs, python, react, etc.)
  type: string;
  
  // Current version
  currentVersion: string;
  
  // Latest version available
  latestVersion: string;
  
  // Latest LTS version if applicable
  latestLtsVersion?: string;
  
  // Whether the framework is outdated
  isOutdated: boolean;
  
  // Whether the framework is deprecated
  isDeprecated: boolean;
  
  // Whether the framework is end-of-life
  isEol: boolean;
  
  // Current support status
  supportStatus: 'supported' | 'maintenance' | 'deprecated' | 'eol';
  
  // When support ends
  supportEndDate?: Date;
  
  // Migration effort score (1-5)
  migrationEffort?: number;
  
  // Security vulnerabilities
  vulnerabilities?: Array<{
    id: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
  }>;
  
  // URL to migration guide
  migrationGuideUrl?: string;
  
  // URL to release notes
  releaseNotesUrl?: string;
}

/**
 * Information about a security vulnerability
 */
export interface VulnerabilityInfo {
  // Vulnerability identifier
  id: string;
  
  // Severity level
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // Short title
  title: string;
  
  // Detailed description
  description: string;
  
  // When the vulnerability was published
  publishedDate?: Date;
  
  // Affected version range
  affectedVersions?: string;
  
  // Versions that include a fix
  patchedVersions?: string;
  
  // Recommended action
  recommendation?: string;
  
  // URL to vulnerability details
  url?: string;
  
  // CVSS score if available
  cvssScore?: number;
}

/**
 * Scanning result containing all issues
 */
export interface ScanningResult {
  // When the scan was performed
  scanTime: Date;
  
  // Dependency issues
  dependencyIssues: DependencyIssue[];
  
  // Extension issues
  extensionIssues: ExtensionIssue[];
  
  // Framework issues
  frameworkIssues: FrameworkIssue[];
  
  // Summary stats
  summary: {
    totalIssues: number;
    highImpactIssues: number;
    securityIssues: number;
    deprecatedTechnologies: number;
    outdatedDependencies: number;
    endOfLifeComponents: number;
  };
}

/**
 * Technical debt report
 */
export interface TechnicalDebtReport {
  // When the report was generated
  generatedAt: Date;
  
  // Overall health score (0-100)
  healthScore: number;
  
  // Debt categories
  categories: {
    securityDebt: number;
    compatibilityDebt: number;
    performanceDebt: number;
    supportabilityDebt: number;
  };
  
  // Issues organized by priority
  issuesByPriority: {
    critical: Array<DependencyIssue | ExtensionIssue | FrameworkIssue>;
    high: Array<DependencyIssue | ExtensionIssue | FrameworkIssue>;
    medium: Array<DependencyIssue | ExtensionIssue | FrameworkIssue>;
    low: Array<DependencyIssue | ExtensionIssue | FrameworkIssue>;
  };
  
  // Top recommendations
  recommendations: string[];
  
  // Historical metrics
  historicalMetrics?: {
    timestamp: Date;
    healthScore: number;
    totalIssues: number;
  }[];
}

/**
 * Notification settings
 */
export interface NotificationSettings {
  // Who to notify
  recipients: string[];
  
  // Notification channels
  channels: Array<'email' | 'slack' | 'teams' | 'webhook'>;
  
  // Notification thresholds
  thresholds: {
    securityIssues: 'all' | 'criticalOnly' | 'highAndAbove';
    outdatedDependencies: 'all' | 'majorOnly' | 'criticalOnly';
    deprecatedTechnologies: boolean;
    endOfLifeComponents: boolean;
  };
  
  // Notification frequency
  frequency: 'immediate' | 'daily' | 'weekly';
  
  // Notification templates
  templates?: {
    email?: {
      subject: string;
      body: string;
    };
    slack?: {
      title: string;
      message: string;
    };
  };
  
  // Integration settings
  integrationSettings?: {
    slack?: {
      webhookUrl: string;
      channel: string;
    };
    teams?: {
      webhookUrl: string;
    };
    email?: {
      smtpServer: string;
      port: number;
      username: string;
      password: string;
      from: string;
    };
    webhook?: {
      url: string;
      method: 'GET' | 'POST';
      headers?: Record<string, string>;
    };
  };
}

/**
 * Version control integration settings
 */
export interface VersionControlSettings {
  // Provider type
  provider: 'github' | 'gitlab' | 'bitbucket' | 'azure-devops';
  
  // API token or credentials
  credentials: {
    token?: string;
    username?: string;
    password?: string;
  };
  
  // Repository information
  repository: {
    owner: string;
    name: string;
    branch?: string;
  };
  
  // Pull request settings
  pullRequestSettings?: {
    enabled: boolean;
    automatic: boolean;
    prefix: string;
    assignees?: string[];
    reviewers?: string[];
    labels?: string[];
  };
  
  // Issue tracking settings
  issueSettings?: {
    enabled: boolean;
    automatic: boolean;
    prefix: string;
    labels?: string[];
  };
  
  // Hook settings
  hookSettings?: {
    preCommit: boolean;
    preReceive: boolean;
  };
}

/**
 * Scanner configuration
 */
export interface ScannerConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Scanners to run
  enabledScanners: {
    dependencies: boolean;
    extensions: boolean;
    frameworks: boolean;
  };
  
  // Scanner-specific configurations
  dependencyScannerConfig?: any;
  extensionScannerConfig?: any;
  frameworkScannerConfig?: any;
  
  // Whether to use offline mode
  offlineMode: boolean;
  
  // Output directory for reports
  outputDir: string;
  
  // Notification settings
  notificationSettings?: NotificationSettings;
  
  // Version control settings
  versionControlSettings?: VersionControlSettings;
  
  // Include patterns
  includePatterns?: string[];
  
  // Exclude patterns
  excludePatterns?: string[];
  
  // Cache directory
  cacheDir?: string;
  
  // Cache TTL in seconds
  cacheTTL?: number;
}
