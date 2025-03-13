/**
 * Vulnerability information structure
 */
export interface VulnerabilityInfo {
  // Unique identifier for the vulnerability (e.g., CVE ID, GitHub Advisory ID)
  id: string;
  
  // Severity level
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // CVSS score if available (Common Vulnerability Scoring System)
  cvssScore?: number;
  
  // Title of the vulnerability
  title: string;
  
  // Detailed description
  description: string;
  
  // URL for more information
  infoUrl?: string;
  
  // When the vulnerability was published
  publishedDate?: Date;
  
  // Versions affected by this vulnerability
  affectedVersions?: string;
  
  // Versions that have patched this vulnerability
  patchedVersions?: string;
  
  // Recommended action to address the vulnerability
  recommendation?: string;
}

/**
 * Base issue interface for all scanner types
 */
export interface BaseIssue {
  // Name/identifier of the outdated or vulnerable item
  name: string;
  
  // When the issue was detected
  detectedAt: Date;
  
  // Security vulnerabilities associated with this item
  vulnerabilities?: VulnerabilityInfo[];
}

/**
 * Issue detected in a framework or technology
 */
export interface FrameworkIssue extends BaseIssue {
  // Current version of the framework
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Whether the framework is outdated
  isOutdated: boolean;
  
  // Whether the framework is deprecated/EOL
  isDeprecated: boolean;
  
  // Framework category
  category: 'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other';
  
  // Specific framework type
  type: string;
  
  // Where this framework was detected
  location: string;
  
  // End of life date (if applicable)
  endOfLifeDate?: Date;
  
  // End of support date (if applicable)
  endOfSupportDate?: Date;
  
  // Suggested upgrade path or migration guide
  migrationPath?: string;
  
  // Estimated migration effort (1-5 scale)
  migrationEffort?: number;
  
  // Estimated business impact of not updating (1-5 scale)
  businessImpact?: number;
  
  // Estimated security impact of not updating (1-5 scale)
  securityImpact?: number;
}

/**
 * Issue detected in a dependency
 */
export interface DependencyIssue extends BaseIssue {
  // Current version of the dependency
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Whether the dependency is outdated
  isOutdated: boolean;
  
  // Whether this is a direct dependency or a transitive/indirect dependency
  isDirect: boolean;
  
  // The package ecosystem (npm, pip, maven, etc.)
  ecosystem: string;
  
  // File where the dependency is defined
  definitionFile: string;
  
  // Suggested command to fix/update this dependency
  suggestedFix?: string;
}

/**
 * Issue detected in a browser extension
 */
export interface BrowserExtensionIssue extends BaseIssue {
  // Extension ID
  id: string;
  
  // Current version of the extension
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Whether the extension is outdated
  isOutdated: boolean;
  
  // The browser this extension is for
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera';
  
  // Whether the extension has been removed from the store
  isRemovedFromStore: boolean;
  
  // Whether the extension has security issues
  hasSecurityIssues: boolean;
  
  // URL to the extension in the store
  storeUrl?: string;
}

/**
 * Issue detected in system components or libraries
 */
export interface SystemComponentIssue extends BaseIssue {
  // Current version of the component
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Whether the component is outdated
  isOutdated: boolean;
  
  // Component type (OS, database, runtime, etc.)
  componentType: string;
  
  // End of life date (if applicable)
  endOfLifeDate?: Date;
  
  // End of support date (if applicable)
  endOfSupportDate?: Date;
  
  // Suggested upgrade path or migration guide
  migrationPath?: string;
  
  // Estimated migration effort (1-5 scale)
  migrationEffort?: number;
  
  // Estimated business impact of not updating (1-5 scale)
  businessImpact?: number;
}

/**
 * Consolidated scan results from all scanners
 */
export interface TechnologyCurrencyScanResults {
  // Issues found in frameworks
  frameworkIssues: FrameworkIssue[];
  
  // Issues found in dependencies
  dependencyIssues: DependencyIssue[];
  
  // Issues found in browser extensions
  browserExtensionIssues: BrowserExtensionIssue[];
  
  // Issues found in system components
  systemComponentIssues: SystemComponentIssue[];
  
  // When the scan was performed
  scanDate: Date;
  
  // Summary metrics
  summary: {
    totalIssues: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
    outdatedFrameworks: number;
    vulnerableDependencies: number;
    outdatedExtensions: number;
    endOfLifeComponents: number;
  };
}

/**
 * Configuration for the scan process
 */
export interface ScannerConfiguration {
  // Root directory to scan
  rootDirectory: string;
  
  // Which scan types to perform
  scanTypes: {
    frameworks: boolean;
    dependencies: boolean;
    browserExtensions: boolean;
    systemComponents: boolean;
  };
  
  // Framework scanner configuration
  frameworkScannerConfig?: {
    // Which framework categories to check
    frameworkCategories: Array<'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other'>;
    // Whether to check for vulnerabilities
    checkVulnerabilities: boolean;
    // Whether to check for end of life/support dates
    checkEndOfLife: boolean;
    // Whether to estimate migration effort
    estimateMigrationEffort: boolean;
    // Whether to estimate business impact
    estimateBusinessImpact: boolean;
    // Minimum age in days to report (0 = report all)
    minimumAgeInDays: number;
    // Skip frameworks with specific names
    ignoreFrameworks?: string[];
    // Skip frameworks matching specific patterns
    ignorePatterns?: string[];
  };
  
  // Dependency scanner configuration
  dependencyScannerConfig?: {
    // Which ecosystems to scan (npm, pip, maven, etc.)
    ecosystems: string[];
    // Whether to check for direct dependencies only or include transitive dependencies
    includeTransitiveDependencies: boolean;
    // Whether to check for security vulnerabilities
    checkVulnerabilities: boolean;
    // Minimum severity level to report ('low', 'medium', 'high', 'critical')
    minSeverity: 'low' | 'medium' | 'high' | 'critical';
    // Skip dependencies with specific names
    ignoreDependencies?: string[];
    // Skip dependencies matching specific patterns
    ignorePatterns?: string[];
    // Skip dev dependencies
    ignoreDevDependencies?: boolean;
    // Whether to suggest fixes (upgrade commands)
    suggestFixes: boolean;
  };
  
  // Browser extension scanner configuration
  browserExtensionScannerConfig?: {
    // Which browsers to scan extensions for
    browsers: Array<'chrome' | 'firefox' | 'safari' | 'edge' | 'opera'>;
    // Whether to check for security vulnerabilities
    checkVulnerabilities: boolean;
    // Whether to check for browser compatibility issues
    checkCompatibility: boolean;
    // Specific users to scan for (if not specified, uses current user)
    users?: string[];
    // Skip extensions with specific IDs
    ignoreExtensions?: string[];
    // Skip extensions matching specific patterns
    ignorePatterns?: string[];
  };
  
  // System component scanner configuration
  systemComponentScannerConfig?: {
    // Which system components to check
    componentTypes: Array<'os' | 'runtime' | 'database' | 'middleware' | 'other'>;
    // Whether to check for security vulnerabilities
    checkVulnerabilities: boolean;
    // Whether to check for end of life/support dates
    checkEndOfLife: boolean;
    // Skip components with specific names
    ignoreComponents?: string[];
  };
  
  // Notification configuration
  notificationConfig?: {
    // Whether to send email notifications
    enableEmailNotifications: boolean;
    // Email recipients for notifications
    emailRecipients: string[];
    // Whether to send Slack notifications
    enableSlackNotifications: boolean;
    // Slack webhook URL
    slackWebhookUrl?: string;
    // Slack channel
    slackChannel?: string;
    // Whether to create GitHub issues for detected problems
    createGitHubIssues: boolean;
    // GitHub repository for issues
    gitHubRepository?: string;
    // Minimum severity for notifications ('low', 'medium', 'high', 'critical')
    minSeverityForNotification: 'low' | 'medium' | 'high' | 'critical';
  };
  
  // Reporting configuration
  reportingConfig?: {
    // Whether to generate HTML reports
    generateHtmlReport: boolean;
    // Whether to generate JSON reports
    generateJsonReport: boolean;
    // Whether to generate PDF reports
    generatePdfReport: boolean;
    // Directory to save reports
    reportDirectory: string;
    // Whether to include detailed vulnerability information
    includeVulnerabilityDetails: boolean;
    // Whether to include remediation information
    includeRemediationInfo: boolean;
    // Whether to include historical data for trend analysis
    includeHistoricalData: boolean;
  };
  
  // API timeouts in milliseconds
  apiTimeoutMs: number;
}
