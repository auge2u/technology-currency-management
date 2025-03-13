/**
 * Base configuration for all scanners
 */
export interface ScannerConfig {
  // Root directory to scan
  rootDir: string;
  
  // Paths to exclude from scanning
  excludePaths?: string[];
  
  // Custom output format
  outputFormat?: 'json' | 'csv' | 'markdown' | 'html';
  
  // Flag to enable detailed logging
  verbose?: boolean;
  
  // Maximum concurrency for scans
  maxConcurrency?: number;
  
  // Timeout for individual operations (in ms)
  operationTimeout?: number;
  
  // Custom scanner-specific settings
  [key: string]: any;
}

/**
 * Base interface for all scanner issues
 */
export interface BaseIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Risk level of the issue
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Detailed recommendation for resolving the issue
  recommendation: string;
  
  // Tags for categorizing and filtering issues
  tags: string[];
}

/**
 * Interface for dependency-related issues
 */
export interface DependencyIssue extends BaseIssue {
  // Name of the package
  packageName: string;
  
  // Current version used in the project
  currentVersion: string;
  
  // Latest available version
  latestVersion?: string;
  
  // Package manager (npm, pip, maven, etc.)
  packageManager: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget';
  
  // Whether it's a direct dependency or transitive
  isDirect: boolean;
  
  // Whether the package is outdated
  isOutdated: boolean;
  
  // Whether the package has known vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerability details if applicable
  vulnerabilities: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    fixedInVersion?: string;
    url?: string;
  }[];
  
  // Files that depend on this package
  dependentFiles: string[];
  
  // Impact of updating this dependency
  updateImpact: {
    breakingChanges: boolean;
    affectedComponents?: string[];
    estimatedEffort: 'low' | 'medium' | 'high';
  };
}

/**
 * Interface for browser extension-related issues
 */
export interface ExtensionIssue extends BaseIssue {
  // Extension name
  name: string;
  
  // Extension ID
  id: string;
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion?: string;
  
  // Browser type
  browser: 'chrome' | 'firefox' | 'safari' | 'edge';
  
  // Whether the extension is outdated
  isOutdated: boolean;
  
  // Whether the extension has known vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerability details if applicable
  vulnerabilities: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    affectedVersions?: string;
    fixedInVersion?: string;
    url?: string;
  }[];
  
  // Whether the extension has compatibility issues
  hasCompatibilityIssues: boolean;
  
  // Compatibility issue details
  compatibilityIssues: {
    type: 'api_deprecated' | 'browser_update_required' | 'permission_changes' | 'manifest_version';
    description: string;
    remediation?: string;
  }[];
  
  // Whether the extension is deprecated
  isDeprecated: boolean;
  
  // Deprecation details if applicable
  deprecationDetails?: {
    deprecationDate?: Date;
    endOfSupportDate?: Date;
    reason?: string;
    alternatives?: string[];
  };
  
  // Permissions requested by the extension
  permissions?: string[];
  
  // Path to manifest file, if available
  manifestPath?: string;
}

/**
 * Interface for framework/library-related issues
 */
export interface FrameworkIssue extends BaseIssue {
  // Framework/library name
  name: string;
  
  // Current version used in the project
  currentVersion: string;
  
  // Latest available version
  latestVersion?: string;
  
  // Framework type (frontend, backend, database, etc.)
  type: 'frontend' | 'backend' | 'database' | 'mobile' | 'desktop' | 'testing' | 'infrastructure' | 'other';
  
  // Whether the framework is outdated
  isOutdated: boolean;
  
  // Whether the framework has known vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerability details if applicable
  vulnerabilities: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    fixedInVersion?: string;
    url?: string;
  }[];
  
  // Whether the framework is deprecated or approaching end-of-life
  isDeprecated: boolean;
  
  // End-of-life/support details if applicable
  eolDetails?: {
    announcementDate?: Date;
    eolDate?: Date;
    ltsEndDate?: Date;
    migrationPath?: string;
    alternatives?: string[];
  };
  
  // Files using this framework
  affectedFiles: string[];
  
  // Impact of updating this framework
  updateImpact: {
    breakingChanges: boolean;
    affectedComponents?: string[];
    estimatedEffort: 'low' | 'medium' | 'high';
    requiredChanges?: string[];
  };
}

/**
 * Interface for system component-related issues
 */
export interface SystemComponentIssue extends BaseIssue {
  // Component name
  name: string;
  
  // Component type
  type: 'os' | 'runtime' | 'database' | 'server' | 'container' | 'cloud' | 'other';
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion?: string;
  
  // Whether the component is outdated
  isOutdated: boolean;
  
  // Whether the component has known vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerability details if applicable
  vulnerabilities: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    fixedInVersion?: string;
    url?: string;
  }[];
  
  // Whether the component is deprecated or approaching end-of-life
  isDeprecated: boolean;
  
  // End-of-life/support details if applicable
  eolDetails?: {
    announcementDate?: Date;
    eolDate?: Date;
    extendedSupportEndDate?: Date;
    migrationPath?: string;
    alternatives?: string[];
  };
  
  // Impact of updating this component
  updateImpact: {
    breakingChanges: boolean;
    affectedServices?: string[];
    downtime?: boolean;
    estimatedEffort: 'low' | 'medium' | 'high';
    requiredChanges?: string[];
  };
}

/**
 * Interface for API-related issues
 */
export interface ApiIssue extends BaseIssue {
  // API name
  name: string;
  
  // API type
  type: 'rest' | 'graphql' | 'grpc' | 'soap' | 'websocket' | 'other';
  
  // Current version used
  currentVersion: string;
  
  // Latest available version
  latestVersion?: string;
  
  // API provider/vendor
  provider?: string;
  
  // Whether the API is outdated
  isOutdated: boolean;
  
  // Whether the API version is deprecated
  isDeprecated: boolean;
  
  // Deprecation details if applicable
  deprecationDetails?: {
    announcementDate?: Date;
    deprecationDate?: Date;
    sunsetDate?: Date;
    reason?: string;
    alternatives?: string[];
  };
  
  // Whether deprecated features are being used
  usesDeprecatedFeatures: boolean;
  
  // Details about deprecated features
  deprecatedFeatures?: {
    name: string;
    description: string;
    removalDate?: Date;
    alternatives?: string;
  }[];
  
  // Files using this API
  affectedFiles: string[];
  
  // Impact of updating this API
  updateImpact: {
    breakingChanges: boolean;
    affectedComponents?: string[];
    estimatedEffort: 'low' | 'medium' | 'high';
    requiredChanges?: string[];
  };
}

/**
 * Interface for database-related issues
 */
export interface DatabaseIssue extends BaseIssue {
  // Database name
  name: string;
  
  // Database type
  type: 'sql' | 'nosql' | 'graph' | 'time-series' | 'object' | 'key-value' | 'other';
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion?: string;
  
  // Whether the database is outdated
  isOutdated: boolean;
  
  // Whether the database has known vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerability details if applicable
  vulnerabilities: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    fixedInVersion?: string;
    url?: string;
  }[];
  
  // Whether the database is deprecated or approaching end-of-life
  isDeprecated: boolean;
  
  // End-of-life/support details if applicable
  eolDetails?: {
    announcementDate?: Date;
    eolDate?: Date;
    extendedSupportEndDate?: Date;
    migrationPath?: string;
    alternatives?: string[];
  };
  
  // Whether deprecated features are being used
  usesDeprecatedFeatures: boolean;
  
  // Details about deprecated features
  deprecatedFeatures?: {
    name: string;
    description: string;
    removalDate?: Date;
    alternatives?: string;
  }[];
  
  // Connection strings or identifiers (redacted for security)
  connectionIdentifiers?: string[];
  
  // Impact of updating this database
  updateImpact: {
    breakingChanges: boolean;
    dataCompatibility: boolean;
    downtime?: boolean;
    estimatedEffort: 'low' | 'medium' | 'high';
    requiredChanges?: string[];
  };
}

/**
 * Union type for all issue types
 */
export type TechnologyIssue =
  | DependencyIssue
  | ExtensionIssue
  | FrameworkIssue
  | SystemComponentIssue
  | ApiIssue
  | DatabaseIssue;

/**
 * Interface for scan results
 */
export interface ScanResult {
  // Timestamp when the scan was performed
  timestamp: Date;
  
  // List of all detected issues
  issues: TechnologyIssue[];
  
  // Summary statistics
  summary: {
    totalIssues: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
    byType: Record<string, number>;
    byTag: Record<string, number>;
  };
  
  // Scan metadata
  metadata: {
    scanDuration: number; // milliseconds
    scannedFiles: number;
    scannedComponents: number;
    scannerVersions: Record<string, string>;
    excludedPaths: string[];
    errors?: string[];
  };
}

/**
 * Interface for scan configurations
 */
export interface ScanConfig {
  // Root directory to scan
  rootDir: string;
  
  // Paths to exclude from scanning
  excludePaths?: string[];
  
  // Scanners to include
  scanners: {
    // Dependency scanner config
    dependencies?: {
      enabled: boolean;
      packageManagers?: Array<'npm' | 'pip' | 'maven' | 'gradle' | 'nuget'>;
      directDependenciesOnly?: boolean;
      checkVulnerabilities?: boolean;
      maxTransitiveDepth?: number;
      assessUpdateImpact?: boolean;
    };
    
    // Extensions scanner config
    extensions?: {
      enabled: boolean;
      browsers?: Array<'chrome' | 'firefox' | 'safari' | 'edge'>;
      scanForManifests?: boolean;
      scanInstalledExtensions?: boolean;
      checkVulnerabilities?: boolean;
      categories?: string[];
    };
    
    // Frameworks scanner config
    frameworks?: {
      enabled: boolean;
      types?: Array<'frontend' | 'backend' | 'database' | 'mobile' | 'desktop' | 'testing' | 'infrastructure' | 'other'>;
      checkVulnerabilities?: boolean;
      checkEol?: boolean;
      customDbPath?: string;
    };
    
    // System components scanner config
    systemComponents?: {
      enabled: boolean;
      types?: Array<'os' | 'runtime' | 'database' | 'server' | 'container' | 'cloud' | 'other'>;
      checkVulnerabilities?: boolean;
      checkEol?: boolean;
      includeVersions?: string[];
    };
    
    // API scanner config
    apis?: {
      enabled: boolean;
      types?: Array<'rest' | 'graphql' | 'grpc' | 'soap' | 'websocket' | 'other'>;
      checkDeprecation?: boolean;
      providers?: string[];
    };
    
    // Database scanner config
    databases?: {
      enabled: boolean;
      types?: Array<'sql' | 'nosql' | 'graph' | 'time-series' | 'object' | 'key-value' | 'other'>;
      checkVulnerabilities?: boolean;
      checkEol?: boolean;
      checkDeprecatedFeatures?: boolean;
    };
  };
  
  // Output configuration
  output?: {
    format: 'json' | 'csv' | 'markdown' | 'html';
    destination?: string;
    includeDetails?: boolean;
    groupBy?: 'type' | 'riskLevel' | 'tag';
  };
  
  // Notification configuration
  notifications?: {
    enabled: boolean;
    threshold?: 'low' | 'medium' | 'high' | 'critical';
    channels?: Array<'email' | 'slack' | 'teams' | 'webhook'>;
    recipients?: string[];
    webhookUrls?: string[];
  };
  
  // Schedule configuration
  schedule?: {
    enabled: boolean;
    frequency: 'daily' | 'weekly' | 'monthly' | 'custom';
    customCron?: string;
    retainResults?: number; // Number of scan results to retain
  };
  
  // Advanced configuration
  advanced?: {
    maxConcurrency?: number;
    operationTimeout?: number; // milliseconds
    retries?: number;
    verbose?: boolean;
    debugMode?: boolean;
  };
}

/**
 * Interface for notification configuration
 */
export interface NotificationConfig {
  // Minimum risk level to trigger notifications
  threshold: 'low' | 'medium' | 'high' | 'critical';
  
  // Notification channels
  channels: Array<'email' | 'slack' | 'teams' | 'webhook'>;
  
  // Email configuration if email channel is enabled
  email?: {
    recipients: string[];
    sender?: string;
    subject?: string;
    smtpConfig?: {
      host: string;
      port: number;
      secure?: boolean;
      auth?: {
        user: string;
        pass: string;
      };
    };
  };
  
  // Slack configuration if slack channel is enabled
  slack?: {
    webhookUrl: string;
    channel?: string;
    username?: string;
    iconEmoji?: string;
  };
  
  // Microsoft Teams configuration if teams channel is enabled
  teams?: {
    webhookUrl: string;
  };
  
  // Generic webhook configuration if webhook channel is enabled
  webhook?: {
    urls: string[];
    headers?: Record<string, string>;
    method?: 'POST' | 'PUT';
  };
  
  // Notification templating
  templates?: {
    subject?: string;
    body?: string;
    summary?: string;
  };
  
  // Notification grouping options
  grouping?: {
    enabled: boolean;
    groupBy?: 'riskLevel' | 'type' | 'tag';
    maxItemsPerGroup?: number;
  };
}

/**
 * Interface for version information
 */
export interface VersionInfo {
  version: string;
  releaseDate?: Date;
  isLatest: boolean;
  isDeprecated?: boolean;
  eolDate?: Date;
  isLts?: boolean;
  ltsEndDate?: Date;
  hasVulnerabilities?: boolean;
  vulnerabilityDetails?: {
    count: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  requiresUpgradeFrom?: string[];
  breakingChanges?: {
    description: string;
    impact: 'low' | 'medium' | 'high';
  }[];
}

/**
 * Interface for remediation information
 */
export interface RemediationInfo {
  // Type of remediation
  type: 'update' | 'replace' | 'remove' | 'patch' | 'configure' | 'monitor';
  
  // Description of the remediation steps
  description: string;
  
  // Target version to update to (if applicable)
  targetVersion?: string;
  
  // Estimated effort required
  estimatedEffort: 'low' | 'medium' | 'high';
  
  // Estimated time required (in hours)
  estimatedTime?: number;
  
  // Risk level of the remediation
  risk: 'low' | 'medium' | 'high';
  
  // Any prerequisites for the remediation
  prerequisites?: string[];
  
  // Specific steps to follow
  steps?: string[];
  
  // Commands or scripts to run (if applicable)
  commands?: string[];
  
  // Alternatives if this remediation isn't suitable
  alternatives?: {
    type: 'update' | 'replace' | 'remove' | 'patch' | 'configure' | 'monitor';
    description: string;
    pros: string[];
    cons: string[];
  }[];
  
  // Components affected by this remediation
  affectedComponents?: string[];
  
  // Services that need to be restarted
  requiresRestart?: string[];
  
  // Whether this remediation can be automated
  canBeAutomated?: boolean;
  
  // Link to automation script or tool (if applicable)
  automationPath?: string;
}

/**
 * Interface for a technology inventory item
 */
export interface TechnologyInventoryItem {
  // Unique identifier
  id: string;
  
  // Name of the technology
  name: string;
  
  // Type of technology
  type: 'dependency' | 'extension' | 'framework' | 'system' | 'api' | 'database' | 'other';
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion?: string;
  
  // Optional vendor/provider
  vendor?: string;
  
  // When this technology was added to the inventory
  addedDate: Date;
  
  // When this technology was last updated
  lastUpdatedDate: Date;
  
  // When this technology was last scanned
  lastScannedDate: Date;
  
  // Current status
  status: 'current' | 'outdated' | 'vulnerable' | 'deprecated' | 'end-of-life';
  
  // Risk level based on status
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Usage information
  usage: {
    projects?: string[];
    services?: string[];
    teams?: string[];
    criticality: 'low' | 'medium' | 'high' | 'critical';
    usageCount?: number;
  };
  
  // Important dates
  dates?: {
    releaseDate?: Date;
    lastPatched?: Date;
    nextScheduledReview?: Date;
    endOfSupport?: Date;
    endOfLife?: Date;
  };
  
  // Reference to the last scan that found issues
  lastScanId?: string;
  
  // Current issues with this technology
  issues?: TechnologyIssue[];
  
  // Categorization tags
  tags: string[];
  
  // Notes about this technology
  notes?: string;
  
  // Links to documentation, source, etc.
  links?: {
    documentation?: string;
    source?: string;
    releases?: string;
    roadmap?: string;
  };
}
