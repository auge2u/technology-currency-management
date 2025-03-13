/**
 * Common base interface for all scanning issues
 */
export interface BaseIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Optional notes about the issue
  notes?: string;
  
  // Tags for categorization
  tags?: string[];
  
  // Recommendation for resolving the issue
  recommendation?: string;
}

/**
 * Dependency scan issue
 */
export interface DependencyIssue extends BaseIssue {
  // Name of the dependency
  name: string;
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Package manager (npm, pip, maven, etc.)
  packageManager: string;
  
  // Type of dependency (production, development, peer, optional)
  type: 'production' | 'development' | 'peer' | 'optional';
  
  // Path to the manifest file where this dependency was found
  manifestFile: string;
  
  // Whether the dependency is outdated
  isOutdated: boolean;
  
  // Whether the dependency is deprecated
  isDeprecated: boolean;
  
  // Whether the dependency has security issues
  hasSecurityIssues: boolean;
  
  // Security issues details if any
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
    cve?: string;
  }>;
  
  // License information
  license?: string;
  
  // Repository URL
  repo?: string;
  
  // Business impact score (1-5, where 5 is highest impact)
  businessImpact?: number;
  
  // Update effort score (1-5, where 5 is highest effort)
  updateEffort?: number;
}

/**
 * Browser extension scan issue
 */
export interface ExtensionIssue extends BaseIssue {
  // Extension ID
  id: string;
  
  // Extension name
  name: string;
  
  // Browser (chrome, firefox, edge, safari)
  browser: string;
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Path where the extension is installed
  path: string;
  
  // Whether the extension is outdated
  isOutdated: boolean;
  
  // Whether the extension is deprecated
  isDeprecated: boolean;
  
  // Whether the extension has security issues
  hasSecurityIssues: boolean;
  
  // Security issues details if any
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cve?: string;
  }>;
  
  // Store URL
  storeUrl?: string;
  
  // Compatibility issues
  compatibilityIssues?: string[];
  
  // Whether the extension is approved by the organization
  isApproved?: boolean;
  
  // Whether the extension has been removed from the extension store
  removedFromStore?: boolean;
  
  // Risk level assessment
  riskLevel?: 'low' | 'medium' | 'high' | 'critical';
  
  // Update urgency assessment
  updateUrgency?: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Framework/technology scan issue
 */
export interface FrameworkIssue extends BaseIssue {
  // Name of the framework or technology
  name: string;
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Type of technology
  type: 'framework' | 'language' | 'runtime' | 'database' | 'infrastructure' | 'other';
  
  // Files where this framework/technology is used
  files: string[];
  
  // Whether the framework is outdated
  isOutdated: boolean;
  
  // Whether the framework is deprecated
  isDeprecated: boolean;
  
  // Whether the framework has security issues
  hasSecurityIssues: boolean;
  
  // End of life date if known
  endOfLifeDate?: Date;
  
  // End of support date if known
  endOfSupportDate?: Date;
  
  // Security issues details if any
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
    cve?: string;
  }>;
  
  // License information
  license?: string;
  
  // Repository URL
  repo?: string;
  
  // Usage count in the codebase
  usageCount?: number;
  
  // Business impact score (1-5, where 5 is highest impact)
  businessImpact?: number;
  
  // Update effort score (1-5, where 5 is highest effort)
  updateEffort?: number;
  
  // Suggested migration path
  migrationPath?: string;
}

/**
 * API usage scan issue for deprecated APIs
 */
export interface ApiIssue extends BaseIssue {
  // Name of the API
  name: string;
  
  // API source (framework, language, library)
  source: string;
  
  // Usage locations in code
  locations: Array<{
    file: string;
    line: number;
    column: number;
    code: string;
  }>;
  
  // Whether the API is deprecated
  isDeprecated: boolean;
  
  // Whether the API has security issues
  hasSecurityIssues: boolean;
  
  // Deprecation date if known
  deprecationDate?: Date;
  
  // Removal date if known
  removalDate?: Date;
  
  // Security issues details if any
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
    cve?: string;
  }>;
  
  // Suggested replacement API
  replacement?: string;
  
  // Code example for migration
  migrationExample?: string;
  
  // Documentation URL
  documentationUrl?: string;
  
  // Business impact score (1-5, where 5 is highest impact)
  businessImpact?: number;
  
  // Update effort score (1-5, where 5 is highest effort)
  updateEffort?: number;
}

/**
 * Scan report containing all issues
 */
export interface ScanReport {
  // When the scan was run
  scanDate: Date;
  
  // Scan duration in milliseconds
  duration: number;
  
  // System information
  system: {
    platform: string;
    architecture: string;
    nodeVersion?: string;
    cpuCores?: number;
    memoryTotal?: number;
  };
  
  // Scan configuration
  config: Record<string, any>;
  
  // Dependency issues
  dependencyIssues: DependencyIssue[];
  
  // Extension issues
  extensionIssues: ExtensionIssue[];
  
  // Framework/technology issues
  frameworkIssues: FrameworkIssue[];
  
  // API issues
  apiIssues: ApiIssue[];
  
  // Summary statistics
  summary: {
    totalIssues: number;
    criticalIssues: number;
    highPriorityIssues: number;
    mediumPriorityIssues: number;
    lowPriorityIssues: number;
    securityIssues: number;
    deprecatedIssues: number;
    outdatedIssues: number;
    unresolvedIssues: number;
  };
  
  // Overall health score (0-100)
  healthScore: number;
  
  // Next steps recommendations
  recommendations: string[];
  
  // Any errors that occurred during scanning
  errors?: Array<{
    message: string;
    stack?: string;
    scanner: string;
  }>;
}

/**
 * Configuration for the scanning process
 */
export interface ScanConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Whether to use offline mode (don't make API calls)
  offlineMode: boolean;
  
  // Dependency scanning configuration
  dependencyScanning: {
    enabled: boolean;
    includeDev: boolean;
    includePeer: boolean;
    includeOptional: boolean;
    ignorePackages?: string[];
  };
  
  // Extension scanning configuration
  extensionScanning: {
    enabled: boolean;
    browsers: {
      chrome: boolean;
      firefox: boolean;
      edge: boolean;
      safari: boolean;
    };
    approvedExtensions?: string[];
  };
  
  // Framework scanning configuration
  frameworkScanning: {
    enabled: boolean;
    includeLanguages: boolean;
    includeRuntimes: boolean;
    includeDatabases: boolean;
    includeInfrastructure: boolean;
  };
  
  // API scanning configuration
  apiScanning: {
    enabled: boolean;
    frameworks: string[];
    libraries: string[];
  };
  
  // Output configuration
  output: {
    jsonFile?: string;
    htmlReport?: string;
    csvExport?: string;
    console: boolean;
  };
  
  // Cache configuration
  cache: {
    enabled: boolean;
    directory?: string;
    ttlMinutes?: number;
  };
  
  // Custom rules path
  customRulesPath?: string;
  
  // GitHub integration
  github?: {
    enabled: boolean;
    token?: string;
    owner?: string;
    repo?: string;
    createIssues?: boolean;
  };
}
