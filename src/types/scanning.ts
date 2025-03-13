/**
 * Types for scanning and technology currency management
 */

/**
 * Severity level for security vulnerabilities
 */
export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

/**
 * Information about a vulnerability
 */
export interface VulnerabilityInfo {
  // Unique identifier for the vulnerability
  id: string;
  
  // CVSS score (0.0-10.0)
  cvssScore?: number;
  
  // Severity level
  severity: SeverityLevel;
  
  // Vulnerability title
  title: string;
  
  // Detailed description
  description?: string;
  
  // URL to vulnerability details
  infoUrl?: string;
  
  // When the vulnerability was published
  publishedDate?: Date;
  
  // Affected versions range
  affectedVersions?: string;
  
  // Fixed versions
  patchedVersions?: string;
  
  // Recommended action
  recommendation?: string;
}

/**
 * Base issue interface for all scanners
 */
export interface BaseIssue {
  // Name of the component
  name: string;
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Whether the component is outdated
  isOutdated: boolean;
  
  // Whether the component is deprecated
  isDeprecated?: boolean;
  
  // Deprecation message if available
  deprecationMessage?: string;
  
  // When the issue was detected
  detectedAt: Date;
}

/**
 * Issue detected by the dependency scanner
 */
export interface DependencyIssue extends BaseIssue {
  // Whether this is a direct or transitive dependency
  isDirect: boolean;
  
  // Ecosystem (npm, pip, maven, etc.)
  ecosystem: string;
  
  // Path to the definition file (package.json, requirements.txt, etc.)
  definitionFile: string;
  
  // List of security vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // Command to upgrade the dependency
  suggestedFix?: string;
}

/**
 * Issue detected by the browser extension scanner
 */
export interface BrowserExtensionIssue extends BaseIssue {
  // Extension ID
  id: string;
  
  // Browser name
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera';
  
  // Whether the extension has security issues
  hasSecurityIssues: boolean;
  
  // Whether the extension has been removed from the store
  isRemovedFromStore: boolean;
  
  // List of security vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // URL to the extension in the store
  storeUrl: string;
}

/**
 * Issue detected by the framework scanner
 */
export interface FrameworkIssue extends BaseIssue {
  // Framework category
  category: 'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other';
  
  // Type of the framework/technology
  type: string;
  
  // Location where the framework is used
  location: string;
  
  // End of life date if available
  endOfLifeDate?: Date;
  
  // End of support date if available
  endOfSupportDate?: Date;
  
  // List of security vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // Migration path to a newer version
  migrationPath?: string;
  
  // Estimated migration effort (1-5)
  migrationEffort?: number;
  
  // Business impact of not migrating (1-5)
  businessImpact?: number;
  
  // Security impact of not migrating (1-5)
  securityImpact?: number;
}

/**
 * Issue detected by the database technology scanner
 */
export interface DatabaseIssue extends BaseIssue {
  // Database type (MySQL, PostgreSQL, etc.)
  dbType: string;
  
  // Database instance identifier
  instanceId: string;
  
  // Connection details
  connectionInfo?: string;
  
  // End of life date if available
  endOfLifeDate?: Date;
  
  // End of support date if available
  endOfSupportDate?: Date;
  
  // List of security vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // Migration path to a newer version
  migrationPath?: string;
}

/**
 * Issue detected by the infrastructure scanner
 */
export interface InfrastructureIssue extends BaseIssue {
  // Infrastructure type (VM, container, etc.)
  infraType: string;
  
  // Provider (AWS, Azure, GCP, etc.)
  provider?: string;
  
  // Resource identifier
  resourceId: string;
  
  // Location (region, zone, etc.)
  location?: string;
  
  // End of life date if available
  endOfLifeDate?: Date;
  
  // End of support date if available
  endOfSupportDate?: Date;
  
  // List of security vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // Migration path to a newer version
  migrationPath?: string;
}

/**
 * Issue detected by the security scanner
 */
export interface SecurityIssue extends BaseIssue {
  // Security component type
  securityType: 'certificate' | 'encryption' | 'protocol' | 'algorithm' | 'key' | 'other';
  
  // Severity level
  severity: SeverityLevel;
  
  // Where the security component is used
  usageLocation: string;
  
  // List of vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // Remediation steps
  remediation?: string;
}

/**
 * Issue detected by the language runtime scanner
 */
export interface LanguageRuntimeIssue extends BaseIssue {
  // Language name
  language: string;
  
  // Runtime identifier
  runtimeId: string;
  
  // Where the runtime is used
  usageLocation: string;
  
  // End of life date if available
  endOfLifeDate?: Date;
  
  // End of support date if available
  endOfSupportDate?: Date;
  
  // List of security vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // Migration path to a newer version
  migrationPath?: string;
}

/**
 * Aggregated result from all scanners
 */
export interface TechnologyCurrencyScanResult {
  // Scan metadata
  scanId: string;
  startTime: Date;
  endTime: Date;
  duration: number; // milliseconds
  
  // Organization and environment info
  organization?: string;
  environment?: string;
  
  // Issues by category
  dependencyIssues: DependencyIssue[];
  frameworkIssues: FrameworkIssue[];
  browserExtensionIssues: BrowserExtensionIssue[];
  databaseIssues: DatabaseIssue[];
  infrastructureIssues: InfrastructureIssue[];
  securityIssues: SecurityIssue[];
  languageRuntimeIssues: LanguageRuntimeIssue[];
  
  // Summary statistics
  totalIssues: number;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  
  // Technical debt estimation
  estimatedRemediationDays?: number;
  estimatedRemediationCost?: number;
}
