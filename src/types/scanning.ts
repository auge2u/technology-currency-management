/**
 * Common types for technology currency scanning
 */

/**
 * Base issue interface for all scanner types
 */
export interface BaseIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Risk level assessment
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Tags for filtering and categorization
  tags: string[];
  
  // Recommendation for resolving the issue
  recommendation: string;
}

/**
 * Extension-related issue
 */
export interface ExtensionIssue extends BaseIssue {
  // Extension identifier
  id: string;
  
  // Extension display name
  name: string;
  
  // Browser (chrome, firefox, edge, safari)
  browser: string;
  
  // Current version installed
  currentVersion?: string;
  
  // Latest version available
  latestVersion?: string;
  
  // Path to the extension
  path: string;
  
  // Whether the extension is outdated
  isOutdated: boolean;
  
  // Whether the extension is deprecated
  isDeprecated: boolean;
  
  // Whether the extension has security issues
  hasSecurityIssues: boolean;
  
  // URL to the extension in the store
  storeUrl?: string;
  
  // Whether the extension is in the approved list
  isApproved: boolean;
  
  // Whether the extension has been removed from the store
  removedFromStore?: boolean;
  
  // Compatibility issues with current browser
  compatibilityIssues?: string[];
  
  // Security vulnerabilities
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cve?: string;
  }>;
  
  // Urgency for updating
  updateUrgency: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Technology-related issue
 */
export interface TechnologyIssue extends BaseIssue {
  // Technology identifier
  technologyId: string;
  
  // Technology display name
  name: string;
  
  // Technology category
  category: string;
  
  // Current version in use
  currentVersion?: string;
  
  // Latest version available
  latestVersion?: string;
  
  // Files where technology is used
  detectedFiles: string[];
  
  // Whether the technology is end-of-life
  isEol: boolean;
  
  // Whether the technology is outdated
  isOutdated?: boolean;
  
  // Whether the technology is deprecated
  isDeprecated?: boolean;
  
  // Whether the technology has security vulnerabilities
  isVulnerable: boolean;
  
  // Whether the technology has deprecated features
  hasDeprecatedFeatures: boolean;
  
  // Security vulnerabilities
  vulnerabilities?: Array<{
    versionRange: string;
    details: string;
    cveIds?: string[];
    fixedInVersion?: string;
  }>;
  
  // Deprecated features
  deprecatedFeatures?: Array<{
    feature: string;
    deprecatedInVersion: string;
    removedInVersion?: string;
    alternative?: string;
  }>;
  
  // End-of-life details
  eolDetails?: {
    date: Date;
    link?: string;
    migrationGuide?: string;
    replacementPath?: string;
  };
  
  // Website URL
  website?: string;
  
  // Documentation URL
  documentationUrl?: string;
  
  // Recommended alternatives
  alternatives?: string[];
  
  // Business impact score (1-5)
  businessImpact: number;
  
  // Remediation effort score (1-5)
  remediationEffort: number;
}

/**
 * Dependency-related issue
 */
export interface DependencyIssue extends BaseIssue {
  // Package name
  packageName: string;
  
  // Current version in use
  currentVersion: string;
  
  // Latest version available
  latestVersion?: string;
  
  // Package manager (npm, yarn, pip, etc.)
  packageManager: string;
  
  // Whether the dependency is direct or transitive
  isDirect: boolean;
  
  // Whether the dependency is outdated
  isOutdated: boolean;
  
  // Whether the dependency has known vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerability details
  vulnerabilities?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    fixedInVersion?: string;
    url?: string;
  }>;
  
  // Files dependent on this package
  dependentFiles?: string[];
  
  // Update impact assessment
  updateImpact?: {
    breakingChanges: boolean;
    testCoverage?: number;
    affectedComponents?: string[];
    estimatedEffort: 'low' | 'medium' | 'high';
  };
}

/**
 * API deprecation issue
 */
export interface ApiDeprecationIssue extends BaseIssue {
  // API name
  apiName: string;
  
  // API provider
  provider: string;
  
  // Current version in use
  currentVersion?: string;
  
  // When the API will be deprecated
  deprecationDate?: Date;
  
  // When the API will be removed
  removalDate?: Date;
  
  // Files using the deprecated API
  affectedFiles: string[];
  
  // Usage patterns found
  usagePatterns: Array<{
    pattern: string;
    count: number;
    examples: string[];
  }>;
  
  // Recommended replacement API
  replacementApi?: string;
  
  // Migration guide URL
  migrationGuideUrl?: string;
}

/**
 * Cloud service deprecation issue
 */
export interface CloudServiceIssue extends BaseIssue {
  // Service name
  serviceName: string;
  
  // Cloud provider
  provider: string;
  
  // Current version/tier in use
  currentVersion?: string;
  
  // Type of issue (deprecation, price change, etc.)
  issueType: 'deprecation' | 'version-eol' | 'price-change' | 'region-closure' | 'feature-removal';
  
  // When the change will take effect
  effectiveDate?: Date;
  
  // Components using this service
  affectedComponents: string[];
  
  // Business impact assessment
  businessImpact: {
    costIncrease?: number; // Percentage
    downtime?: number; // Minutes
    performance?: 'none' | 'minor' | 'major';
    compliance?: boolean;
    score: number; // 1-5
  };
  
  // Recommended action
  recommendedAction: 'migrate' | 'upgrade' | 'replace' | 'reevaluate-costs';
  
  // Alternative services
  alternatives?: Array<{
    name: string;
    provider: string;
    migrationEffort: 'low' | 'medium' | 'high';
    costComparison?: 'lower' | 'similar' | 'higher';
  }>;
}
