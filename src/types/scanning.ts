/**
 * Base configuration for all scanners
 */
export interface ScannerConfig {
  // Root directory to scan
  rootDir: string;
  
  // Paths to exclude from scanning
  excludePaths?: string[];
  
  // Maximum age of updates in days before flagging
  maxUpdateAge?: number;
  
  // Whether to enable verbose logging
  verbose?: boolean;
}

/**
 * Extension Issue identified by the extension scanner
 */
export interface ExtensionIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Extension ID
  id: string;
  
  // Extension name
  name: string;
  
  // Extension version
  version: string;
  
  // Browser the extension is installed for
  browser: string;
  
  // Manifest version
  manifestVersion: number;
  
  // Extension description
  description?: string;
  
  // How the extension was installed
  installType?: string;
  
  // Path where extension is installed
  installedPath?: string;
  
  // Permissions requested by the extension
  permissions?: string[];
  
  // Optional permissions requested by the extension
  optionalPermissions?: string[];
  
  // Host permissions requested by the extension
  hostPermissions?: string[];
  
  // Homepage URL for the extension
  homepageUrl?: string;
  
  // Update URL for the extension
  updateUrl?: string;
  
  // Store URL for the extension
  storeUrl?: string;
  
  // Latest version available
  latestVersion?: string;
  
  // Whether the extension is outdated
  isOutdated: boolean;
  
  // Whether the extension has vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerabilities found in the extension
  vulnerabilities?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affectedVersions?: string;
    fixedInVersion?: string;
    url?: string;
    cveIds?: string[];
  }[];
  
  // Whether the extension is deprecated
  isDeprecated: boolean;
  
  // Whether the extension has compatibility issues
  isCompatibilityIssue: boolean;
  
  // Compatibility issues found in the extension
  compatibilityIssues?: {
    browserVersion: string;
    description: string;
    impact: 'low' | 'medium' | 'high';
  }[];
  
  // Whether the extension is not being maintained
  isNotMaintained: boolean;
  
  // When the extension was last updated
  lastUpdateDate?: Date;
  
  // Whether the extension has excessive permissions
  hasExcessivePermissions: boolean;
  
  // Permission concerns for the extension
  permissionConcerns?: {
    permission: string;
    level: 'low' | 'medium' | 'high';
    description: string;
  }[];
  
  // Whether the extension uses deprecated APIs
  usesDeprecatedApis: boolean;
  
  // Deprecated APIs used by the extension
  deprecatedApis?: {
    api: string;
    deprecatedSince: string;
    alternatives?: string;
    removalTimeline?: string;
  }[];
  
  // Recommended alternative to the extension
  recommandedAlternative?: string;
  
  // Extension author
  author?: string;
  
  // When the extension was installed
  installDate?: Date;
  
  // Overall risk level of the extension
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Recommendation for addressing the issue
  recommendation: string;
  
  // Tags categorizing the issue
  tags: string[];
}

/**
 * Framework Issue identified by the framework scanner
 */
export interface FrameworkIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Framework name
  name: string;
  
  // Framework type
  type: 'language-core' | 'framework' | 'library' | 'runtime' | 'toolchain' | 'database' | 'api' | 'cloud-service' | 'ui-component' | 'testing' | 'build-tool' | 'infrastructure';
  
  // Framework ecosystem
  ecosystem: 'javascript' | 'typescript' | 'python' | 'java' | 'dotnet' | 'php' | 'ruby' | 'go' | 'rust' | 'database' | 'devops' | 'mobile';
  
  // Framework version
  version?: string;
  
  // Where the framework was detected
  detectedIn: string;
  
  // Latest version available
  latestVersion?: string;
  
  // Whether the framework is outdated
  isOutdated: boolean;
  
  // Number of major versions behind
  majorVersionsBehind?: number;
  
  // Number of minor versions behind
  minorVersionsBehind?: number;
  
  // Whether the framework has vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerabilities found in the framework
  vulnerabilities?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affectedVersions?: string;
    fixedInVersion?: string;
    url?: string;
    cveIds?: string[];
  }[];
  
  // Whether the framework is deprecated
  isDeprecated: boolean;
  
  // Whether the framework is not being maintained
  isNotMaintained: boolean;
  
  // When the framework support ends
  endOfLifeDate?: Date;
  
  // When the framework support ends
  endOfSupportDate?: Date;
  
  // Whether the framework has compatibility issues
  hasCompatibilityIssues: boolean;
  
  // Compatibility issues found in the framework
  compatibilityIssues?: {
    description: string;
    affectedVersions?: string;
    impact: 'low' | 'medium' | 'high';
  }[];
  
  // Whether the framework uses deprecated APIs
  usesDeprecatedApis: boolean;
  
  // Deprecated APIs used by the framework
  deprecatedApis?: {
    api: string;
    deprecatedSince: string;
    removedIn?: string;
    alternatives?: string;
  }[];
  
  // Recommended upgrade path for the framework
  recommendedUpgradePath?: string;
  
  // Recommended alternative to the framework
  recommendedAlternative?: string;
  
  // Documentation URL for the framework
  documentationUrl?: string;
  
  // Repository URL for the framework
  repositoryUrl?: string;
  
  // Last commit date in the repository
  lastCommitDate?: Date;
  
  // Complexity of upgrading the framework
  upgradeComplexity?: 'low' | 'medium' | 'high';
  
  // Risk level of upgrading the framework
  upgradeRiskLevel?: 'low' | 'medium' | 'high';
  
  // Technical debt areas identified
  technicalDebtAreas?: {
    area: string;
    impact: 'low' | 'medium' | 'high';
    description: string;
  }[];
  
  // Overall risk level of the framework issue
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Recommendation for addressing the issue
  recommendation: string;
  
  // Tags categorizing the issue
  tags: string[];
}

/**
 * Dependency Issue identified by the dependency scanner
 */
export interface DependencyIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Package name
  name: string;
  
  // Package manager type (npm, pip, maven, etc.)
  packageManager: 'npm' | 'yarn' | 'pip' | 'mvn' | 'gradle' | 'nuget' | 'composer' | 'gem' | 'cargo' | 'go';
  
  // Package version
  version: string;
  
  // Where the dependency was detected
  detectedIn: string;
  
  // Latest version available
  latestVersion?: string;
  
  // Whether the dependency is outdated
  isOutdated: boolean;
  
  // Number of major versions behind
  majorVersionsBehind?: number;
  
  // Number of minor versions behind
  minorVersionsBehind?: number;
  
  // Number of patch versions behind
  patchVersionsBehind?: number;
  
  // Whether the dependency is using a pinned version
  isPinned: boolean;
  
  // Whether the dependency version uses a range or exact version
  versionType: 'exact' | 'range' | 'caret' | 'tilde' | 'greater' | 'less' | 'star';
  
  // Whether the dependency is direct or transitive
  isDirect: boolean;
  
  // Whether the dependency has vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerabilities found in the dependency
  vulnerabilities?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affectedVersions?: string;
    fixedInVersion?: string;
    url?: string;
    cveIds?: string[];
  }[];
  
  // Whether the dependency has licensing issues
  hasLicensingIssues: boolean;
  
  // Licensing issues with the dependency
  licensingIssues?: {
    license: string;
    compliance: 'compliant' | 'non-compliant' | 'unknown';
    description: string;
  }[];
  
  // Whether the dependency is deprecated
  isDeprecated: boolean;
  
  // Whether the dependency is not being maintained
  isNotMaintained: boolean;
  
  // Last update date
  lastUpdateDate?: Date;
  
  // Whether the dependency has been abandoned
  isAbandoned: boolean;
  
  // Recommended alternative to the dependency
  recommendedAlternative?: string;
  
  // Dependency author
  author?: string;
  
  // Repository URL for the dependency
  repositoryUrl?: string;
  
  // Download count or popularity indicator
  popularity?: number;
  
  // Overall risk level of the dependency issue
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Recommendation for addressing the issue
  recommendation: string;
  
  // Tags categorizing the issue
  tags: string[];
}

/**
 * Code Issue identified by the code scanner
 */
export interface CodeIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Issue type
  type: 'deprecated-api' | 'security-vulnerability' | 'obsolete-pattern' | 'performance-issue' | 'technical-debt';
  
  // Language of the code
  language: string;
  
  // File where the issue was detected
  filePath: string;
  
  // Line number in the file
  lineNumber: number;
  
  // Column number in the file
  columnNumber?: number;
  
  // Line of code with the issue
  lineOfCode: string;
  
  // Description of the issue
  description: string;
  
  // Issue severity
  severity: 'info' | 'warning' | 'error' | 'critical';
  
  // Recommended fix for the issue
  fix?: string;
  
  // Links to documentation about the issue
  documentationLinks?: string[];
  
  // Estimated effort to fix (person-hours)
  estimatedEffort?: number;
  
  // Overall risk level of the code issue
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Recommendation for addressing the issue
  recommendation: string;
  
  // Tags categorizing the issue
  tags: string[];
}

/**
 * Infrastructure Issue identified by the infrastructure scanner
 */
export interface InfrastructureIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Service type
  serviceType: 'container' | 'server' | 'database' | 'networking' | 'cloud-service' | 'orchestration' | 'ci-cd';
  
  // Service name
  serviceName: string;
  
  // Service provider
  provider?: 'aws' | 'azure' | 'gcp' | 'docker' | 'kubernetes' | 'on-premise' | 'other';
  
  // Current version
  version?: string;
  
  // Latest version available
  latestVersion?: string;
  
  // Whether the service is outdated
  isOutdated: boolean;
  
  // Whether the service has security vulnerabilities
  isVulnerable: boolean;
  
  // Vulnerabilities found in the service
  vulnerabilities?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affectedVersions?: string;
    fixedInVersion?: string;
    url?: string;
    cveIds?: string[];
  }[];
  
  // Whether the service is deprecated
  isDeprecated: boolean;
  
  // Whether the service is end-of-life
  isEndOfLife: boolean;
  
  // End-of-life date
  endOfLifeDate?: Date;
  
  // Whether the service has configuration issues
  hasConfigurationIssues: boolean;
  
  // Configuration issues with the service
  configurationIssues?: {
    description: string;
    impact: 'low' | 'medium' | 'high';
    recommendation: string;
  }[];
  
  // Whether the service has compliance issues
  hasComplianceIssues: boolean;
  
  // Compliance issues with the service
  complianceIssues?: {
    standard: string;
    requirement: string;
    description: string;
  }[];
  
  // Estimated migration effort (person-days)
  estimatedMigrationEffort?: number;
  
  // Recommended migration path
  recommendedMigrationPath?: string;
  
  // Financial implications of migration
  financialImplications?: {
    currentCost?: number;
    migrationCost?: number;
    newSolutionCost?: number;
    roi?: number;
    paybackPeriod?: number;
  };
  
  // Overall risk level of the issue
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Recommendation for addressing the issue
  recommendation: string;
  
  // Tags categorizing the issue
  tags: string[];
}

/**
 * Document Issue identified by the documentation scanner
 */
export interface DocumentIssue {
  // When the issue was detected
  detectedAt: Date;
  
  // Document name or identifier
  documentName: string;
  
  // Document type (architecture, requirements, user manual, etc.)
  documentType: 'architecture' | 'requirements' | 'design' | 'user-manual' | 'operation-manual' | 'api-documentation' | 'deployment-guide';
  
  // Document file path
  filePath: string;
  
  // Issue type
  issueType: 'outdated-content' | 'missing-content' | 'inaccurate-content' | 'obsolete-reference' | 'deprecated-terminology';
  
  // Description of the issue
  description: string;
  
  // Issue severity
  severity: 'info' | 'warning' | 'error';
  
  // Document section or page number with the issue
  location?: string;
  
  // Last update date of the document
  lastUpdateDate?: Date;
  
  // Whether the document is outdated
  isOutdated: boolean;
  
  // References to outdated technologies
  outdatedReferences?: {
    technology: string;
    location: string;
    currentVersion: string;
    documentedVersion: string;
  }[];
  
  // Estimated effort to update (person-hours)
  estimatedEffort?: number;
  
  // Tags categorizing the issue
  tags: string[];
  
  // Overall risk level of the issue
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Recommendation for addressing the issue
  recommendation: string;
}

/**
 * Scanning Report containing all issues found
 */
export interface ScanningReport {
  // When the scan was performed
  scanDate: Date;
  
  // Scan name or identifier
  scanName: string;
  
  // Repository or project scanned
  repositoryName: string;
  
  // Scan duration in seconds
  scanDuration: number;
  
  // Overall summary of findings
  summary: {
    // Total issues by severity
    issuesBySeverity: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    
    // Total issues by type
    issuesByType: {
      extensions: number;
      frameworks: number;
      dependencies: number;
      code: number;
      infrastructure: number;
      documents: number;
    };
    
    // Total files scanned
    totalFilesScanned: number;
    
    // Technical debt score (0-100)
    technicalDebtScore: number;
    
    // Recommendations for quick wins
    quickWins: string[];
    
    // High-level recommendations
    strategicRecommendations: string[];
  };
  
  // Extension issues found
  extensionIssues: ExtensionIssue[];
  
  // Framework issues found
  frameworkIssues: FrameworkIssue[];
  
  // Dependency issues found
  dependencyIssues: DependencyIssue[];
  
  // Code issues found
  codeIssues: CodeIssue[];
  
  // Infrastructure issues found
  infrastructureIssues: InfrastructureIssue[];
  
  // Document issues found
  documentIssues: DocumentIssue[];
}