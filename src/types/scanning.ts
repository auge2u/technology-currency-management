/**
 * Represents a pattern to check for deprecated code/technology
 */
export interface DeprecationPattern {
  // Unique identifier for this pattern
  id: string;
  
  // Technology category (e.g., 'javascript', 'react', 'python')
  technology: string;
  
  // Short description of the issue
  message: string;
  
  // Detailed description of why this is deprecated/problematic
  description: string;
  
  // How to fix the issue
  remediation: string;
  
  // URL to documentation about this issue
  documentationUrl: string;
  
  // Regular expression to match this pattern
  regex: string;
  
  // Optional regex to exclude certain matches
  exclusionRegex?: string;
  
  // Severity of the issue
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // File types this pattern applies to
  fileTypes: string[]; // e.g., ['js', 'jsx', 'ts', 'tsx']
}

/**
 * Represents a deprecated technology or pattern found in code
 */
export interface CodePatternIssue {
  // Unique identifier for this instance
  id: string;
  
  // ID of the pattern that matched
  patternId: string;
  
  // File where the issue was found
  file: string;
  
  // Line number where the issue was found
  line: number;
  
  // Column where the issue was found
  column: number;
  
  // The actual code snippet containing the issue
  snippet: string;
  
  // The specific text that matched the pattern
  match: string;
  
  // Short description of the issue
  message: string;
  
  // Detailed description of why this is deprecated/problematic
  description: string;
  
  // How to fix the issue
  remediation: string;
  
  // URL to documentation about this issue
  documentationUrl: string;
  
  // Severity of the issue
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // Technology category
  technology: string;
  
  // When this issue was detected
  detectedAt: Date;
}

/**
 * Represents a dependency with associated vulnerabilities and outdated status
 */
export interface DependencyIssue {
  // Dependency name
  name: string;
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Is the dependency outdated?
  isOutdated: boolean;
  
  // Is this a direct or transitive dependency?
  isDirect: boolean;
  
  // Package ecosystem (npm, pip, maven, etc.)
  ecosystem: string;
  
  // Path to the dependency definition file (package.json, requirements.txt, etc.)
  definitionFile: string;
  
  // Known vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // When this dependency was last updated
  lastUpdated?: Date;
  
  // When this dependency will reach end-of-life/end-of-support
  eolDate?: Date;
  
  // Whether this is a deprecated package
  isDeprecated: boolean;
  
  // Deprecation message if available
  deprecationMessage?: string;
  
  // When this issue was detected
  detectedAt: Date;
  
  // Suggested fix (e.g., upgrade command)
  suggestedFix?: string;
}

/**
 * Represents vulnerability information for a dependency
 */
export interface VulnerabilityInfo {
  // Unique identifier (e.g., CVE ID)
  id: string;
  
  // Vulnerability title
  title: string;
  
  // Detailed description
  description: string;
  
  // Severity level
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // URL to vulnerability details
  url: string;
  
  // Versions affected
  affectedVersions: string;
  
  // Versions that fix this vulnerability
  patchedVersions: string;
  
  // Published date of the vulnerability
  publishedDate: Date;
  
  // Recommended action to fix
  remediation: string;
}

/**
 * Represents a browser extension that requires updating
 */
export interface BrowserExtensionIssue {
  // Extension name
  name: string;
  
  // Extension identifier
  id: string;
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Browser this extension is for
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'opera';
  
  // Is the extension outdated?
  isOutdated: boolean;
  
  // Is the extension deprecated?
  isDeprecated: boolean;
  
  // Does the extension have security issues?
  hasSecurityIssues: boolean;
  
  // Has the extension been removed from the store?
  isRemovedFromStore: boolean;
  
  // Known vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // URL to the extension in the browser store
  storeUrl: string;
  
  // When this issue was detected
  detectedAt: Date;
}

/**
 * Represents a framework, library, or system component that is outdated
 */
export interface SystemComponentIssue {
  // Component name
  name: string;
  
  // Component type (framework, library, system)
  type: 'framework' | 'library' | 'system';
  
  // Current version
  currentVersion: string;
  
  // Latest available version
  latestVersion: string;
  
  // Is the component outdated?
  isOutdated: boolean;
  
  // Minimum version recommended for security
  minimumRecommendedVersion: string;
  
  // End of life/support date
  eolDate?: Date;
  
  // Is this component reaching EOL soon?
  isApproachingEol: boolean;
  
  // Time until EOL
  timeUntilEol?: string;
  
  // Known vulnerabilities
  vulnerabilities: VulnerabilityInfo[];
  
  // Suggested upgrade path
  upgradeInstructions?: string;
  
  // Potential impact of upgrading
  upgradeDifficulty: 'low' | 'medium' | 'high';
  
  // Estimated time to upgrade (in person-days)
  estimatedUpgradeEffort: number;
  
  // When this issue was detected
  detectedAt: Date;
}

/**
 * Report summarizing all types of currency issues
 */
export interface TechnologyCurrencyReport {
  // Project summary
  projectName: string;
  scanDate: Date;
  
  // Overall scores
  overallCurrencyScore: number; // 0-100
  securityScore: number; // 0-100
  technicalDebtScore: number; // 0-100
  
  // Issues by category
  codePatternIssues: CodePatternIssue[];
  dependencyIssues: DependencyIssue[];
  browserExtensionIssues: BrowserExtensionIssue[];
  systemComponentIssues: SystemComponentIssue[];
  
  // Summary statistics
  totalIssues: number;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  
  // Remediation summary
  estimatedRemediationEffort: number; // In person-days
  priorityRemediationItems: Array<CodePatternIssue | DependencyIssue | BrowserExtensionIssue | SystemComponentIssue>;
  
  // Historical data for trending
  historicalScores?: { date: Date; score: number; }[];
}
