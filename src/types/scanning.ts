/**
 * Types for code pattern scanning and technology currency monitoring
 */

/**
 * Represents a pattern that should be detected in code as deprecated or outdated
 */
export interface DeprecationPattern {
  // Unique identifier for the pattern
  id: string;
  
  // The technology this pattern is related to (e.g., 'javascript', 'react', 'python')
  technology: string;
  
  // Short message describing the issue
  message: string;
  
  // Detailed description of why this pattern is problematic
  description: string;
  
  // Recommended remediation steps
  remediation: string;
  
  // URL to documentation about the issue
  documentationUrl?: string;
  
  // Regular expression to detect the pattern (if using regex matching)
  regex?: string;
  
  // Regular expression to exclude false positives (optional)
  exclusionRegex?: string;
  
  // Severity level of the issue
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // File types this pattern applies to (e.g., 'js', 'py', 'java')
  fileTypes: string[];
  
  // For AST-based patterns (JavaScript/TypeScript)
  astNodeType?: string;
  
  // Conditions for AST-based matching
  astCondition?: {
    // For function calls: functionName or object.method
    functionName?: string;
    memberExpression?: string;
    
    // For imports
    importSource?: string;
    
    // For JSX
    jsxTag?: string;
  };
}

/**
 * Represents an instance of a deprecated pattern found in code
 */
export interface CodePatternIssue {
  // Unique identifier for this issue
  id: string;
  
  // ID of the pattern that was matched
  patternId: string;
  
  // File where the issue was found
  file: string;
  
  // Line number where the issue was found
  line: number;
  
  // Column number where the issue was found
  column: number;
  
  // Code snippet with the issue
  snippet: string;
  
  // The exact text that matched the pattern
  match: string;
  
  // Message describing the issue
  message: string;
  
  // Detailed description
  description: string;
  
  // Suggested fix
  remediation: string;
  
  // URL to documentation
  documentationUrl?: string;
  
  // Severity level
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // Technology affected
  technology: string;
  
  // When the issue was detected
  detectedAt: Date;
}

/**
 * Information about a browser extension
 */
export interface BrowserExtensionInfo {
  // Extension name
  name: string;
  
  // Extension ID
  id: string;
  
  // Version of the extension
  version: string;
  
  // Browsers this extension is installed on
  browsers: Array<'chrome' | 'firefox' | 'safari' | 'edge'>;
  
  // When the extension was last updated
  lastUpdated?: Date;
  
  // Latest available version
  latestVersion?: string;
  
  // Is the extension outdated?
  outdated: boolean;
  
  // Number of versions behind latest
  versionsBehind?: number;
  
  // Security issues associated with this extension
  securityIssues?: ExtensionSecurityIssue[];
  
  // Known compatibility issues
  compatibilityIssues?: ExtensionCompatibilityIssue[];
  
  // Is the extension deprecated by the developer?
  deprecated: boolean;
  
  // URL to the extension in the store
  storeUrl?: string;
  
  // Permissions used by the extension
  permissions?: string[];
  
  // Active installation count
  activeInstallations?: number;
}

/**
 * Security issue related to a browser extension
 */
export interface ExtensionSecurityIssue {
  // Issue title
  title: string;
  
  // Issue description
  description: string;
  
  // Severity level
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // Is a fix available?
  fixAvailable: boolean;
  
  // Version where the issue is fixed
  fixedInVersion?: string;
  
  // URL to more information
  referenceUrl?: string;
  
  // CVE identifier if applicable
  cveId?: string;
}

/**
 * Compatibility issue related to a browser extension
 */
export interface ExtensionCompatibilityIssue {
  // Issue title
  title: string;
  
  // Issue description
  description: string;
  
  // Affected browser versions
  affectedBrowsers: Array<{
    browser: 'chrome' | 'firefox' | 'safari' | 'edge';
    versions: string;
  }>;
  
  // Is a fix available?
  fixAvailable: boolean;
  
  // Version where the issue is fixed
  fixedInVersion?: string;
  
  // Workaround if available
  workaround?: string;
}

/**
 * Configuration for monitoring version control systems
 */
export interface VersionControlMonitorConfig {
  // Repositories to monitor
  repositories: Array<{
    url: string;
    branch: string;
    credentials?: {
      type: 'ssh' | 'https';
      username?: string;
      token?: string;
      sshKeyPath?: string;
    };
  }>;
  
  // Technologies to detect in commits
  technologiesToMonitor: string[];
  
  // Patterns to detect outdated dependencies in commits
  dependencyPatterns: Record<string, string>;
  
  // Notification configuration
  notifications: {
    enabled: boolean;
    channels: Array<'email' | 'slack' | 'teams' | 'webhook'>;
    recipients: string[];
  };
}

/**
 * Alert generated from monitoring systems
 */
export interface TechnologyAlert {
  // Unique identifier
  id: string;
  
  // Alert type
  type: 'deprecated' | 'outdated' | 'security' | 'end-of-life';
  
  // Technology name
  technology: string;
  
  // Version affected
  version: string;
  
  // Source of the alert
  source: 'code-scan' | 'dependency-scan' | 'browser-extension' | 'api';
  
  // Severity level
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // Alert message
  message: string;
  
  // Detailed description
  description: string;
  
  // Recommended actions
  recommendations: string[];
  
  // Files affected (if applicable)
  affectedFiles?: string[];
  
  // Components affected
  affectedComponents?: string[];
  
  // When the alert was generated
  createdAt: Date;
  
  // When the alert was last updated
  updatedAt: Date;
  
  // Status of the alert
  status: 'open' | 'acknowledged' | 'in-progress' | 'resolved' | 'wontfix';
  
  // Assigned to (if anyone)
  assignedTo?: string;
  
  // Due date for remediation (if applicable)
  dueDate?: Date;
  
  // Related tickets or issues
  relatedTickets?: string[];
  
  // Tags for categorization
  tags?: string[];
}
