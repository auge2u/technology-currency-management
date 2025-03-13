import { CodePatternIssue, DependencyIssue, BrowserExtensionIssue, SystemComponentIssue } from '../types/scanning';

/**
 * Severity levels in order from least to most severe
 */
const SEVERITY_LEVELS = {
  'low': 0,
  'medium': 1,
  'high': 2,
  'critical': 3
};

/**
 * Determines if a given file content is likely a binary file
 * 
 * @param content File content as string
 * @returns True if the file appears to be binary
 */
export function isBinaryFile(content: string): boolean {
  // Check for null bytes which are common in binary files
  if (content.includes('\0')) {
    return true;
  }
  
  // Check if the file has a high percentage of non-printable characters
  const nonPrintableChars = content.replace(/[\x20-\x7E\n\r\t]/g, '');
  const ratio = nonPrintableChars.length / content.length;
  
  // If more than 30% of the characters are non-printable, consider it binary
  return ratio > 0.3;
}

/**
 * Filter issues by severity threshold
 * 
 * @param issues Array of issues to filter
 * @param threshold Minimum severity level to include
 * @returns Filtered array of issues meeting the severity threshold
 */
export function filterBySeverity<T extends { severity: 'low' | 'medium' | 'high' | 'critical' }>(
  issues: T[],
  threshold: 'low' | 'medium' | 'high' | 'critical'
): T[] {
  const thresholdLevel = SEVERITY_LEVELS[threshold];
  
  return issues.filter(issue => {
    const issueLevel = SEVERITY_LEVELS[issue.severity];
    return issueLevel >= thresholdLevel;
  });
}

/**
 * Categorize issues by severity
 * 
 * @param issues Array of issues to categorize
 * @returns Object with counts by severity
 */
export function categorizeBySeverity<T extends { severity: 'low' | 'medium' | 'high' | 'critical' }>(
  issues: T[]
): { low: number; medium: number; high: number; critical: number; total: number } {
  const result = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
    total: issues.length
  };
  
  issues.forEach(issue => {
    result[issue.severity]++;
  });
  
  return result;
}

/**
 * Group issues by file path
 * 
 * @param issues Array of code pattern issues
 * @returns Object with issues grouped by file path
 */
export function groupIssuesByFile(issues: CodePatternIssue[]): Record<string, CodePatternIssue[]> {
  return issues.reduce((groups, issue) => {
    const file = issue.file;
    if (!groups[file]) {
      groups[file] = [];
    }
    groups[file].push(issue);
    return groups;
  }, {} as Record<string, CodePatternIssue[]>);
}

/**
 * Group issues by technology
 * 
 * @param issues Array of issues with technology field
 * @returns Object with issues grouped by technology
 */
export function groupIssuesByTechnology<T extends { technology: string }>(
  issues: T[]
): Record<string, T[]> {
  return issues.reduce((groups, issue) => {
    const tech = issue.technology;
    if (!groups[tech]) {
      groups[tech] = [];
    }
    groups[tech].push(issue);
    return groups;
  }, {} as Record<string, T[]>);
}

/**
 * Calculate severity score based on issue counts
 * The score is 100 (perfect) - weighted deductions for issues
 * 
 * @param issuesSummary Object with counts by severity
 * @returns Score from 0-100
 */
export function calculateSeverityScore(
  issuesSummary: { low: number; medium: number; high: number; critical: number }
): number {
  // Weights for each severity level
  const weights = {
    low: 1,
    medium: 3,
    high: 10,
    critical: 25
  };
  
  // Calculate weighted deductions
  const deduction = 
    (issuesSummary.low * weights.low) +
    (issuesSummary.medium * weights.medium) +
    (issuesSummary.high * weights.high) +
    (issuesSummary.critical * weights.critical);
  
  // Start with 100 and subtract deductions, minimum score is 0
  return Math.max(0, Math.min(100, 100 - deduction));
}

/**
 * Get priority remediation items based on severity
 * 
 * @param issues All issues of different types
 * @param limit Maximum number of items to include
 * @returns Array of highest priority issues
 */
export function getPriorityRemediationItems(
  codeIssues: CodePatternIssue[],
  dependencyIssues: DependencyIssue[],
  extensionIssues: BrowserExtensionIssue[],
  componentIssues: SystemComponentIssue[],
  limit: number = 10
): Array<CodePatternIssue | DependencyIssue | BrowserExtensionIssue | SystemComponentIssue> {
  // Combine all issues and add type information for later identification
  const allIssues = [
    ...codeIssues.map(issue => ({ ...issue, issueType: 'code' as const })),
    ...dependencyIssues.map(issue => ({ ...issue, issueType: 'dependency' as const })),
    ...extensionIssues.map(issue => ({ ...issue, issueType: 'extension' as const })),
    ...componentIssues.map(issue => ({ ...issue, issueType: 'component' as const }))
  ];
  
  // Sort by severity (critical -> high -> medium -> low)
  const sortedIssues = allIssues.sort((a, b) => {
    return SEVERITY_LEVELS[b.severity] - SEVERITY_LEVELS[a.severity];
  });
  
  // Take the top N issues
  const topIssues = sortedIssues.slice(0, limit);
  
  // Remove the added issueType property before returning
  return topIssues.map(({ issueType, ...issue }) => issue as any);
}

/**
 * Parse version string into comparable components
 * 
 * @param version Version string (e.g., "1.2.3-beta.1")
 * @returns Object with parsed components
 */
export function parseVersion(version: string): { 
  major: number; 
  minor: number; 
  patch: number; 
  prerelease: string | null;
  buildMetadata: string | null;
} {
  // Handle standard semver format: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
  const semverRegex = /^(\d+)\.(\d+)\.(\d+)(?:-([^+]+))?(?:\+(.+))?$/;
  const match = version.match(semverRegex);
  
  if (match) {
    return {
      major: parseInt(match[1], 10),
      minor: parseInt(match[2], 10),
      patch: parseInt(match[3], 10),
      prerelease: match[4] || null,
      buildMetadata: match[5] || null
    };
  }
  
  // Fallback for non-standard versions
  const parts = version.split('.');
  return {
    major: parseInt(parts[0] || '0', 10),
    minor: parseInt(parts[1] || '0', 10),
    patch: parseInt(parts[2] || '0', 10),
    prerelease: null,
    buildMetadata: null
  };
}

/**
 * Compare two version strings
 * 
 * @param versionA First version string
 * @param versionB Second version string
 * @returns -1 if A < B, 0 if A = B, 1 if A > B
 */
export function compareVersions(versionA: string, versionB: string): number {
  const a = parseVersion(versionA);
  const b = parseVersion(versionB);
  
  // Compare major, minor, patch
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  
  // Handle prereleases
  // A version with a prerelease has lower precedence than the same version without it
  if (a.prerelease === null && b.prerelease !== null) return 1;
  if (a.prerelease !== null && b.prerelease === null) return -1;
  if (a.prerelease !== null && b.prerelease !== null) {
    // Simple string comparison for prerelease parts
    if (a.prerelease < b.prerelease) return -1;
    if (a.prerelease > b.prerelease) return 1;
  }
  
  return 0;
}

/**
 * Calculate version difference significance
 * 
 * @param currentVersion Current version string
 * @param latestVersion Latest version string
 * @returns Difference type: 'none', 'patch', 'minor', 'major'
 */
export function getVersionDifferenceType(
  currentVersion: string, 
  latestVersion: string
): 'none' | 'patch' | 'minor' | 'major' {
  const current = parseVersion(currentVersion);
  const latest = parseVersion(latestVersion);
  
  if (latest.major > current.major) return 'major';
  if (latest.minor > current.minor) return 'minor';
  if (latest.patch > current.patch) return 'patch';
  return 'none';
}

/**
 * Estimate upgrade effort based on version difference
 * 
 * @param currentVersion Current version string
 * @param targetVersion Target version string
 * @returns Estimated upgrade difficulty
 */
export function estimateUpgradeDifficulty(
  currentVersion: string,
  targetVersion: string,
  baseComplexity: 'low' | 'medium' | 'high' = 'medium'
): 'low' | 'medium' | 'high' {
  const diffType = getVersionDifferenceType(currentVersion, targetVersion);
  
  // Complexity matrix based on version difference and base complexity
  const complexityMatrix: {
    [key in 'low' | 'medium' | 'high']: {
      [key in 'none' | 'patch' | 'minor' | 'major']: 'low' | 'medium' | 'high'
    }
  } = {
    low: {
      none: 'low',
      patch: 'low',
      minor: 'medium',
      major: 'high'
    },
    medium: {
      none: 'low',
      patch: 'medium',
      minor: 'medium',
      major: 'high'
    },
    high: {
      none: 'medium',
      patch: 'medium',
      minor: 'high',
      major: 'high'
    }
  };
  
  return complexityMatrix[baseComplexity][diffType];
}
