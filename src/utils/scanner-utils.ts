/**
 * Utility functions for technology scanners
 */

/**
 * Compare two version strings
 * @param version1 First version string
 * @param version2 Second version string
 * @returns -1 if version1 < version2, 0 if equal, 1 if version1 > version2
 */
export function compareVersions(version1: string, version2: string): number {
  if (!version1 && !version2) return 0;
  if (!version1) return -1;
  if (!version2) return 1;
  
  // Split versions into components
  const v1Components = version1.split(/[.-]/);
  const v2Components = version2.split(/[.-]/);
  
  // Compare each component
  const maxLength = Math.max(v1Components.length, v2Components.length);
  
  for (let i = 0; i < maxLength; i++) {
    // If a component is missing, treat it as 0
    const v1Component = i < v1Components.length ? parseInt(v1Components[i], 10) || 0 : 0;
    const v2Component = i < v2Components.length ? parseInt(v2Components[i], 10) || 0 : 0;
    
    if (v1Component < v2Component) return -1;
    if (v1Component > v2Component) return 1;
  }
  
  return 0;
}

/**
 * Format a date for display
 * @param date Date to format
 * @returns Formatted date string
 */
export function formatDate(date?: Date): string {
  if (!date) return 'Unknown';
  return date.toISOString().split('T')[0];
}

/**
 * Calculate days between two dates
 * @param date1 First date
 * @param date2 Second date (defaults to current date)
 * @returns Number of days between dates
 */
export function daysBetween(date1: Date, date2: Date = new Date()): number {
  const oneDay = 24 * 60 * 60 * 1000; // hours*minutes*seconds*milliseconds
  const diffDays = Math.round(Math.abs((date1.getTime() - date2.getTime()) / oneDay));
  return diffDays;
}

/**
 * Check if a version string is a valid semantic version
 * @param version Version string to check
 * @returns True if valid semver
 */
export function isValidSemver(version: string): boolean {
  const semverRegex = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
  return semverRegex.test(version);
}

/**
 * Parse a semantic version string into its components
 * @param version Semver string
 * @returns Object with version components
 */
export function parseSemver(version: string): {
  major: number;
  minor: number;
  patch: number;
  prerelease: string;
  buildmetadata: string;
} {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)(?:-([\w.-]+))?(?:\+([\w.-]+))?$/);
  
  if (!match) {
    return {
      major: 0,
      minor: 0,
      patch: 0,
      prerelease: '',
      buildmetadata: ''
    };
  }
  
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
    prerelease: match[4] || '',
    buildmetadata: match[5] || ''
  };
}

/**
 * Estimate the business impact of outdated technology
 * @param isOutdated Whether the technology is outdated
 * @param isDeprecated Whether the technology is deprecated
 * @param hasVulnerabilities Whether the technology has vulnerabilities
 * @param isCriticalSystem Whether this is a critical system component
 * @returns Business impact score from 1-5
 */
export function estimateBusinessImpact(
  isOutdated: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean,
  isCriticalSystem: boolean
): number {
  // Start with a base impact level
  let impact = 1;
  
  // Adjust based on conditions
  if (isOutdated) impact += 1;
  if (isDeprecated) impact += 2;
  if (hasVulnerabilities) impact += 2;
  if (isCriticalSystem) impact += 1;
  
  // Cap at 5
  return Math.min(5, impact);
}

/**
 * Calculate percentage difference between two versions
 * @param currentVersion Current version
 * @param latestVersion Latest version
 * @returns Percentage behind (0-100)
 */
export function calculateVersionDifference(
  currentVersion: string,
  latestVersion: string
): number {
  const current = parseSemver(currentVersion);
  const latest = parseSemver(latestVersion);
  
  // For major version differences, use a scale based on semantic versioning
  const majorDiff = latest.major - current.major;
  
  if (majorDiff > 0) {
    // Calculate percentage based on major version difference
    // Each major version is considered a 20% gap
    return Math.min(100, majorDiff * 20);
  }
  
  // For minor version differences
  const minorDiff = latest.minor - current.minor;
  
  if (minorDiff > 0) {
    // Each minor version is a 5% gap
    return Math.min(19, minorDiff * 5);
  }
  
  // For patch version differences
  const patchDiff = latest.patch - current.patch;
  
  if (patchDiff > 0) {
    // Each patch is a 1% gap
    return Math.min(4, patchDiff);
  }
  
  return 0;
}

/**
 * Generate a migration score based on how challenging it would be to update
 * @param currentVersion Current version
 * @param latestVersion Latest version
 * @param type Technology type
 * @returns Migration difficulty score from 1-5
 */
export function estimateMigrationDifficulty(
  currentVersion: string,
  latestVersion: string,
  type: string
): number {
  // Start with a base difficulty level
  let difficulty = 1;
  
  // Check version difference
  const versionDiff = calculateVersionDifference(currentVersion, latestVersion);
  
  // Adjust difficulty based on version difference
  if (versionDiff >= 50) {
    difficulty += 3; // Major version jump (multiple major versions behind)
  } else if (versionDiff >= 20) {
    difficulty += 2; // Major version jump
  } else if (versionDiff >= 10) {
    difficulty += 1; // Significant minor version jump
  }
  
  // Adjust based on known difficult migrations
  const highDifficultyTypes = ['database', 'core-framework', 'language-runtime'];
  if (highDifficultyTypes.some(t => type.includes(t))) {
    difficulty += 1;
  }
  
  // Cap at 5
  return Math.min(5, difficulty);
}

/**
 * Calculate the age of a technology version in days
 * @param releaseDate Release date of the version
 * @returns Age in days
 */
export function calculateVersionAge(releaseDate?: Date): number {
  if (!releaseDate) return 0;
  return daysBetween(releaseDate);
}

/**
 * Check if a version is within its support lifecycle
 * @param version Version to check
 * @param endOfSupportDate End of support date
 * @returns True if supported
 */
export function isVersionSupported(version: string, endOfSupportDate?: Date): boolean {
  if (!endOfSupportDate) return true;
  return new Date() < endOfSupportDate;
}

/**
 * Format a timeframe into a human-readable string
 * @param days Number of days
 * @returns Human-readable timeframe
 */
export function formatTimeframe(days: number): string {
  if (days < 0) return 'Already passed';
  if (days === 0) return 'Today';
  if (days < 30) return `${days} days`;
  if (days < 365) return `${Math.round(days / 30)} months`;
  return `${Math.round(days / 365)} years`;
}

/**
 * Prioritize issues based on urgency and impact
 * @param issues Array of issues with impact and urgency scores
 * @returns Sorted array of issues
 */
export function prioritizeIssues<T extends { businessImpact?: number; securityImpact?: number }>(issues: T[]): T[] {
  return [...issues].sort((a, b) => {
    const aImpact = Math.max(a.businessImpact || 0, a.securityImpact || 0);
    const bImpact = Math.max(b.businessImpact || 0, b.securityImpact || 0);
    return bImpact - aImpact;
  });
}
