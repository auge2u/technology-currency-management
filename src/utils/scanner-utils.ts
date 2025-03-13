/**
 * Utility functions for technology currency scanners
 */

/**
 * Compare version numbers
 * @param a First version
 * @param b Second version
 * @returns Negative if a < b, positive if a > b, 0 if equal
 */
export function compareVersions(a: string, b: string): number {
  // Handle undefined/null values
  if (!a && !b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  
  // Split version strings into components
  const aParts = a.split(/[.-]/).map(part => {
    // If component is numeric, parse it
    return /^\d+$/.test(part) ? parseInt(part, 10) : part;
  });
  
  const bParts = b.split(/[.-]/).map(part => {
    return /^\d+$/.test(part) ? parseInt(part, 10) : part;
  });
  
  // Compare each component
  const maxLength = Math.max(aParts.length, bParts.length);
  
  for (let i = 0; i < maxLength; i++) {
    // Treat missing components as lower than any existing component
    if (i >= aParts.length) return -1;
    if (i >= bParts.length) return 1;
    
    const aVal = aParts[i];
    const bVal = bParts[i];
    
    // If types don't match, try to convert
    if (typeof aVal !== typeof bVal) {
      // If one is a number and one is a string, compare the string representation
      if (typeof aVal === 'number' && typeof bVal === 'string') {
        const comp = String(aVal).localeCompare(bVal);
        if (comp !== 0) return comp;
      } else if (typeof aVal === 'string' && typeof bVal === 'number') {
        const comp = aVal.localeCompare(String(bVal));
        if (comp !== 0) return comp;
      } else {
        // Different types that can't be compared, treat as equal for this component
        continue;
      }
    } else {
      // Same types, compare directly
      if (aVal < bVal) return -1;
      if (aVal > bVal) return 1;
    }
  }
  
  // All components are equal
  return 0;
}

/**
 * Get the number of days between two dates
 * @param start Start date
 * @param end End date
 * @returns Number of days between dates (negative if end is before start)
 */
export function daysBetween(start: Date, end: Date): number {
  const startDate = new Date(start);
  const endDate = new Date(end);
  
  // Set both dates to midnight
  startDate.setHours(0, 0, 0, 0);
  endDate.setHours(0, 0, 0, 0);
  
  // Calculate milliseconds between dates and convert to days
  const diffMs = endDate.getTime() - startDate.getTime();
  return Math.round(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Estimate business impact of outdated technology
 * @param isOutdated Whether technology is outdated
 * @param isDeprecated Whether technology is deprecated
 * @param hasVulnerabilities Whether technology has known vulnerabilities
 * @param isCriticalSystem Whether this is a critical system
 * @returns Business impact score (1-5)
 */
export function estimateBusinessImpact(
  isOutdated: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean,
  isCriticalSystem: boolean
): number {
  let score = 1; // Start with minimal impact
  
  if (isOutdated) score += 1;
  if (isDeprecated) score += 2;
  if (hasVulnerabilities) score += 2;
  if (isCriticalSystem) score += 1;
  
  // Cap at maximum of 5
  return Math.min(score, 5);
}

/**
 * Estimate migration difficulty based on version differences
 * @param currentVersion Current version
 * @param targetVersion Target version
 * @param type Type of technology
 * @returns Migration effort score (1-5)
 */
export function estimateMigrationDifficulty(
  currentVersion: string,
  targetVersion: string,
  type: string
): number {
  // Calculate version gap
  const versionGap = calculateVersionGap(currentVersion, targetVersion);
  
  // Base difficulty on technology type and version gap
  let baseDifficulty: number;
  
  switch (type) {
    case 'js-framework':
    case 'node-framework':
      // JavaScript frameworks often have more breaking changes
      baseDifficulty = 2 + versionGap * 0.7;
      break;
    case 'python-framework':
    case 'java-framework':
    case 'php-framework':
      // More stable frameworks typically
      baseDifficulty = 1.5 + versionGap * 0.6;
      break;
    case 'database':
      // Database migrations can be complex
      baseDifficulty = 3 + versionGap * 0.5;
      break;
    case 'library':
      // Libraries are usually easier to upgrade
      baseDifficulty = 1 + versionGap * 0.4;
      break;
    default:
      // Default for unknown types
      baseDifficulty = 2 + versionGap * 0.5;
  }
  
  // Major version changes are often more difficult
  const majorVersionChange = getMajorVersionChange(currentVersion, targetVersion);
  if (majorVersionChange > 0) {
    baseDifficulty += majorVersionChange * 0.5;
  }
  
  // Cap at minimum 1 and maximum 5
  return Math.max(1, Math.min(Math.round(baseDifficulty), 5));
}

/**
 * Calculate a normalized version gap score
 * @param currentVersion Current version
 * @param targetVersion Target version
 * @returns Version gap score (0-5)
 */
function calculateVersionGap(currentVersion: string, targetVersion: string): number {
  // Extract major and minor versions
  const current = parseVersionParts(currentVersion);
  const target = parseVersionParts(targetVersion);
  
  // Calculate gap score based on major, minor, and patch differences
  const majorDiff = Math.max(0, target.major - current.major);
  const minorDiff = Math.max(0, target.minor - current.minor);
  const patchDiff = Math.max(0, target.patch - current.patch);
  
  // Weight the differences
  return Math.min(5, (majorDiff * 2) + (minorDiff * 0.5) + (patchDiff * 0.1));
}

/**
 * Get the major version change between two versions
 * @param currentVersion Current version
 * @param targetVersion Target version
 * @returns Number of major version increments
 */
function getMajorVersionChange(currentVersion: string, targetVersion: string): number {
  const current = parseVersionParts(currentVersion);
  const target = parseVersionParts(targetVersion);
  
  return Math.max(0, target.major - current.major);
}

/**
 * Parse version string into major, minor, and patch components
 * @param version Version string
 * @returns Object with major, minor, and patch numbers
 */
function parseVersionParts(version: string): { major: number; minor: number; patch: number } {
  // Default values
  const result = { major: 0, minor: 0, patch: 0 };
  
  if (!version) return result;
  
  // Extract version parts
  const parts = version.split(/[.-]/);
  
  // Parse numeric values
  result.major = parseInt(parts[0]) || 0;
  
  if (parts.length > 1) {
    result.minor = parseInt(parts[1]) || 0;
  }
  
  if (parts.length > 2) {
    result.patch = parseInt(parts[2]) || 0;
  }
  
  return result;
}

/**
 * Generate a random ID
 * @param length Length of ID (default: 12)
 * @returns Random ID string
 */
export function generateId(length: number = 12): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return result;
}

/**
 * Filter out false positive outdated dependencies
 * @param dependencyName Name of dependency
 * @param currentVersion Current version
 * @param latestVersion Latest version
 * @returns Whether the dependency should be considered outdated
 */
export function isReallyOutdated(
  dependencyName: string,
  currentVersion: string,
  latestVersion: string
): boolean {
  // Skip checking dependencies that use exact versions for a reason
  const exemptDependencies = [
    // Common dependencies that may have pinned versions
    'react-scripts',
    'typescript',
    'webpack'
  ];
  
  if (exemptDependencies.includes(dependencyName)) {
    // For exempt dependencies, only consider major version differences
    const current = parseVersionParts(currentVersion);
    const latest = parseVersionParts(latestVersion);
    
    return latest.major > current.major;
  }
  
  // For other dependencies, check if the version difference is significant
  return compareVersions(currentVersion, latestVersion) < 0;
}

/**
 * Determine if a dependency is critical based on its usage
 * @param dependencyName Name of dependency
 * @returns Whether the dependency is critical
 */
export function isDependencyCritical(dependencyName: string): boolean {
  // List of dependencies that are typically critical
  const criticalDependencies = [
    // Security-related
    'helmet',
    'jsonwebtoken',
    'bcrypt',
    'crypto',
    'passport',
    'auth0',
    'oauth',
    
    // Core framework/runtime
    'react',
    'angular',
    'vue',
    'express',
    'next',
    'nuxt',
    'nest',
    'django',
    'flask',
    'spring',
    'laravel',
    'rails',
    
    // Database
    'mongoose',
    'sequelize',
    'typeorm',
    'prisma',
    'knex',
    'objection',
    'pg',
    'mongodb',
    'mysql',
    'sqlite',
    
    // State management
    'redux',
    'mobx',
    'vuex',
    'recoil',
    'zustand'
  ];
  
  return criticalDependencies.some(dep => 
    dependencyName === dep || dependencyName.startsWith(`${dep}-`) || dependencyName.startsWith(`${dep}/`)
  );
}
