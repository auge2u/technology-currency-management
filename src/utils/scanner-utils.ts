import * as semver from 'semver';

/**
 * Compare two versions
 * Returns: 
 * - negative if version1 < version2
 * - positive if version1 > version2
 * - 0 if equal
 */
export function compareVersions(version1: string, version2: string): number {
  // Try semver comparison first
  try {
    // Clean and normalize versions for semver
    const cleanV1 = semver.valid(semver.coerce(version1));
    const cleanV2 = semver.valid(semver.coerce(version2));
    
    if (cleanV1 && cleanV2) {
      return semver.compare(cleanV1, cleanV2);
    }
  } catch (error) {
    // Fall back to simple comparison if semver fails
  }
  
  // Simple version comparison for non-semver versions
  const v1Parts = version1.split('.').map(p => parseInt(p, 10) || 0);
  const v2Parts = version2.split('.').map(p => parseInt(p, 10) || 0);
  
  // Add zeroes to make arrays the same length
  while (v1Parts.length < v2Parts.length) v1Parts.push(0);
  while (v2Parts.length < v1Parts.length) v2Parts.push(0);
  
  // Compare each part
  for (let i = 0; i < v1Parts.length; i++) {
    if (v1Parts[i] > v2Parts[i]) return 1;
    if (v1Parts[i] < v2Parts[i]) return -1;
  }
  
  return 0;
}

/**
 * Calculate days between two dates
 */
export function daysBetween(date1: Date, date2: Date): number {
  const oneDay = 24 * 60 * 60 * 1000; // hours*minutes*seconds*milliseconds
  const diffDays = Math.round(Math.abs((date1.getTime() - date2.getTime()) / oneDay));
  return diffDays;
}

/**
 * Check if a dependency is outdated enough to be a concern
 * Some minor version differences might not be worth updating
 */
export function isReallyOutdated(name: string, currentVersion: string, latestVersion: string): boolean {
  try {
    // If we can use semver, we'll do a more nuanced check
    const cleanCurrent = semver.valid(semver.coerce(currentVersion));
    const cleanLatest = semver.valid(semver.coerce(latestVersion));
    
    if (cleanCurrent && cleanLatest) {
      // Major version difference is always a concern
      if (semver.major(cleanCurrent) < semver.major(cleanLatest)) {
        return true;
      }
      
      // For minor version, it depends on the age of the package
      if (semver.minor(cleanCurrent) < semver.minor(cleanLatest)) {
        // If it's more than 2 minor versions behind, it's outdated
        return semver.minor(cleanLatest) - semver.minor(cleanCurrent) >= 2;
      }
      
      // For patch versions, only flag if significantly behind
      return semver.patch(cleanLatest) - semver.patch(cleanCurrent) >= 5;
    }
  } catch (error) {
    // Fall back to simpler comparison
  }
  
  // If semver fails, just do basic comparison
  return compareVersions(currentVersion, latestVersion) < 0;
}

/**
 * Check if a dependency is critical based on its name
 * Critical dependencies are those that would cause significant 
 * business impact if they had issues
 */
export function isDependencyCritical(name: string): boolean {
  // List of keywords that might indicate a critical dependency
  const criticalKeywords = [
    'auth', 'security', 'payment', 'passport', 'oauth', 
    'database', 'storage', 'core', 'api', 'server', 
    'mongo', 'sql', 'postgres', 'mysql', 'oracle',
    'aws-sdk', 'azure', 'firebase', 'crypto', 'bcrypt',
    'express', 'koa', 'fastify', 'react', 'angular', 'vue'
  ];
  
  const nameLower = name.toLowerCase();
  return criticalKeywords.some(keyword => nameLower.includes(keyword));
}

/**
 * Check if a component should be excluded from scanning
 */
export function shouldExcludeComponent(path: string, excludePatterns: string[] = []): boolean {
  // Common patterns to exclude
  const defaultExcludes = [
    'node_modules', '.git', 'dist', 'build', 'target',
    'coverage', '.idea', '.vscode', 'test', 'tests',
    '.cache', '.next', '.nuxt', 'bin', 'obj'
  ];
  
  const allPatterns = [...defaultExcludes, ...excludePatterns];
  
  // Check if path matches any exclude pattern
  return allPatterns.some(pattern => {
    if (pattern.startsWith('**/')) {
      // Handle glob pattern
      return path.includes(pattern.substring(3));
    } else if (pattern.endsWith('/**')) {
      // Handle directory and all subdirectories
      return path.startsWith(pattern.substring(0, pattern.length - 3));
    } else {
      // Exact match or simple substring
      return path.includes(pattern);
    }
  });
}

/**
 * Get version change type (major, minor, patch)
 */
export function getVersionChangeType(currentVersion: string, latestVersion: string): 'major' | 'minor' | 'patch' | 'unknown' {
  try {
    const cleanCurrent = semver.valid(semver.coerce(currentVersion));
    const cleanLatest = semver.valid(semver.coerce(latestVersion));
    
    if (cleanCurrent && cleanLatest) {
      if (semver.major(cleanCurrent) < semver.major(cleanLatest)) {
        return 'major';
      }
      
      if (semver.minor(cleanCurrent) < semver.minor(cleanLatest)) {
        return 'minor';
      }
      
      if (semver.patch(cleanCurrent) < semver.patch(cleanLatest)) {
        return 'patch';
      }
      
      return 'unknown';
    }
  } catch (error) {
    // Fall back to simple comparison
  }
  
  // Can't determine type with simple version comparison
  return 'unknown';
}

/**
 * Classify the migration risk based on dependency change
 */
export function classifyMigrationRisk(
  name: string, 
  versionChangeType: 'major' | 'minor' | 'patch' | 'unknown', 
  hasVulnerabilities: boolean
): 'low' | 'medium' | 'high' | 'critical' {
  // Critical dependencies with major version changes have high risk
  if (isDependencyCritical(name) && versionChangeType === 'major') {
    return hasVulnerabilities ? 'critical' : 'high';
  }
  
  // Major version changes generally have medium risk
  if (versionChangeType === 'major') {
    return hasVulnerabilities ? 'high' : 'medium';
  }
  
  // Minor version changes have lower risk
  if (versionChangeType === 'minor') {
    return hasVulnerabilities ? 'medium' : 'low';
  }
  
  // Patch versions are typically low risk
  return hasVulnerabilities ? 'medium' : 'low';
}

/**
 * Calculate the health score for a project based on issues
 */
export function calculateHealthScore(
  totalDependencies: number,
  outdatedDependencies: number,
  vulnerableDependencies: number,
  deprecatedDependencies: number,
  eolFrameworks: number
): number {
  // Start with a perfect score
  let score = 100;
  
  // Calculate percentages
  const outdatedPercent = totalDependencies > 0 ? (outdatedDependencies / totalDependencies) * 100 : 0;
  const vulnerablePercent = totalDependencies > 0 ? (vulnerableDependencies / totalDependencies) * 100 : 0;
  const deprecatedPercent = totalDependencies > 0 ? (deprecatedDependencies / totalDependencies) * 100 : 0;
  
  // Deduct points based on issues
  // Vulnerable dependencies have the biggest impact
  score -= vulnerablePercent * 0.5;
  
  // Deprecated dependencies are next
  score -= deprecatedPercent * 0.3;
  
  // Outdated dependencies have less impact
  score -= outdatedPercent * 0.2;
  
  // EOL frameworks have a fixed impact
  score -= eolFrameworks * 5;
  
  // Ensure the score stays in the 0-100 range
  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Format a date for display
 */
export function formatDate(date?: Date): string {
  if (!date) {
    return 'N/A';
  }
  
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

/**
 * Generate a simple hash for caching
 */
export function generateHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16);
}

/**
 * Calculate priority of an issue
 */
export function calculateIssuePriority(
  businessImpact: number, 
  securityImpact?: number, 
  isEol?: boolean,
  isDeprecated?: boolean
): 'critical' | 'high' | 'medium' | 'low' {
  // Security vulnerabilities take precedence
  if (securityImpact && securityImpact >= 4) {
    return 'critical';
  }
  
  // EOL technologies are high priority
  if (isEol) {
    return businessImpact >= 4 ? 'critical' : 'high';
  }
  
  // Deprecated technologies with high business impact
  if (isDeprecated && businessImpact >= 4) {
    return 'high';
  }
  
  // Map business impact to priority
  if (businessImpact >= 5) return 'critical';
  if (businessImpact >= 4) return 'high';
  if (businessImpact >= 2) return 'medium';
  return 'low';
}
