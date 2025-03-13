import * as semver from 'semver';
import { log } from './logging';

/**
 * Compare two version strings
 * Returns:
 * - negative if version1 < version2
 * - 0 if version1 === version2
 * - positive if version1 > version2
 */
export function compareVersions(version1: string, version2: string): number {
  try {
    // Clean the versions to handle different formats
    const cleanedVersion1 = cleanVersionString(version1);
    const cleanedVersion2 = cleanVersionString(version2);
    
    // Try semver comparison first
    if (semver.valid(cleanedVersion1) && semver.valid(cleanedVersion2)) {
      return semver.compare(cleanedVersion1, cleanedVersion2);
    }
    
    // Fall back to custom comparison for non-semver versions
    return compareVersionParts(cleanedVersion1, cleanedVersion2);
  } catch (error) {
    log.warn('Error comparing versions', { error, version1, version2 });
    return 0; // Assume equal if comparison fails
  }
}

/**
 * Clean a version string to make it more comparable
 */
export function cleanVersionString(version: string): string {
  // Remove common prefixes like 'v', '=', '^', '~'
  let cleaned = version.trim().replace(/^[v=^~]+/, '');
  
  // Handle ranges by taking the upper bound for '>=' and '>' and lower bound for '<=' and '<'
  if (cleaned.startsWith('>=') || cleaned.startsWith('>')) {
    cleaned = cleaned.substring(cleaned.indexOf(' ') + 1);
  } else if (cleaned.startsWith('<=') || cleaned.startsWith('<')) {
    cleaned = cleaned.substring(cleaned.indexOf(' ') + 1);
  }
  
  // Convert '-SNAPSHOT', '-beta', etc. to prerelease format that semver understands
  if (cleaned.includes('-') && !cleaned.includes('-rc') && !cleaned.includes('-alpha') && 
      !cleaned.includes('-beta') && !cleaned.includes('-pre')) {
    const parts = cleaned.split('-');
    if (parts.length === 2) {
      if (parts[1].toLowerCase() === 'snapshot') {
        cleaned = `${parts[0]}-snapshot.0`;
      } else {
        cleaned = `${parts[0]}-0.${parts[1]}`;
      }
    }
  }
  
  return cleaned;
}

/**
 * Compare version parts for non-semver versions
 */
function compareVersionParts(version1: string, version2: string): number {
  // Split into parts by dots and dashes
  const v1Parts = splitVersionIntoParts(version1);
  const v2Parts = splitVersionIntoParts(version2);
  
  // Compare parts one by one
  const maxLength = Math.max(v1Parts.length, v2Parts.length);
  
  for (let i = 0; i < maxLength; i++) {
    // Missing parts are treated as 0
    const v1Part = i < v1Parts.length ? v1Parts[i] : '0';
    const v2Part = i < v2Parts.length ? v2Parts[i] : '0';
    
    // Try numeric comparison if both are numbers
    const v1Num = parseInt(v1Part, 10);
    const v2Num = parseInt(v2Part, 10);
    
    if (!isNaN(v1Num) && !isNaN(v2Num)) {
      if (v1Num !== v2Num) {
        return v1Num - v2Num;
      }
    } else {
      // String comparison if not both numbers
      const stringCompare = v1Part.localeCompare(v2Part);
      if (stringCompare !== 0) {
        return stringCompare;
      }
    }
  }
  
  return 0; // All parts are equal
}

/**
 * Split a version string into parts for comparison
 */
function splitVersionIntoParts(version: string): string[] {
  // Split by dots and handle special characters
  return version
    .replace(/[\-+]/, '.') // Convert dashes and plus signs to dots
    .split('.')
    .map(part => part.trim())
    .filter(part => part.length > 0);
}

/**
 * Calculate days between two dates
 */
export function daysBetween(date1: Date, date2: Date): number {
  const diff = Math.abs(date2.getTime() - date1.getTime());
  return Math.floor(diff / (1000 * 60 * 60 * 24));
}

/**
 * Calculate severity score from 0-100 based on various factors
 */
export function calculateSeverityScore(
  isOutdated: boolean,
  isDeprecated: boolean,
  daysOutdated: number | undefined,
  daysToEndOfLife: number | undefined,
  vulnerabilities: any[]
): number {
  let score = 0;
  
  // Base scores
  if (isOutdated) score += 10;
  if (isDeprecated) score += 30;
  
  // Days outdated score (max 20)
  if (daysOutdated) {
    if (daysOutdated > 365) score += 20;
    else if (daysOutdated > 180) score += 15;
    else if (daysOutdated > 90) score += 10;
    else if (daysOutdated > 30) score += 5;
  }
  
  // Days to end of life (max 30)
  if (daysToEndOfLife !== undefined) {
    if (daysToEndOfLife < 0) score += 30;
    else if (daysToEndOfLife < 30) score += 25;
    else if (daysToEndOfLife < 90) score += 20;
    else if (daysToEndOfLife < 180) score += 10;
    else if (daysToEndOfLife < 365) score += 5;
  }
  
  // Vulnerability score (max 40)
  if (vulnerabilities && vulnerabilities.length > 0) {
    let vulnScore = 0;
    for (const vuln of vulnerabilities) {
      switch (vuln.severity) {
        case 'critical':
          vulnScore += 10;
          break;
        case 'high':
          vulnScore += 7;
          break;
        case 'medium':
          vulnScore += 4;
          break;
        case 'low':
          vulnScore += 1;
          break;
      }
    }
    score += Math.min(40, vulnScore);
  }
  
  // Cap at 100
  return Math.min(100, score);
}

/**
 * Map a severity score (0-100) to a severity level
 */
export function mapScoreToSeverity(score: number): 'critical' | 'high' | 'medium' | 'low' {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

/**
 * Calculate the estimated effort (in days) to remediate an issue
 */
export function estimateRemediationEffort(
  issueType: string,
  severity: string,
  isDeprecated: boolean,
  hasVulnerabilities: boolean
): number {
  // Base effort by issue type
  let baseEffort = 0;
  
  switch (issueType) {
    case 'dependency':
      baseEffort = 0.5; // Half a day for simple dependency updates
      break;
    case 'browserExtension':
      baseEffort = 0.25; // Quarter day for browser extensions
      break;
    case 'framework':
      baseEffort = 5; // 5 days for framework updates (much more complex)
      break;
    case 'database':
      baseEffort = 3; // 3 days for database updates
      break;
    case 'infrastructure':
      baseEffort = 2; // 2 days for infrastructure updates
      break;
    case 'security':
      baseEffort = 1; // 1 day for security component updates
      break;
    case 'languageRuntime':
      baseEffort = 4; // 4 days for language runtime updates
      break;
    default:
      baseEffort = 1; // Default to 1 day
  }
  
  // Multipliers based on severity
  let severityMultiplier = 1.0;
  switch (severity) {
    case 'critical':
      severityMultiplier = 1.5;
      break;
    case 'high':
      severityMultiplier = 1.3;
      break;
    case 'medium':
      severityMultiplier = 1.1;
      break;
    case 'low':
      severityMultiplier = 1.0;
      break;
  }
  
  // Additional factors
  if (isDeprecated) severityMultiplier *= 1.5;
  if (hasVulnerabilities) severityMultiplier *= 1.2;
  
  return baseEffort * severityMultiplier;
}

/**
 * Calculate the estimated business impact of an issue (1-10)
 */
export function estimateBusinessImpact(
  issueType: string,
  severity: string,
  isDeprecated: boolean,
  hasVulnerabilities: boolean,
  daysToEndOfLife?: number
): number {
  // Base impact by issue type
  let baseImpact = 0;
  
  switch (issueType) {
    case 'dependency':
      baseImpact = 3;
      break;
    case 'browserExtension':
      baseImpact = 2;
      break;
    case 'framework':
      baseImpact = 8;
      break;
    case 'database':
      baseImpact = 9;
      break;
    case 'infrastructure':
      baseImpact = 7;
      break;
    case 'security':
      baseImpact = 8;
      break;
    case 'languageRuntime':
      baseImpact = 6;
      break;
    default:
      baseImpact = 5;
  }
  
  // Adjust based on severity
  switch (severity) {
    case 'critical':
      baseImpact += 2;
      break;
    case 'high':
      baseImpact += 1.5;
      break;
    case 'medium':
      baseImpact += 1;
      break;
    case 'low':
      baseImpact += 0;
      break;
  }
  
  // Adjust for other factors
  if (isDeprecated) baseImpact += 1;
  if (hasVulnerabilities) baseImpact += 1.5;
  
  // End of life adjustment
  if (daysToEndOfLife !== undefined) {
    if (daysToEndOfLife < 0) baseImpact += 2;
    else if (daysToEndOfLife < 30) baseImpact += 1.5;
    else if (daysToEndOfLife < 90) baseImpact += 1;
    else if (daysToEndOfLife < 180) baseImpact += 0.5;
  }
  
  // Cap at 10
  return Math.min(10, baseImpact);
}
