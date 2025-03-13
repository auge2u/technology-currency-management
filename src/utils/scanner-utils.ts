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
  if (version1 === version2) return 0;
  
  // Handle non-standard version strings
  if (version1 === 'latest') return -1; // 'latest' is always less than any version
  if (version2 === 'latest') return 1;  // Any version is greater than 'latest'
  
  // Extract numeric parts for comparison
  const parts1 = version1.split(/[.-]/).map(part => {
    // Try to parse as a number if possible
    const num = parseInt(part, 10);
    return isNaN(num) ? part : num;
  });
  
  const parts2 = version2.split(/[.-]/).map(part => {
    const num = parseInt(part, 10);
    return isNaN(num) ? part : num;
  });
  
  // Compare each part
  const maxLength = Math.max(parts1.length, parts2.length);
  
  for (let i = 0; i < maxLength; i++) {
    // Treat missing parts as 0 for numeric or '' for strings
    const part1 = i < parts1.length ? parts1[i] : (typeof parts1[0] === 'number' ? 0 : '');
    const part2 = i < parts2.length ? parts2[i] : (typeof parts2[0] === 'number' ? 0 : '');
    
    // Different types, convert to string for comparison
    if (typeof part1 !== typeof part2) {
      const str1 = String(part1);
      const str2 = String(part2);
      
      if (str1 < str2) return -1;
      if (str1 > str2) return 1;
      continue;
    }
    
    // Same types, compare directly
    if (part1 < part2) return -1;
    if (part1 > part2) return 1;
  }
  
  // All parts equal
  return 0;
}

/**
 * Calculate days between two dates
 * @param date1 First date
 * @param date2 Second date
 * @returns Number of days between dates
 */
export function daysBetween(date1: Date, date2: Date): number {
  // Convert both dates to milliseconds since epoch
  const date1Ms = date1.getTime();
  const date2Ms = date2.getTime();
  
  // Calculate difference in milliseconds
  const diffMs = Math.abs(date2Ms - date1Ms);
  
  // Convert to days and return
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Check if a version is within a version range
 * @param version Version to check
 * @param range Version range (e.g., '>=1.0.0 <2.0.0')
 * @returns Whether the version is in the range
 */
export function isVersionInRange(version: string, range: string): boolean {
  // Handle simple ranges
  if (range.includes('||')) {
    // OR ranges, e.g., '>=1.0.0 <2.0.0 || >=3.0.0'
    const orRanges = range.split('||').map(r => r.trim());
    return orRanges.some(orRange => isVersionInRange(version, orRange));
  }
  
  // Handle multiple conditions
  if (range.includes(' ')) {
    // AND ranges, e.g., '>=1.0.0 <2.0.0'
    const andRanges = range.split(' ').map(r => r.trim()).filter(r => r !== '');
    return andRanges.every(andRange => isVersionInSimpleRange(version, andRange));
  }
  
  // Handle single condition
  return isVersionInSimpleRange(version, range);
}

/**
 * Check if a version is within a simple version range
 * @param version Version to check
 * @param range Simple version range (e.g., '>=1.0.0')
 * @returns Whether the version is in the range
 */
function isVersionInSimpleRange(version: string, range: string): boolean {
  // Extract operator and version from range
  const match = range.match(/^([<>=~^]*)(.*)$/);
  
  if (!match) {
    return version === range; // Exact match if no operator
  }
  
  const [, operator, rangeVersion] = match;
  
  // Compare based on operator
  const comparison = compareVersions(version, rangeVersion);
  
  switch (operator) {
    case '>':
      return comparison > 0;
    case '>=':
      return comparison >= 0;
    case '<':
      return comparison < 0;
    case '<=':
      return comparison <= 0;
    case '=':
    case '==':
      return comparison === 0;
    case '~':
      // Compatible changes (patch level)
      // ~1.2.3 is equivalent to >=1.2.3 <1.3.0
      const parts = rangeVersion.split('.');
      const nextMinor = [...parts];
      nextMinor[1] = String(parseInt(nextMinor[1] || '0', 10) + 1);
      nextMinor[2] = '0';
      
      return isVersionInRange(version, `>=${rangeVersion} <${nextMinor.join('.')}`);
    case '^':
      // Compatible changes (minor level)
      // ^1.2.3 is equivalent to >=1.2.3 <2.0.0
      const caretParts = rangeVersion.split('.');
      const nextMajor = [...caretParts];
      nextMajor[0] = String(parseInt(nextMajor[0] || '0', 10) + 1);
      nextMajor[1] = '0';
      nextMajor[2] = '0';
      
      return isVersionInRange(version, `>=${rangeVersion} <${nextMajor.join('.')}`);
    default:
      return version === rangeVersion; // Default to exact match
  }
}

/**
 * Parse a vulnerability impact score (CVSS) into a severity level
 * @param cvssScore CVSS score (0-10)
 * @returns Severity level ('low', 'medium', 'high', 'critical')
 */
export function cvssToSeverity(cvssScore: number): 'low' | 'medium' | 'high' | 'critical' {
  if (cvssScore >= 9.0) return 'critical';
  if (cvssScore >= 7.0) return 'high';
  if (cvssScore >= 4.0) return 'medium';
  return 'low';
}

/**
 * Estimate business impact from technical factors
 * @param isOutdated Whether the component is outdated
 * @param isDeprecated Whether the component is deprecated
 * @param hasVulnerabilities Whether the component has vulnerabilities
 * @param criticalSystemComponent Whether this is a critical system component
 * @returns Business impact score (1-5)
 */
export function estimateBusinessImpact(
  isOutdated: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean,
  criticalSystemComponent: boolean
): number {
  let score = 1; // Start with minimal impact
  
  if (isOutdated) score += 1;
  if (isDeprecated) score += 1;
  if (hasVulnerabilities) score += 2;
  if (criticalSystemComponent) score += 1;
  
  return Math.min(5, score); // Cap at 5
}

/**
 * Generate a standardized ID for a detected issue
 * @param issueType Type of issue (framework, dependency, extension)
 * @param name Name of the component
 * @param version Version of the component
 * @returns Unique issue ID
 */
export function generateIssueId(
  issueType: string,
  name: string,
  version: string
): string {
  // Create a consistent ID format for tracking issues
  const nameSlug = name.toLowerCase().replace(/[^a-z0-9]/g, '-');
  const versionSlug = version.replace(/[^a-z0-9.]/g, '-');
  
  return `${issueType}-${nameSlug}-${versionSlug}`;
}

/**
 * Format a date for display or storage
 * @param date Date to format
 * @param format Format style ('iso', 'short', 'long')
 * @returns Formatted date string
 */
export function formatDate(
  date: Date | undefined,
  format: 'iso' | 'short' | 'long' = 'iso'
): string {
  if (!date) return 'N/A';
  
  switch (format) {
    case 'iso':
      return date.toISOString();
    case 'short':
      return date.toLocaleDateString();
    case 'long':
      return date.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    default:
      return date.toISOString();
  }
}
