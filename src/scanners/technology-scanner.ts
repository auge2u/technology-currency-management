import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { ScannerConfig, TechnologyIssue } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);

/**
 * Configuration specific to technology scanning
 */
export interface TechnologyScannerConfig extends ScannerConfig {
  // Optional custom database of technologies
  customTechnologyDbPath?: string;
  
  // Whether to detect end-of-life dates
  detectEol?: boolean;
  
  // Whether to estimate migration effort
  estimateMigrationEffort?: boolean;
  
  // Maximum number of file samples to read per technology
  maxFileSamplesPerTechnology?: number;
  
  // Custom technology definitions to supplement or override defaults
  customTechnologyDefinitions?: Record<string, TechnologyDefinition>;
  
  // Specific categories to include or exclude
  includeCategories?: Array<'framework' | 'library' | 'language' | 'runtime' | 'platform' | 'api' | 'other'>;
  excludeCategories?: Array<'framework' | 'library' | 'language' | 'runtime' | 'platform' | 'api' | 'other'>;
  
  // Specific technologies to include or exclude
  includeTechnologies?: string[];
  excludeTechnologies?: string[];
}

/**
 * Definition of a technology for detection and analysis
 */
interface TechnologyDefinition {
  // Technology name
  name: string;
  
  // Category of technology
  category: 'framework' | 'library' | 'language' | 'runtime' | 'platform' | 'api' | 'other';
  
  // File patterns where this technology can be found
  filePatterns: string[];
  
  // Regex patterns to detect this technology in files
  detectionPatterns: string[];
  
  // Regex to extract version information
  versionExtractionPattern?: string;
  
  // Default version to assume if not detectable
  defaultVersion?: string;
  
  // List of versions with their status
  versions?: Record<string, {
    releaseDate?: string;
    endOfLifeDate?: string;
    supportStatus: 'active' | 'maintenance' | 'security-only' | 'end-of-life' | 'unknown';
    knownIssues?: string[];
  }>;
  
  // Known alternatives to this technology
  alternatives?: string[];
  
  // Migration effort estimate (1-10)
  migrationEffort?: number;
  
  // Is this technology deprecated
  isDeprecated?: boolean;
  
  // Latest stable version
  latestVersion?: string;
  
  // Vendor/maintainer URL
  vendorUrl?: string;
  
  // Documentation URL
  documentationUrl?: string;
}

/**
 * Scanner for detecting outdated and deprecated technologies
 */
export async function scanTechnologies(
  config: TechnologyScannerConfig
): Promise<TechnologyIssue[]> {
  try {
    log.info('Starting technology scanner');
    const issues: TechnologyIssue[] = [];
    
    // Load technology definitions database
    const technologyDefs = await loadTechnologyDefinitions(config);
    log.info(`Loaded ${Object.keys(technologyDefs).length} technology definitions`);
    
    // Filter definitions based on config
    const filteredDefs = filterTechnologyDefinitions(technologyDefs, config);
    log.info(`Using ${Object.keys(filteredDefs).length} technology definitions after filtering`);
    
    // Scan for each technology
    for (const [techId, definition] of Object.entries(filteredDefs)) {
      try {
        log.info(`Scanning for technology: ${definition.name}`);
        
        // Find files that match the technology patterns
        const matchingFiles = await findMatchingFiles(definition, config);
        log.info(`Found ${matchingFiles.length} files matching patterns for ${definition.name}`);
        
        if (matchingFiles.length === 0) {
          continue; // Skip if no files match
        }
        
        // Analyze the files to confirm technology and detect version
        const analysisResults = await analyzeTechnologyUsage(definition, matchingFiles, config);
        log.info(`Analysis complete for ${definition.name}`);
        
        if (!analysisResults.detected) {
          continue; // Skip if technology was not actually detected
        }
        
        // Check if technology is outdated or deprecated
        const isOutdated = checkIfOutdated(definition, analysisResults.version);
        
        if (isOutdated || definition.isDeprecated === true) {
          // Create an issue
          const daysUntilEndOfLife = calculateDaysUntilEndOfLife(definition, analysisResults.version);
          
          const issue: TechnologyIssue = {
            detectedAt: new Date(),
            name: definition.name,
            category: definition.category,
            currentVersion: analysisResults.version,
            latestVersion: definition.latestVersion,
            isDeprecated: !!definition.isDeprecated,
            isOutdated,
            supportStatus: getTechnologySupportStatus(definition, analysisResults.version),
            knownIssues: getKnownIssues(definition, analysisResults.version),
            affectedFiles: analysisResults.detectedFiles,
            alternatives: definition.alternatives,
            riskLevel: calculateRiskLevel(definition, analysisResults.version, isOutdated),
            tags: generateTags(definition, analysisResults.version, isOutdated),
            recommendation: generateRecommendation(definition, analysisResults.version, isOutdated),
            updateImpact: assessUpdateImpact(definition, analysisResults.version)
          };
          
          // Add end of life information if available
          if (daysUntilEndOfLife !== null) {
            issue.daysUntilEndOfLife = daysUntilEndOfLife;
            
            // Extract the EOL date from the definition
            const versionInfo = definition.versions?.[analysisResults.version];
            if (versionInfo?.endOfLifeDate) {
              issue.endOfLifeDate = new Date(versionInfo.endOfLifeDate);
            }
          }
          
          issues.push(issue);
          log.info(`Added issue for technology ${definition.name} ${analysisResults.version}`);
        }
      } catch (techError) {
        log.error(`Error analyzing technology ${definition.name}`, { error: techError });
      }
    }
    
    log.info(`Completed technology scanning. Found ${issues.length} total issues`);
    return issues;
  } catch (error) {
    log.error('Error during technology scanning', { error });
    return [];
  }
}

/**
 * Load technology definitions from built-in data and custom sources
 */
async function loadTechnologyDefinitions(
  config: TechnologyScannerConfig
): Promise<Record<string, TechnologyDefinition>> {
  // Start with built-in technology definitions
  const definitions = getBuiltInTechnologyDefinitions();
  
  // Add custom definitions from config
  if (config.customTechnologyDefinitions) {
    for (const [id, def] of Object.entries(config.customTechnologyDefinitions)) {
      definitions[id] = def;
    }
  }
  
  // Load from custom database file if specified
  if (config.customTechnologyDbPath && fs.existsSync(config.customTechnologyDbPath)) {
    try {
      const customDb = JSON.parse(await readFileAsync(config.customTechnologyDbPath, 'utf8'));
      
      for (const [id, def] of Object.entries(customDb)) {
        // Validate tech definition structure
        if (isValidTechDefinition(def as any)) {
          definitions[id] = def as TechnologyDefinition;
        } else {
          log.warn(`Invalid technology definition found in custom DB: ${id}`);
        }
      }
    } catch (dbError) {
      log.error('Error loading custom technology database', { error: dbError });
    }
  }
  
  return definitions;
}

/**
 * Check if a technology definition has the required properties
 */
function isValidTechDefinition(def: any): boolean {
  return (
    typeof def === 'object' &&
    typeof def.name === 'string' &&
    ['framework', 'library', 'language', 'runtime', 'platform', 'api', 'other'].includes(def.category) &&
    Array.isArray(def.filePatterns) &&
    Array.isArray(def.detectionPatterns)
  );
}

/**
 * Filter technology definitions based on configuration
 */
function filterTechnologyDefinitions(
  definitions: Record<string, TechnologyDefinition>,
  config: TechnologyScannerConfig
): Record<string, TechnologyDefinition> {
  const filtered: Record<string, TechnologyDefinition> = {};
  
  for (const [id, def] of Object.entries(definitions)) {
    // Skip if explicitly excluded
    if (config.excludeTechnologies?.includes(def.name)) {
      continue;
    }
    
    // Skip if category is excluded
    if (config.excludeCategories?.includes(def.category)) {
      continue;
    }
    
    // Include only if in includeCategories (if specified)
    if (config.includeCategories && !config.includeCategories.includes(def.category)) {
      continue;
    }
    
    // Include only if in includeTechnologies (if specified)
    if (config.includeTechnologies && !config.includeTechnologies.includes(def.name)) {
      continue;
    }
    
    filtered[id] = def;
  }
  
  return filtered;
}

/**
 * Find files that match the file patterns for a technology
 */
async function findMatchingFiles(
  definition: TechnologyDefinition,
  config: TechnologyScannerConfig
): Promise<string[]> {
  const matchingFiles: string[] = [];
  
  // Process each file pattern
  for (const pattern of definition.filePatterns) {
    try {
      const files = await glob(pattern, {
        cwd: config.rootDir,
        absolute: true,
        ignore: [...(config.excludePaths || []), '**/node_modules/**', '**/.git/**']
      });
      
      // Apply file size restrictions if configured
      if (config.maxFileSizeBytes) {
        for (const file of files) {
          try {
            const stats = await fs.promises.stat(file);
            if (stats.size <= config.maxFileSizeBytes) {
              matchingFiles.push(file);
            } else {
              log.info(`Skipping file exceeding size limit: ${file} (${stats.size} bytes)`);
            }
          } catch (fileError) {
            log.warn(`Error checking file size for ${file}`, { error: fileError });
          }
        }
      } else {
        matchingFiles.push(...files);
      }
    } catch (globError) {
      log.warn(`Error searching for pattern ${pattern}`, { error: globError });
    }
  }
  
  return [...new Set(matchingFiles)]; // Deduplicate
}

/**
 * Analyze files to detect technology usage and version
 */
async function analyzeTechnologyUsage(
  definition: TechnologyDefinition,
  files: string[],
  config: TechnologyScannerConfig
): Promise<{
  detected: boolean;
  version: string;
  detectedFiles: string[];
}> {
  const result = {
    detected: false,
    version: definition.defaultVersion || 'unknown',
    detectedFiles: [] as string[]
  };
  
  // Limit number of files to analyze if configured
  const filesToAnalyze = config.maxFileSamplesPerTechnology && 
    config.maxFileSamplesPerTechnology < files.length ?
    files.slice(0, config.maxFileSamplesPerTechnology) : 
    files;
  
  // Create regex objects from detection patterns
  const detectionRegexes = definition.detectionPatterns.map(pattern => new RegExp(pattern, 'i'));
  
  // Create version extraction regex if available
  const versionRegex = definition.versionExtractionPattern ? 
    new RegExp(definition.versionExtractionPattern, 'i') : 
    null;
  
  // Analyze each file
  for (const file of filesToAnalyze) {
    try {
      const content = await readFileAsync(file, 'utf8');
      
      // Check if any detection pattern matches
      const detected = detectionRegexes.some(regex => regex.test(content));
      
      if (detected) {
        result.detected = true;
        result.detectedFiles.push(file);
        
        // Extract version if possible
        if (versionRegex) {
          const versionMatch = content.match(versionRegex);
          if (versionMatch && versionMatch[1]) {
            result.version = versionMatch[1].trim();
            // Once we find a version, no need to look further
            // (assuming all files use the same version)
            break;
          }
        }
      }
    } catch (fileError) {
      log.warn(`Error analyzing file ${file}`, { error: fileError });
    }
  }
  
  return result;
}

/**
 * Check if a technology version is outdated
 */
function checkIfOutdated(
  definition: TechnologyDefinition,
  version: string
): boolean {
  // If the technology has a latest version defined
  if (definition.latestVersion && version !== 'unknown') {
    // Simple version comparison for now
    // A more sophisticated approach would use semver or custom logic per technology
    return version !== definition.latestVersion;
  }
  
  // If the technology has version-specific support status
  if (definition.versions && version in definition.versions) {
    const versionInfo = definition.versions[version];
    return versionInfo.supportStatus !== 'active';
  }
  
  return false;
}

/**
 * Calculate days until end-of-life for a technology version
 */
function calculateDaysUntilEndOfLife(
  definition: TechnologyDefinition,
  version: string
): number | null {
  // Skip if no version info or EOL date
  if (!definition.versions || 
      !definition.versions[version] || 
      !definition.versions[version].endOfLifeDate) {
    return null;
  }
  
  const eolDateString = definition.versions[version].endOfLifeDate;
  
  try {
    const eolDate = new Date(eolDateString!);
    const today = new Date();
    
    // Calculate difference in days
    const diffTime = eolDate.getTime() - today.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    return Math.max(0, diffDays); // Return 0 if already past EOL
  } catch (dateError) {
    log.warn(`Error calculating EOL days for ${definition.name} ${version}`, { error: dateError });
    return null;
  }
}

/**
 * Get support status for a technology version
 */
function getTechnologySupportStatus(
  definition: TechnologyDefinition,
  version: string
): 'active' | 'maintenance' | 'security-only' | 'end-of-life' | 'unknown' {
  // If version-specific status is available
  if (definition.versions && version in definition.versions) {
    return definition.versions[version].supportStatus;
  }
  
  // Default status based on whether it's deprecated
  return definition.isDeprecated ? 'end-of-life' : 'unknown';
}

/**
 * Get known issues for a technology version
 */
function getKnownIssues(
  definition: TechnologyDefinition,
  version: string
): string[] | undefined {
  // If version-specific issues are available
  if (definition.versions && version in definition.versions) {
    return definition.versions[version].knownIssues;
  }
  
  return undefined;
}

/**
 * Calculate risk level for a technology issue
 */
function calculateRiskLevel(
  definition: TechnologyDefinition,
  version: string,
  isOutdated: boolean
): 'low' | 'medium' | 'high' | 'critical' {
  // Start with a base risk level
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  // If the technology is deprecated, it's at least medium risk
  if (definition.isDeprecated) {
    riskLevel = 'medium';
  }
  
  // Check support status if version info is available
  if (definition.versions && version in definition.versions) {
    const versionInfo = definition.versions[version];
    
    switch (versionInfo.supportStatus) {
      case 'end-of-life':
        riskLevel = 'high';
        break;
      case 'security-only':
        riskLevel = 'medium';
        break;
      case 'maintenance':
        if (riskLevel === 'low') riskLevel = 'low';
        break;
      case 'active':
        // Active support keeps risk low unless other factors increase it
        break;
    }
    
    // Check if past end-of-life
    if (versionInfo.endOfLifeDate) {
      const eolDate = new Date(versionInfo.endOfLifeDate);
      const today = new Date();
      
      if (today > eolDate) {
        // Past EOL is high risk
        riskLevel = 'high';
        
        // More than a year past EOL is critical
        const yearInMs = 365 * 24 * 60 * 60 * 1000;
        if (today.getTime() - eolDate.getTime() > yearInMs) {
          riskLevel = 'critical';
        }
      } else {
        // Approaching EOL
        const threeMonthsInMs = 90 * 24 * 60 * 60 * 1000;
        if (eolDate.getTime() - today.getTime() < threeMonthsInMs) {
          // Within 3 months of EOL increases risk
          if (riskLevel === 'low') riskLevel = 'medium';
          else if (riskLevel === 'medium') riskLevel = 'high';
        }
      }
    }
    
    // Known issues increase risk
    if (versionInfo.knownIssues && versionInfo.knownIssues.length > 0) {
      // Having any known issues increases risk
      if (riskLevel === 'low') riskLevel = 'medium';
      else if (riskLevel === 'medium') riskLevel = 'high';
      
      // Many known issues may indicate critical risk
      if (versionInfo.knownIssues.length > 3) {
        riskLevel = 'high';
      }
    }
  }
  
  // Being significantly outdated increases risk
  if (isOutdated && definition.latestVersion && version !== 'unknown') {
    const versionParts = version.split('.');
    const latestParts = definition.latestVersion.split('.');
    
    // Check major version difference (simple heuristic)
    if (versionParts[0] !== latestParts[0]) {
      if (riskLevel === 'medium') riskLevel = 'high';
      else if (riskLevel === 'low') riskLevel = 'medium';
      
      // Multiple major versions behind is more serious
      const majorDiff = parseInt(latestParts[0]) - parseInt(versionParts[0]);
      if (majorDiff >= 2) {
        riskLevel = 'high';
      }
    }
  }
  
  return riskLevel;
}

/**
 * Generate tags for a technology issue
 */
function generateTags(
  definition: TechnologyDefinition,
  version: string,
  isOutdated: boolean
): string[] {
  const tags = [definition.category];
  
  // Add tech-specific tag
  tags.push(definition.name.toLowerCase().replace(/\s+/g, '-'));
  
  // Version-related tags
  if (version !== 'unknown') {
    tags.push(`version-${version}`);
  }
  
  // Status tags
  if (definition.isDeprecated) {
    tags.push('deprecated');
  }
  
  if (isOutdated) {
    tags.push('outdated');
    
    // Check if it's a major, minor, or patch version difference
    if (definition.latestVersion && version !== 'unknown') {
      const versionParts = version.split('.');
      const latestParts = definition.latestVersion.split('.');
      
      if (versionParts[0] !== latestParts[0]) {
        tags.push('major-update-needed');
      } else if (versionParts[1] !== latestParts[1]) {
        tags.push('minor-update-needed');
      } else {
        tags.push('patch-update-needed');
      }
    }
  }
  
  // Support status tag
  const supportStatus = getTechnologySupportStatus(definition, version);
  tags.push(`support-${supportStatus}`);
  
  // EOL tag if applicable
  if (definition.versions?.[version]?.endOfLifeDate) {
    const eolDate = new Date(definition.versions[version].endOfLifeDate!); 
    const today = new Date();
    
    if (today > eolDate) {
      tags.push('past-eol');
    } else {
      // Calculate months until EOL
      const monthsUntilEol = Math.floor(
        (eolDate.getTime() - today.getTime()) / (30 * 24 * 60 * 60 * 1000)
      );
      
      if (monthsUntilEol <= 3) {
        tags.push('eol-imminent');
      } else if (monthsUntilEol <= 12) {
        tags.push('eol-approaching');
      }
    }
  }
  
  return tags;
}

/**
 * Generate recommendation for a technology issue
 */
function generateRecommendation(
  definition: TechnologyDefinition,
  version: string,
  isOutdated: boolean
): string {
  const recommendations: string[] = [];
  
  // Handle deprecated technology
  if (definition.isDeprecated) {
    recommendations.push(
      `${definition.name} is deprecated and should be replaced with an alternative technology.`
    );
    
    if (definition.alternatives && definition.alternatives.length > 0) {
      recommendations.push(
        `Consider using one of these alternatives: ${definition.alternatives.join(', ')}.`
      );
    }
  }
  // Handle outdated but not deprecated technology
  else if (isOutdated && definition.latestVersion) {
    recommendations.push(
      `Update ${definition.name} from version ${version} to the latest version ${definition.latestVersion}.`
    );
    
    // Add version-specific concerns
    if (definition.versions && version in definition.versions) {
      const versionInfo = definition.versions[version];
      
      if (versionInfo.supportStatus === 'end-of-life') {
        recommendations.push(
          `Version ${version} has reached end-of-life and is no longer supported.`
        );
      } else if (versionInfo.supportStatus === 'security-only') {
        recommendations.push(
          `Version ${version} is in security-only maintenance mode and receives only critical security patches.`
        );
      } else if (versionInfo.supportStatus === 'maintenance') {
        recommendations.push(
          `Version ${version} is in maintenance mode and will not receive new features.`
        );
      }
      
      // Add EOL warning
      if (versionInfo.endOfLifeDate) {
        const eolDate = new Date(versionInfo.endOfLifeDate);
        const today = new Date();
        
        if (today > eolDate) {
          recommendations.push(
            `This version reached end-of-life on ${eolDate.toLocaleDateString()}. Upgrade immediately.`
          );
        } else {
          recommendations.push(
            `This version will reach end-of-life on ${eolDate.toLocaleDateString()}. Plan your upgrade accordingly.`
          );
        }
      }
      
      // Add known issues
      if (versionInfo.knownIssues && versionInfo.knownIssues.length > 0) {
        recommendations.push(
          `This version has ${versionInfo.knownIssues.length} known issues:`
        );
        
        versionInfo.knownIssues.forEach(issue => {
          recommendations.push(`- ${issue}`);
        });
      }
    }
  }
  
  // Add general information
  if (definition.vendorUrl) {
    recommendations.push(`Vendor information: ${definition.vendorUrl}`);
  }
  
  if (definition.documentationUrl) {
    recommendations.push(`Documentation: ${definition.documentationUrl}`);
  }
  
  // If no specific recommendations were made, add a default message
  if (recommendations.length === 0) {
    recommendations.push(
      `No immediate action required for ${definition.name} ${version}.`
    );
  }
  
  return recommendations.join('\n');
}

/**
 * Assess the impact of updating or replacing a technology
 */
function assessUpdateImpact(
  definition: TechnologyDefinition,
  version: string
): {
  breakingChanges: boolean;
  affectedComponents?: string[];
  estimatedEffort: 'low' | 'medium' | 'high';
  estimatedTimeInDays?: number;
} {
  // Default impact assessment
  const impact = {
    breakingChanges: false,
    estimatedEffort: 'low' as 'low' | 'medium' | 'high'
  };
  
  // Defaulting to medium for most migrations
  if (definition.isDeprecated) {
    impact.breakingChanges = true;
    impact.estimatedEffort = 'high';
    impact.estimatedTimeInDays = estimateTimeInDays(definition, 'high');
  } else if (definition.latestVersion && version !== 'unknown') {
    // Determine if breaking changes are likely
    const versionParts = version.split('.');
    const latestParts = definition.latestVersion.split('.');
    
    // Major version bump typically means breaking changes
    if (versionParts[0] !== latestParts[0]) {
      impact.breakingChanges = true;
      impact.estimatedEffort = 'medium';
      impact.estimatedTimeInDays = estimateTimeInDays(definition, 'medium');
      
      // Multiple major versions behind is harder to migrate
      const majorDiff = parseInt(latestParts[0]) - parseInt(versionParts[0]);
      if (majorDiff >= 2) {
        impact.estimatedEffort = 'high';
        impact.estimatedTimeInDays = estimateTimeInDays(definition, 'high');
      }
    } 
    // Multiple minor version jumps may require moderate effort
    else if (versionParts[1] !== latestParts[1]) {
      const minorVersionDiff = parseInt(latestParts[1]) - parseInt(versionParts[1]);
      
      if (minorVersionDiff > 2) {
        impact.estimatedEffort = 'medium';
        impact.estimatedTimeInDays = estimateTimeInDays(definition, 'medium');
      } else {
        impact.estimatedTimeInDays = estimateTimeInDays(definition, 'low');
      }
    } else {
      impact.estimatedTimeInDays = estimateTimeInDays(definition, 'low');
    }
  }
  
  // Use the migration effort from definition if available
  if (definition.migrationEffort !== undefined) {
    if (definition.migrationEffort >= 7) {
      impact.estimatedEffort = 'high';
      impact.estimatedTimeInDays = estimateTimeInDays(definition, 'high');
    } else if (definition.migrationEffort >= 4) {
      impact.estimatedEffort = 'medium';
      impact.estimatedTimeInDays = estimateTimeInDays(definition, 'medium');
    } else {
      impact.estimatedEffort = 'low';
      impact.estimatedTimeInDays = estimateTimeInDays(definition, 'low');
    }
  }
  
  return impact;
}

/**
 * Estimate time to update in days based on effort level
 */
function estimateTimeInDays(
  definition: TechnologyDefinition,
  effortLevel: 'low' | 'medium' | 'high'
): number {
  // Base ranges for different effort levels
  const timeRanges = {
    low: { min: 1, max: 3 },
    medium: { min: 5, max: 15 },
    high: { min: 20, max: 60 }
  };
  
  // Get the appropriate range
  const range = timeRanges[effortLevel];
  
  // Adjust based on specific technology if we have migration effort data
  if (definition.migrationEffort !== undefined) {
    const factor = definition.migrationEffort / 5; // Normalize to a 0-2 scale (0.2 to 2.0)
    return Math.round((range.min + (range.max - range.min) / 2) * factor);
  }
  
  // Otherwise return the middle of the range
  return Math.round(range.min + (range.max - range.min) / 2);
}

/**
 * Get built-in technology definitions
 */
function getBuiltInTechnologyDefinitions(): Record<string, TechnologyDefinition> {
  // This would typically load from a built-in database
  // Here we're defining a few common technologies as examples
  return {
    'react16': {
      name: 'React',
      category: 'framework',
      filePatterns: ['**/package.json', '**/*.jsx', '**/*.tsx'],
      detectionPatterns: ['react@16\\.', 'import React from', 'require\\(["\']react["\']\\)'],
      versionExtractionPattern: 'react@(\\d+\\.\\d+\\.\\d+)',
      isDeprecated: false,
      latestVersion: '18.2.0',
      vendorUrl: 'https://reactjs.org/',
      documentationUrl: 'https://reactjs.org/docs/getting-started.html',
      versions: {
        '16.0.0': {
          releaseDate: '2017-09-26',
          endOfLifeDate: '2022-03-29',
          supportStatus: 'end-of-life',
          knownIssues: [
            'Potential memory leaks in concurrent mode',
            'Performance degradation with large component trees'
          ]
        },
        '16.8.0': {
          releaseDate: '2019-02-06',
          endOfLifeDate: '2022-03-29',
          supportStatus: 'end-of-life',
          knownIssues: ['React Hooks performance issues in certain edge cases']
        },
        '16.14.0': {
          releaseDate: '2020-10-14',
          endOfLifeDate: '2023-06-01',
          supportStatus: 'security-only',
          knownIssues: []
        }
      },
      alternatives: ['Preact', 'Vue.js', 'Svelte'],
      migrationEffort: 5
    },
    'jquery': {
      name: 'jQuery',
      category: 'library',
      filePatterns: ['**/*.js', '**/package.json', '**/*.html'],
      detectionPatterns: ['jquery@\\d+', 'import \\$ from ["\']jquery["\']', '<script.*jquery.*\\.js', '\\$\\(function'],
      versionExtractionPattern: 'jquery@(\\d+\\.\\d+\\.\\d+)',
      defaultVersion: '3.0.0',
      isDeprecated: false,
      latestVersion: '3.7.1',
      vendorUrl: 'https://jquery.com/',
      documentationUrl: 'https://api.jquery.com/',
      versions: {
        '1.12.4': {
          releaseDate: '2016-05-20',
          endOfLifeDate: '2016-12-31',
          supportStatus: 'end-of-life',
          knownIssues: [
            'Security vulnerabilities in older versions',
            'Performance issues compared to modern DOM APIs',
            'Lack of modern JavaScript features'
          ]
        },
        '2.2.4': {
          releaseDate: '2016-05-20',
          endOfLifeDate: '2018-12-31',
          supportStatus: 'end-of-life',
          knownIssues: [
            'Performance issues compared to modern DOM APIs',
            'Lack of modern JavaScript features'
          ]
        },
        '3.5.1': {
          releaseDate: '2020-05-04',
          supportStatus: 'maintenance',
          knownIssues: [
            'Redundant when using modern frameworks'
          ]
        }
      },
      alternatives: ['Vanilla JavaScript', 'React', 'Vue.js'],
      migrationEffort: 7
    },
    'python27': {
      name: 'Python 2.7',
      category: 'language',
      filePatterns: ['**/*.py', '**/requirements.txt', '**/Pipfile', '**/setup.py'],
      detectionPatterns: ['#!/usr/bin/env python2', 'from __future__ import', 'print "'],
      defaultVersion: '2.7.18',
      isDeprecated: true,
      latestVersion: '3.11.5',
      vendorUrl: 'https://www.python.org/',
      documentationUrl: 'https://docs.python.org/',
      versions: {
        '2.7.18': {
          releaseDate: '2020-04-20',
          endOfLifeDate: '2020-01-01',
          supportStatus: 'end-of-life',
          knownIssues: [
            'No security updates since January 2020',
            'Most libraries have dropped Python 2 support',
            'Poor Unicode handling compared to Python 3',
            'Missing modern language features'
          ]
        }
      },
      alternatives: ['Python 3.11', 'Python 3.10'],
      migrationEffort: 8
    },
    'angular1': {
      name: 'AngularJS',
      category: 'framework',
      filePatterns: ['**/*.js', '**/package.json', '**/*.html'],
      detectionPatterns: ['angular@1\\.', 'angular\\.module\\(', 'ng-app', 'ng-controller'],
      versionExtractionPattern: 'angular@(1\\.\\d+\\.\\d+)',
      defaultVersion: '1.8.2',
      isDeprecated: true,
      latestVersion: '1.8.2',
      vendorUrl: 'https://angularjs.org/',
      documentationUrl: 'https://docs.angularjs.org/',
      versions: {
        '1.8.2': {
          releaseDate: '2021-03-05',
          endOfLifeDate: '2022-01-01',
          supportStatus: 'end-of-life',
          knownIssues: [
            'No security updates since January 2022',
            'Performance issues with large applications',
            'Limited support for modern web features'
          ]
        }
      },
      alternatives: ['Angular 16', 'React', 'Vue.js'],
      migrationEffort: 9
    },
    'bootstrap3': {
      name: 'Bootstrap 3',
      category: 'framework',
      filePatterns: ['**/*.html', '**/*.css', '**/package.json', '**/*.scss'],
      detectionPatterns: ['bootstrap@3', '\\.col-md-', 'navbar-default'],
      versionExtractionPattern: 'bootstrap@(3\\.\\d+\\.\\d+)',
      defaultVersion: '3.4.1',
      isDeprecated: false,
      latestVersion: '5.3.1',
      vendorUrl: 'https://getbootstrap.com/',
      documentationUrl: 'https://getbootstrap.com/docs/3.4/',
      versions: {
        '3.4.1': {
          releaseDate: '2019-02-13',
          supportStatus: 'maintenance',
          knownIssues: [
            'Limited Flexbox support compared to newer versions',
            'Less modern design aesthetics',
            'Requires jQuery dependency'
          ]
        }
      },
      alternatives: ['Bootstrap 5', 'Tailwind CSS', 'Bulma'],
      migrationEffort: 6
    },
    'nodejs12': {
      name: 'Node.js 12',
      category: 'runtime',
      filePatterns: ['**/package.json', '**/.nvmrc', '**/.node-version'],
      detectionPatterns: ['node@12', '"node": "12', '\\.nvmrc.*12'],
      versionExtractionPattern: 'node@(12\\.\\d+\\.\\d+)',
      defaultVersion: '12.22.12',
      isDeprecated: true,
      latestVersion: '20.5.1',
      vendorUrl: 'https://nodejs.org/',
      documentationUrl: 'https://nodejs.org/docs/latest-v12.x/api/',
      versions: {
        '12.22.12': {
          releaseDate: '2022-04-05',
          endOfLifeDate: '2022-04-30',
          supportStatus: 'end-of-life',
          knownIssues: [
            'Security vulnerabilities no longer patched',
            'Performance improvements in newer versions',
            'Missing modern JavaScript features support'
          ]
        }
      },
      alternatives: ['Node.js 20', 'Node.js 18'],
      migrationEffort: 4
    }
  };
}