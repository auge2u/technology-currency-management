import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { TechnologyIssue } from '../types/scanning';
import { compareVersions, formatDate } from '../utils/scanner-utils';

const readFileAsync = promisify(fs.readFile);

/**
 * Configuration for technology scanning
 */
export interface TechnologyScannerConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Whether to use offline mode (don't make API calls)
  offlineMode: boolean;
  
  // Skip specific technologies
  ignoreTechnologies?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
  
  // Custom technology patterns to detect
  customPatterns?: Record<string, string[]>;
  
  // Months threshold to flag upcoming EOL
  upcomingEolMonths?: number;
}

/**
 * Technology definition with version patterns
 */
interface TechnologyPattern {
  name: string;
  type: 'framework' | 'language' | 'library' | 'database' | 'platform' | 'runtime' | 'tool';
  patterns: Array<{
    filePattern: string;
    versionPattern?: RegExp;
    dependencyPattern?: string;
    versionExtractor?: (content: string) => string | null;
  }>;
}

/**
 * Detected technology
 */
interface DetectedTechnology {
  name: string;
  type: string;
  version?: string;
  detectedAt: string;
  location: string;
}

/**
 * EOL (End of Life) information
 */
interface EolInfo {
  currentVersion: string;
  latestVersion: string;
  isEol: boolean;
  eolDate?: Date;
  isDeprecated: boolean;
  isOutdated: boolean;
  supportedVersions?: string[];
  releaseDate?: Date;
  endOfSupportDate?: Date;
  endOfExtendedSupportDate?: Date;
  migrationPath?: string;
  migrationEffort?: number;
  recommendedVersion?: string;
}

/**
 * Technology version with lifecycle information
 */
interface TechnologyVersion {
  version: string;
  releaseDate?: Date;
  endOfSupportDate?: Date;
  endOfExtendedSupportDate?: Date;
  isEol: boolean;
  isLts?: boolean;
  isLatest?: boolean;
}

/**
 * Scanner for detecting frameworks, languages, and technologies
 */
export async function scanTechnologies(
  config: TechnologyScannerConfig
): Promise<TechnologyIssue[]> {
  try {
    log.info('Starting technology scanner');
    const issues: TechnologyIssue[] = [];
    
    // Detect technologies
    const technologies = await detectTechnologies(config);
    log.info(`Found ${technologies.length} technologies`);
    
    // Check each technology
    for (const technology of technologies) {
      try {
        // Skip ignored technologies
        if (config.ignoreTechnologies && config.ignoreTechnologies.includes(technology.name)) {
          log.info(`Skipping ignored technology: ${technology.name}`);
          continue;
        }
        
        // Get EOL information
        const eolInfo = await getEolInfo(
          technology.name,
          technology.type,
          technology.version,
          config.offlineMode,
          config.cacheDir
        );
        
        // Only create an issue if there's at least one problem
        if (eolInfo.isEol || eolInfo.isDeprecated || eolInfo.isOutdated || 
            (eolInfo.eolDate && isUpcomingEol(eolInfo.eolDate, config.upcomingEolMonths || 6))) {
          
          // Create the issue
          const issue: TechnologyIssue = {
            name: technology.name,
            type: technology.type,
            currentVersion: technology.version || eolInfo.currentVersion,
            latestVersion: eolInfo.latestVersion,
            location: technology.location,
            detectedAt: new Date(),
            isEol: eolInfo.isEol,
            isDeprecated: eolInfo.isDeprecated,
            isOutdated: eolInfo.isOutdated,
            eolDate: eolInfo.eolDate,
            endOfSupportDate: eolInfo.endOfSupportDate,
            endOfExtendedSupportDate: eolInfo.endOfExtendedSupportDate,
            supportedVersions: eolInfo.supportedVersions,
            releaseDate: eolInfo.releaseDate
          };
          
          // Calculate business impact
          issue.businessImpact = calculateBusinessImpact(
            technology,
            eolInfo
          );
          
          // Calculate migration effort
          if (eolInfo.migrationEffort !== undefined) {
            issue.migrationEffort = eolInfo.migrationEffort;
          } else {
            issue.migrationEffort = calculateMigrationEffort(
              technology,
              eolInfo
            );
          }
          
          // Generate recommendation
          issue.recommendation = generateRecommendation(
            technology,
            eolInfo
          );
          
          // Generate tags
          issue.tags = generateTags(
            technology,
            eolInfo
          );
          
          // Add to issues list
          issues.push(issue);
          log.info(`Added issue for technology ${technology.name} ${technology.version || 'unknown version'}`);
        }
      } catch (techError) {
        log.warn(`Error processing technology: ${technology.name}`, { error: techError });
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
 * Detect technologies used in the project
 */
async function detectTechnologies(
  config: TechnologyScannerConfig
): Promise<DetectedTechnology[]> {
  try {
    const technologies: DetectedTechnology[] = [];
    const rootDir = config.rootDirectory;
    
    // Define technology patterns
    const patterns = getTechnologyPatterns();
    
    // Add custom patterns if provided
    if (config.customPatterns) {
      for (const [name, filePatterns] of Object.entries(config.customPatterns)) {
        // Add as custom technology type
        patterns.push({
          name,
          type: 'framework',
          patterns: filePatterns.map(pattern => ({ filePattern: pattern }))
        });
      }
    }
    
    // Detect each technology
    for (const technology of patterns) {
      try {
        for (const pattern of technology.patterns) {
          try {
            const matches = await glob(path.join(rootDir, pattern.filePattern), {
              ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**']
            });
            
            for (const match of matches) {
              try {
                let version: string | undefined;
                
                // Try to extract version if a version pattern is provided
                if (pattern.versionPattern || pattern.versionExtractor) {
                  try {
                    const content = await readFileAsync(match, 'utf8');
                    
                    if (pattern.versionExtractor) {
                      const extractedVersion = pattern.versionExtractor(content);
                      if (extractedVersion) {
                        version = extractedVersion;
                      }
                    } else if (pattern.versionPattern) {
                      const versionMatch = content.match(pattern.versionPattern);
                      if (versionMatch && versionMatch[1]) {
                        version = versionMatch[1];
                      }
                    }
                  } catch (readError) {
                    // Skip version extraction if file can't be read
                  }
                }
                
                // Only add if not already detected
                const existingTech = technologies.find(t => 
                  t.name === technology.name && t.version === version
                );
                
                if (!existingTech) {
                  technologies.push({
                    name: technology.name,
                    type: technology.type,
                    version,
                    detectedAt: match,
                    location: match
                  });
                  
                  log.info(
                    `Detected ${technology.name} ${version || 'unknown version'} at ${match}`
                  );
                }
              } catch (matchError) {
                log.warn(`Error processing match: ${match}`, { error: matchError });
              }
            }
          } catch (patternError) {
            log.warn(`Error processing pattern: ${pattern.filePattern}`, { error: patternError });
          }
        }
      } catch (techError) {
        log.warn(`Error processing technology: ${technology.name}`, { error: techError });
      }
    }
    
    return technologies;
  } catch (error) {
    log.error('Error detecting technologies', { error });
    return [];
  }
}

/**
 * Get end-of-life information for a technology
 */
async function getEolInfo(
  name: string,
  type: string,
  version?: string,
  offlineMode: boolean,
  cacheDir?: string
): Promise<EolInfo> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(cacheDir, `tech-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as EolInfo;
        log.info(`Loaded ${name} EOL info from cache`);
        return cachedInfo;
      } catch (cacheError) {
        log.warn(`Error reading technology cache for ${name}`, { error: cacheError });
      }
    }
  }
  
  // If in offline mode and no cache, return placeholder data
  if (offlineMode) {
    log.info(`Offline mode enabled for ${name}, using placeholder data`);
    return {
      currentVersion: version || '0.0.0',
      latestVersion: version || '0.0.0', // Assume current version is latest
      isEol: false,
      isDeprecated: false,
      isOutdated: false
    };
  }
  
  // In a real implementation, we would query a technology database or API
  // For this example, we'll use mock data
  try {
    log.info(`Querying EOL info for ${type} ${name} ${version || 'unknown version'}`);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 200));
    
    // Define technology versions with lifecycle information
    const techVersions = getTechnologyVersions(name);
    
    // Find current version or use the provided one
    const currentVersionObj = version 
      ? techVersions.find(v => v.version === version) 
      : techVersions[Math.floor(Math.random() * techVersions.length)];
    
    const currentVersion = currentVersionObj?.version || version || '0.0.0';
    
    // Find latest version
    const latestVersion = techVersions
      .filter(v => v.isLatest)
      .map(v => v.version)
      .sort((a, b) => compareVersions(b, a))[0] || currentVersion;
    
    // Calculate if it's EOL
    const isEol = currentVersionObj?.isEol || false;
    
    // Generate random dates if not set
    const releaseDate = currentVersionObj?.releaseDate || 
      new Date(Date.now() - Math.random() * 5 * 365 * 24 * 60 * 60 * 1000);
    
    const endOfSupportDate = currentVersionObj?.endOfSupportDate || 
      new Date(releaseDate.getTime() + Math.random() * 3 * 365 * 24 * 60 * 60 * 1000);
    
    const endOfExtendedSupportDate = currentVersionObj?.endOfExtendedSupportDate || 
      new Date(endOfSupportDate.getTime() + Math.random() * 2 * 365 * 24 * 60 * 60 * 1000);
    
    // Generate the EOL info
    const info: EolInfo = {
      currentVersion,
      latestVersion,
      isEol,
      eolDate: isEol ? endOfSupportDate : undefined,
      isDeprecated: Math.random() < 0.2, // 20% chance of being deprecated
      isOutdated: compareVersions(currentVersion, latestVersion) < 0,
      supportedVersions: techVersions
        .filter(v => !v.isEol)
        .map(v => v.version),
      releaseDate,
      endOfSupportDate,
      endOfExtendedSupportDate,
      recommendedVersion: latestVersion
    };
    
    // Calculate migration effort based on version difference
    const versionDiff = compareVersions(latestVersion, currentVersion);
    info.migrationEffort = Math.min(5, Math.max(1, Math.ceil(versionDiff / 2)));
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(cacheDir, `tech-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
        await fs.promises.writeFile(cacheFile, JSON.stringify(info, null, 2), 'utf8');
        log.info(`Cached ${name} EOL info`);
      } catch (cacheError) {
        log.warn(`Error writing technology cache for ${name}`, { error: cacheError });
      }
    }
    
    return info;
  } catch (error) {
    log.error(`Error querying EOL info for ${name}`, { error });
    
    // Return basic info if query fails
    return {
      currentVersion: version || '0.0.0',
      latestVersion: version || '0.0.0',
      isEol: false,
      isDeprecated: false,
      isOutdated: false
    };
  }
}

/**
 * Check if EOL date is approaching within the specified number of months
 */
function isUpcomingEol(eolDate: Date, months: number): boolean {
  const now = new Date();
  const monthsAway = (eolDate.getTime() - now.getTime()) / (30 * 24 * 60 * 60 * 1000);
  return monthsAway > 0 && monthsAway <= months;
}

/**
 * Calculate business impact score for a technology issue
 */
function calculateBusinessImpact(
  technology: DetectedTechnology,
  eolInfo: EolInfo
): number {
  let score = 1; // Start with minimal impact
  
  // EOL has high impact
  if (eolInfo.isEol) score += 2;
  
  // Deprecation has medium impact
  if (eolInfo.isDeprecated) score += 1;
  
  // Being outdated has lower impact
  if (eolInfo.isOutdated) score += 1;
  
  // If EOL date is close, increase impact
  if (eolInfo.eolDate) {
    const monthsToEol = (eolInfo.eolDate.getTime() - new Date().getTime()) / (30 * 24 * 60 * 60 * 1000);
    if (monthsToEol > 0 && monthsToEol <= 3) {
      score += 1;
    }
  }
  
  // Core technologies have higher impact
  const criticalTechnologies = ['java', 'dotnet', 'python', 'nodejs', 'react', 'angular', 'vue', 'spring', 'django'];
  if (criticalTechnologies.includes(technology.name.toLowerCase())) {
    score += 1;
  }
  
  // Cap at maximum of 5
  return Math.min(score, 5);
}

/**
 * Calculate migration effort for updating a technology
 */
function calculateMigrationEffort(
  technology: DetectedTechnology,
  eolInfo: EolInfo
): number {
  // Use provided migration effort if available
  if (eolInfo.migrationEffort !== undefined) {
    return eolInfo.migrationEffort;
  }
  
  // Start with default effort
  let effort = 3;
  
  // Calculate version difference
  if (technology.version && eolInfo.latestVersion) {
    const versionDiff = compareVersions(eolInfo.latestVersion, technology.version);
    
    // Major version upgrades are more difficult
    if (versionDiff >= 2) {
      effort += 1;
    } else if (versionDiff <= 0) {
      effort -= 1; // Same or newer version is easier
    }
  }
  
  // Technology type affects effort
  switch (technology.type) {
    case 'language':
    case 'platform':
      // Languages and platforms are harder to migrate
      effort += 1;
      break;
    case 'library':
      // Libraries are generally easier
      effort -= 1;
      break;
  }
  
  // Cap at 1-5 range
  return Math.max(1, Math.min(5, effort));
}

/**
 * Generate a recommendation for a technology issue
 */
function generateRecommendation(
  technology: DetectedTechnology,
  eolInfo: EolInfo
): string {
  const recommendations: string[] = [];
  
  if (eolInfo.isEol) {
    recommendations.push(
      `Migrate ${technology.name} ${technology.version || ''} to a supported version as it has reached end-of-life`
    );
    
    if (eolInfo.recommendedVersion) {
      recommendations.push(
        `Consider upgrading to ${technology.name} ${eolInfo.recommendedVersion}`
      );
    }
  } else if (eolInfo.isDeprecated) {
    recommendations.push(
      `Plan migration from deprecated ${technology.name} ${technology.version || ''} to a supported alternative`
    );
  } else if (eolInfo.isOutdated) {
    recommendations.push(
      `Update ${technology.name} from ${technology.version || eolInfo.currentVersion} to ${eolInfo.latestVersion}`
    );
  }
  
  if (eolInfo.eolDate) {
    const now = new Date();
    const monthsToEol = Math.round((eolInfo.eolDate.getTime() - now.getTime()) / (30 * 24 * 60 * 60 * 1000));
    
    if (monthsToEol > 0 && monthsToEol <= 12) {
      recommendations.push(
        `Prepare for ${technology.name} end-of-support in approximately ${monthsToEol} month${monthsToEol !== 1 ? 's' : ''} (${formatDate(eolInfo.eolDate)})`
      );
    }
  }
  
  if (recommendations.length === 0) {
    recommendations.push(`No immediate action required for ${technology.name} ${technology.version || ''}`);
  }
  
  return recommendations.join('. ');
}

/**
 * Generate tags for categorizing technology issues
 */
function generateTags(
  technology: DetectedTechnology,
  eolInfo: EolInfo
): string[] {
  const tags: string[] = [technology.type];
  
  if (eolInfo.isEol) tags.push('eol');
  if (eolInfo.isDeprecated) tags.push('deprecated');
  if (eolInfo.isOutdated) tags.push('outdated');
  
  // Add upcoming-eol tag if EOL is within 6 months
  if (eolInfo.eolDate) {
    const now = new Date();
    const monthsToEol = (eolInfo.eolDate.getTime() - now.getTime()) / (30 * 24 * 60 * 60 * 1000);
    if (monthsToEol > 0 && monthsToEol <= 6) {
      tags.push('upcoming-eol');
    }
  }
  
  return tags;
}

/**
 * Get predefined technology patterns for detection
 */
function getTechnologyPatterns(): TechnologyPattern[] {
  return [
    // JavaScript Frameworks
    {
      name: 'React',
      type: 'framework',
      patterns: [
        { filePattern: '**/package.json', dependencyPattern: 'react' },
        { filePattern: '**/*.jsx' },
        { filePattern: '**/*.tsx' },
        {
          filePattern: '**/package.json',
          versionExtractor: (content) => {
            try {
              const pkg = JSON.parse(content);
              return pkg.dependencies?.react || pkg.devDependencies?.react || null;
            } catch {
              return null;
            }
          }
        }
      ]
    },
    {
      name: 'Angular',
      type: 'framework',
      patterns: [
        { filePattern: '**/angular.json' },
        { filePattern: '**/package.json', dependencyPattern: '@angular/core' },
        {
          filePattern: '**/package.json',
          versionExtractor: (content) => {
            try {
              const pkg = JSON.parse(content);
              return pkg.dependencies?.['@angular/core'] || pkg.devDependencies?.['@angular/core'] || null;
            } catch {
              return null;
            }
          }
        }
      ]
    },
    {
      name: 'Vue',
      type: 'framework',
      patterns: [
        { filePattern: '**/package.json', dependencyPattern: 'vue' },
        { filePattern: '**/*.vue' },
        {
          filePattern: '**/package.json',
          versionExtractor: (content) => {
            try {
              const pkg = JSON.parse(content);
              return pkg.dependencies?.vue || pkg.devDependencies?.vue || null;
            } catch {
              return null;
            }
          }
        }
      ]
    },
    // Backend Frameworks
    {
      name: 'Express',
      type: 'framework',
      patterns: [
        { filePattern: '**/package.json', dependencyPattern: 'express' },
        {
          filePattern: '**/package.json',
          versionExtractor: (content) => {
            try {
              const pkg = JSON.parse(content);
              return pkg.dependencies?.express || pkg.devDependencies?.express || null;
            } catch {
              return null;
            }
          }
        }
      ]
    },
    {
      name: 'Django',
      type: 'framework',
      patterns: [
        { filePattern: '**/requirements.txt', versionPattern: /django([>=<~]*)([\d\.]+)/i },
        { filePattern: '**/settings.py' },
        { filePattern: '**/urls.py' },
      ]
    },
    {
      name: 'Spring Boot',
      type: 'framework',
      patterns: [
        { filePattern: '**/pom.xml', versionPattern: /<spring-boot.version>([\d\.]+)<\/spring-boot.version>/ },
        { filePattern: '**/build.gradle', versionPattern: /spring-boot:["']([\d\.]+)["']/ },
        { filePattern: '**/application.properties' },
        { filePattern: '**/application.yml' },
      ]
    },
    // Languages
    {
      name: 'Node.js',
      type: 'runtime',
      patterns: [
        { filePattern: '**/package.json' },
        { filePattern: '**/.nvmrc', versionPattern: /^v?([\d\.]+)$/ },
        { filePattern: '**/.node-version', versionPattern: /^v?([\d\.]+)$/ },
      ]
    },
    {
      name: 'Python',
      type: 'language',
      patterns: [
        { filePattern: '**/requirements.txt' },
        { filePattern: '**/*.py' },
        { filePattern: '**/Pipfile' },
        { filePattern: '**/.python-version', versionPattern: /^([\d\.]+)$/ },
        { filePattern: '**/runtime.txt', versionPattern: /python-([\d\.]+)/ },
      ]
    },
    {
      name: 'Java',
      type: 'language',
      patterns: [
        { filePattern: '**/pom.xml' },
        { filePattern: '**/build.gradle' },
        { filePattern: '**/*.java' },
        { 
          filePattern: '**/pom.xml', 
          versionPattern: /<java.version>([\d\.]+)<\/java.version>/ 
        },
        { 
          filePattern: '**/build.gradle', 
          versionPattern: /sourceCompatibility\s*=\s*['"]?([\d\.]+)['"]?/ 
        },
      ]
    },
    {
      name: 'PHP',
      type: 'language',
      patterns: [
        { filePattern: '**/composer.json' },
        { filePattern: '**/*.php' },
        { 
          filePattern: '**/composer.json', 
          versionExtractor: (content) => {
            try {
              const pkg = JSON.parse(content);
              return pkg.require?.php || null;
            } catch {
              return null;
            }
          }
        },
      ]
    },
    // Databases
    {
      name: 'MongoDB',
      type: 'database',
      patterns: [
        { filePattern: '**/package.json', dependencyPattern: 'mongoose' },
        { filePattern: '**/package.json', dependencyPattern: 'mongodb' },
        { filePattern: '**/docker-compose.yml', versionPattern: /image:\s*mongo:([\d\.]+)/ },
      ]
    },
    {
      name: 'PostgreSQL',
      type: 'database',
      patterns: [
        { filePattern: '**/package.json', dependencyPattern: 'pg' },
        { filePattern: '**/docker-compose.yml', versionPattern: /image:\s*postgres:([\d\.]+)/ },
        { filePattern: '**/requirements.txt', versionPattern: /psycopg2([>=<~]*)([\d\.]+)/ },
      ]
    },
    // Mobile Frameworks
    {
      name: 'React Native',
      type: 'framework',
      patterns: [
        { filePattern: '**/package.json', dependencyPattern: 'react-native' },
        {
          filePattern: '**/package.json',
          versionExtractor: (content) => {
            try {
              const pkg = JSON.parse(content);
              return pkg.dependencies?.['react-native'] || pkg.devDependencies?.['react-native'] || null;
            } catch {
              return null;
            }
          }
        }
      ]
    },
    {
      name: 'Flutter',
      type: 'framework',
      patterns: [
        { filePattern: '**/pubspec.yaml', versionPattern: /sdk:\s*flutter/ },
        { filePattern: '**/*.dart' },
      ]
    },
    // DevOps
    {
      name: 'Docker',
      type: 'tool',
      patterns: [
        { filePattern: '**/Dockerfile' },
        { filePattern: '**/docker-compose.yml' },
      ]
    },
    {
      name: 'Kubernetes',
      type: 'platform',
      patterns: [
        { filePattern: '**/*.yaml', versionPattern: /apiVersion:\s*([\w\/]+)/ },
        { filePattern: '**/*.yml', versionPattern: /apiVersion:\s*([\w\/]+)/ },
      ]
    },
    // .NET
    {
      name: '.NET',
      type: 'platform',
      patterns: [
        { filePattern: '**/*.csproj', versionPattern: /<TargetFramework>net([\d\.]+)<\/TargetFramework>/ },
        { filePattern: '**/*.cs' },
        { filePattern: '**/global.json', versionPattern: /"version":\s*"([\d\.]+)"/ },
      ]
    },
    // Other frameworks
    {
      name: 'Laravel',
      type: 'framework',
      patterns: [
        { filePattern: '**/composer.json', dependencyPattern: 'laravel/framework' },
        { filePattern: '**/artisan' },
        { 
          filePattern: '**/composer.json', 
          versionExtractor: (content) => {
            try {
              const pkg = JSON.parse(content);
              return pkg.require?.['laravel/framework'] || null;
            } catch {
              return null;
            }
          }
        },
      ]
    },
    {
      name: 'Ruby on Rails',
      type: 'framework',
      patterns: [
        { filePattern: '**/Gemfile', versionPattern: /gem\s+['"]rails['"]\s*,\s*['"]([\d\.]+)['"]/ },
        { filePattern: '**/config/application.rb' },
        { filePattern: '**/config/routes.rb' },
      ]
    },
    // Add more technologies as needed
  ];
}

/**
 * Get technology versions with lifecycle information
 */
function getTechnologyVersions(name: string): TechnologyVersion[] {
  // This would come from a database or API in a real implementation
  // Here we're using mock data for demonstration
  
  const now = new Date();
  const oneYear = 365 * 24 * 60 * 60 * 1000;
  
  switch (name.toLowerCase()) {
    case 'node.js':
      return [
        {
          version: '20.0.0',
          releaseDate: new Date(now.getTime() - 0.2 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 1.8 * oneYear),
          isEol: false,
          isLatest: true
        },
        {
          version: '18.0.0',
          releaseDate: new Date(now.getTime() - 1.5 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 0.5 * oneYear),
          isEol: false,
          isLts: true
        },
        {
          version: '16.0.0',
          releaseDate: new Date(now.getTime() - 2.5 * oneYear),
          endOfSupportDate: new Date(now.getTime() - 0.5 * oneYear),
          isEol: true
        },
        {
          version: '14.0.0',
          releaseDate: new Date(now.getTime() - 3.5 * oneYear),
          endOfSupportDate: new Date(now.getTime() - 1.5 * oneYear),
          isEol: true
        }
      ];
      
    case 'react':
      return [
        {
          version: '18.2.0',
          releaseDate: new Date(now.getTime() - 0.4 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 2 * oneYear),
          isEol: false,
          isLatest: true
        },
        {
          version: '18.0.0',
          releaseDate: new Date(now.getTime() - 0.9 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 1.5 * oneYear),
          isEol: false
        },
        {
          version: '17.0.2',
          releaseDate: new Date(now.getTime() - 2 * oneYear),
          endOfSupportDate: new Date(now.getTime() - 0.2 * oneYear),
          isEol: true
        },
        {
          version: '16.14.0',
          releaseDate: new Date(now.getTime() - 3 * oneYear),
          endOfSupportDate: new Date(now.getTime() - 1.2 * oneYear),
          isEol: true
        }
      ];
    
    case 'python':
      return [
        {
          version: '3.12.0',
          releaseDate: new Date(now.getTime() - 0.3 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 4.7 * oneYear),
          isEol: false,
          isLatest: true
        },
        {
          version: '3.11.0',
          releaseDate: new Date(now.getTime() - 1.3 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 3.7 * oneYear),
          isEol: false
        },
        {
          version: '3.10.0',
          releaseDate: new Date(now.getTime() - 2.3 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 2.7 * oneYear),
          isEol: false
        },
        {
          version: '3.9.0',
          releaseDate: new Date(now.getTime() - 3.3 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 1.7 * oneYear),
          isEol: false
        },
        {
          version: '3.8.0',
          releaseDate: new Date(now.getTime() - 4.3 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 0.7 * oneYear),
          isEol: false
        },
        {
          version: '3.7.0',
          releaseDate: new Date(now.getTime() - 5.3 * oneYear),
          endOfSupportDate: new Date(now.getTime() - 0.3 * oneYear),
          isEol: true
        },
        {
          version: '2.7.0',
          releaseDate: new Date(now.getTime() - 8 * oneYear),
          endOfSupportDate: new Date(now.getTime() - 3 * oneYear),
          isEol: true
        }
      ];
      
    // Add more technologies as needed
    
    default:
      // Generate random versions for other technologies
      return [
        {
          version: '2.0.0',
          releaseDate: new Date(now.getTime() - 0.3 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 2.7 * oneYear),
          isEol: false,
          isLatest: true
        },
        {
          version: '1.5.0',
          releaseDate: new Date(now.getTime() - 1.5 * oneYear),
          endOfSupportDate: new Date(now.getTime() + 1.5 * oneYear),
          isEol: false
        },
        {
          version: '1.0.0',
          releaseDate: new Date(now.getTime() - 3 * oneYear),
          endOfSupportDate: new Date(now.getTime() - 0.5 * oneYear),
          isEol: true
        },
        {
          version: '0.9.0',
          releaseDate: new Date(now.getTime() - 4 * oneYear),
          endOfSupportDate: new Date(now.getTime() - 1.5 * oneYear),
          isEol: true
        }
      ];
  }
}
