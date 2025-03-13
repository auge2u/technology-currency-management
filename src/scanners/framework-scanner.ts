import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import * as child_process from 'child_process';
import { FrameworkIssue, VulnerabilityInfo } from '../types/scanning';
import { log } from '../utils/logging';
import { compareVersions, daysBetween, estimateBusinessImpact, estimateMigrationDifficulty } from '../utils/scanner-utils';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(child_process.exec);

/**
 * Configuration for framework scanning
 */
export interface FrameworkScannerConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Which framework categories to check
  categories: Array<'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other'>;
  
  // Whether to use offline mode (don't make API calls)
  offlineMode: boolean;
  
  // Whether to check for security vulnerabilities
  checkVulnerabilities: boolean;
  
  // Skip frameworks with specific names
  ignoreFrameworks?: string[];
  
  // Skip frameworks matching specific patterns
  ignorePatterns?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
  
  // Whether this is a critical system
  isCriticalSystem?: boolean;
}

/**
 * Framework database record
 */
interface FrameworkRecord {
  name: string;
  type: string;
  category: 'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other';
  versions: FrameworkVersion[];
  detectionPatterns: {
    filePatterns: string[];
    contentPatterns: string[];
    packagePatterns: string[];
  };
  alternativeFrameworks?: {
    name: string;
    url: string;
    migrationGuideUrl?: string;
  }[];
}

/**
 * Framework version information
 */
interface FrameworkVersion {
  version: string;
  releaseDate: Date;
  endOfLifeDate?: Date;
  endOfSupportDate?: Date;
  isDeprecated: boolean;
  knownVulnerabilities: VulnerabilityInfo[];
  migrationNotes?: string;
}

/**
 * Detected framework
 */
interface DetectedFramework {
  name: string;
  type: string;
  category: 'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other';
  version?: string;
  location: string;
  detectionConfidence: 'low' | 'medium' | 'high';
  detectionMethod: 'file_pattern' | 'content_pattern' | 'package_pattern';
}

/**
 * Scanner for detecting outdated frameworks and libraries
 */
export async function scanFrameworks(
  config: FrameworkScannerConfig
): Promise<FrameworkIssue[]> {
  try {
    log.info('Starting framework scanner');
    const issues: FrameworkIssue[] = [];
    
    // Load framework database
    const frameworkDb = await getFrameworkDatabase(config.cacheDir, config.offlineMode);
    log.info(`Loaded framework database with ${frameworkDb.length} entries`);
    
    // Filter framework database by requested categories
    const filteredFrameworks = frameworkDb.filter(fw => config.categories.includes(fw.category));
    log.info(`Filtered to ${filteredFrameworks.length} frameworks in requested categories`);
    
    // Detect used frameworks
    const detectedFrameworks = await detectUsedFrameworks(config.rootDirectory, filteredFrameworks);
    log.info(`Detected ${detectedFrameworks.length} frameworks in use`);
    
    // Process each detected framework
    for (const detected of detectedFrameworks) {
      try {
        // Skip ignored frameworks
        if (config.ignoreFrameworks && config.ignoreFrameworks.includes(detected.name)) {
          log.info(`Skipping ignored framework: ${detected.name}`);
          continue;
        }
        
        // Skip frameworks matching ignore patterns
        if (config.ignorePatterns && 
            config.ignorePatterns.some(pattern => new RegExp(pattern).test(detected.name))) {
          log.info(`Skipping framework matching ignore pattern: ${detected.name}`);
          continue;
        }
        
        // Find framework record in database
        const frameworkRecord = frameworkDb.find(fw => fw.name === detected.name);
        
        // Skip if not found in database
        if (!frameworkRecord) {
          log.info(`Framework not found in database: ${detected.name}`);
          continue;
        }
        
        // Find version information
        if (!detected.version) {
          log.info(`No version detected for framework: ${detected.name}`);
          continue;
        }
        
        // Find version records - get exact match or the closest older version
        let versionRecord = frameworkRecord.versions.find(v => v.version === detected.version);
        
        if (!versionRecord) {
          // Sort versions and find the closest older version
          const olderVersions = frameworkRecord.versions
            .filter(v => compareVersions(v.version, detected.version) <= 0)
            .sort((a, b) => compareVersions(b.version, a.version)); // Sort in descending order
          
          if (olderVersions.length > 0) {
            versionRecord = olderVersions[0];
          } else {
            // If no older version found, use the oldest available version
            versionRecord = frameworkRecord.versions
              .sort((a, b) => compareVersions(a.version, b.version))[0];
          }
        }
        
        // Skip if no version record found (shouldn't happen if database is well-formed)
        if (!versionRecord) {
          log.warn(`No version record found for framework: ${detected.name} ${detected.version}`);
          continue;
        }
        
        // Get latest version
        const latestVersion = frameworkRecord.versions
          .sort((a, b) => compareVersions(b.version, a.version))[0];
        
        // Check if outdated
        const isOutdated = compareVersions(detected.version, latestVersion.version) < 0;
        
        // Check if deprecated
        const isDeprecated = versionRecord.isDeprecated;
        
        // Check if end of life/support has passed or is approaching
        const now = new Date();
        const isEol = versionRecord.endOfLifeDate && now >= versionRecord.endOfLifeDate;
        const isSupportEnding = versionRecord.endOfSupportDate && now >= versionRecord.endOfSupportDate;
        
        // Calculate days until end of life/support
        const daysUntilEol = versionRecord.endOfLifeDate ? 
          daysBetween(now, versionRecord.endOfLifeDate) : undefined;
        
        const daysUntilSupportEnds = versionRecord.endOfSupportDate ? 
          daysBetween(now, versionRecord.endOfSupportDate) : undefined;
        
        // Check for vulnerabilities
        const vulnerabilities = versionRecord.knownVulnerabilities;
        
        // Only create an issue if there's at least one problem
        if (isOutdated || isDeprecated || isEol || isSupportEnding || 
            (config.checkVulnerabilities && vulnerabilities.length > 0)) {
          
          // Create the issue
          const issue: FrameworkIssue = {
            name: detected.name,
            category: detected.category,
            type: detected.type,
            currentVersion: detected.version,
            latestVersion: latestVersion.version,
            isOutdated,
            isDeprecated,
            endOfLifeDate: versionRecord.endOfLifeDate,
            endOfSupportDate: versionRecord.endOfSupportDate,
            location: detected.location,
            detectedAt: new Date()
          };
          
          // Add vulnerability info if any exist
          if (vulnerabilities.length > 0) {
            issue.vulnerabilities = vulnerabilities;
            issue.securityImpact = Math.max(...vulnerabilities.map(v => 
              securityImpactFromSeverity(v.severity)));
          }
          
          // Calculate business impact
          issue.businessImpact = estimateBusinessImpact(
            isOutdated,
            isDeprecated,
            vulnerabilities.length > 0,
            config.isCriticalSystem || false
          );
          
          // Calculate migration effort
          issue.migrationEffort = estimateMigrationDifficulty(
            detected.version,
            latestVersion.version,
            detected.type
          );
          
          // Generate migration path
          issue.migrationPath = generateMigrationPath(
            detected.name,
            detected.version,
            latestVersion.version,
            frameworkRecord
          );
          
          // Generate recommendation
          issue.recommendation = generateRecommendation(
            detected.name,
            detected.version,
            latestVersion.version,
            isOutdated,
            isDeprecated,
            isEol,
            isSupportEnding,
            daysUntilEol,
            daysUntilSupportEnds,
            vulnerabilities.length > 0,
            frameworkRecord.alternativeFrameworks
          );
          
          // Add to issues list
          issues.push(issue);
          log.info(`Added issue for framework ${detected.name} ${detected.version}`);
        }
      } catch (frameworkError) {
        log.warn(`Error processing framework: ${detected.name}`, { error: frameworkError });
      }
    }
    
    log.info(`Completed framework scanning. Found ${issues.length} total issues`);
    return issues;
  } catch (error) {
    log.error('Error during framework scanning', { error });
    return [];
  }
}

/**
 * Get framework database (either from cache or create a new one)
 */
async function getFrameworkDatabase(
  cacheDir?: string,
  offlineMode: boolean = false
): Promise<FrameworkRecord[]> {
  // Check for cached database
  if (cacheDir && fs.existsSync(cacheDir)) {
    const dbPath = path.join(cacheDir, 'framework-database.json');
    
    if (fs.existsSync(dbPath)) {
      try {
        const dbContent = await readFileAsync(dbPath, 'utf8');
        const db = JSON.parse(dbContent, (key, value) => {
          // Convert date strings back to Date objects
          if (key === 'releaseDate' || key === 'endOfLifeDate' || key === 'endOfSupportDate') {
            return value ? new Date(value) : null;
          }
          return value;
        }) as FrameworkRecord[];
        
        log.info(`Loaded framework database from cache with ${db.length} entries`);
        return db;
      } catch (readError) {
        log.warn('Error reading framework database from cache', { error: readError });
      }
    }
  }
  
  // If we're in offline mode and couldn't load from cache, use a minimal database
  if (offlineMode) {
    log.info('Offline mode enabled and no cache found, using minimal framework database');
    return getMinimalFrameworkDb();
  }
  
  // Otherwise, create a complete database
  log.info('Creating new framework database');
  
  // In a real implementation, this would query a framework database API
  // For this example, we'll return a predefined set of frameworks
  const db = getMinimalFrameworkDb();
  
  // If we have a cache directory, save this database for future use
  if (cacheDir) {
    try {
      if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
      }
      
      const dbPath = path.join(cacheDir, 'framework-database.json');
      await fs.promises.writeFile(dbPath, JSON.stringify(db, null, 2), 'utf8');
      log.info(`Saved framework database to ${dbPath}`);
    } catch (saveError) {
      log.warn('Error saving framework database to cache', { error: saveError });
    }
  }
  
  return db;
}

/**
 * Creates a minimal framework database for offline use
 */
function getMinimalFrameworkDb(): FrameworkRecord[] {
  // This is a simplified database for example purposes
  // A real database would be much more comprehensive
  return [
    {
      name: 'React',
      type: 'js-framework',
      category: 'frontend',
      versions: [
        {
          version: '16.0.0',
          releaseDate: new Date('2017-09-26'),
          endOfSupportDate: new Date('2023-06-15'),
          isDeprecated: true,
          knownVulnerabilities: [
            {
              id: 'GHSA-42m2-109x-5gv5',
              severity: 'medium',
              title: 'Cross-Site Scripting in React',
              description: 'React vulnerable to XSS attacks when unfiltered user inputs are used',
              publishedDate: new Date('2022-03-11'),
              affectedVersions: '<16.13.1',
              patchedVersions: '>=16.13.1',
              recommendation: 'Upgrade to React 16.13.1 or newer'
            }
          ]
        },
        {
          version: '17.0.0',
          releaseDate: new Date('2020-10-20'),
          endOfSupportDate: new Date('2025-10-20'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '18.0.0',
          releaseDate: new Date('2022-03-29'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '18.2.0',
          releaseDate: new Date('2022-06-14'),
          isDeprecated: false,
          knownVulnerabilities: []
        }
      ],
      detectionPatterns: {
        filePatterns: ['package.json'],
        contentPatterns: ['import React', 'import * as React'],
        packagePatterns: ['"react":']            
      }
    },
    {
      name: 'Angular',
      type: 'js-framework',
      category: 'frontend',
      versions: [
        {
          version: '12.0.0',
          releaseDate: new Date('2021-05-12'),
          endOfSupportDate: new Date('2022-11-12'),
          isDeprecated: true,
          knownVulnerabilities: []
        },
        {
          version: '13.0.0',
          releaseDate: new Date('2021-11-03'),
          endOfSupportDate: new Date('2023-05-03'),
          isDeprecated: true,
          knownVulnerabilities: []
        },
        {
          version: '14.0.0',
          releaseDate: new Date('2022-06-02'),
          endOfSupportDate: new Date('2023-12-02'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '15.0.0',
          releaseDate: new Date('2022-11-16'),
          endOfSupportDate: new Date('2024-05-16'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '16.0.0',
          releaseDate: new Date('2023-05-03'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '17.0.0',
          releaseDate: new Date('2023-11-08'),
          isDeprecated: false,
          knownVulnerabilities: []
        }
      ],
      detectionPatterns: {
        filePatterns: ['angular.json'],
        contentPatterns: ['@Component', '@NgModule'],
        packagePatterns: ['"@angular/core":']
      }
    },
    {
      name: 'Vue.js',
      type: 'js-framework',
      category: 'frontend',
      versions: [
        {
          version: '2.6.0',
          releaseDate: new Date('2019-02-04'),
          endOfSupportDate: new Date('2023-12-31'),
          isDeprecated: true,
          knownVulnerabilities: []
        },
        {
          version: '2.7.0',
          releaseDate: new Date('2022-07-01'),
          endOfSupportDate: new Date('2024-12-31'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '3.0.0',
          releaseDate: new Date('2020-09-18'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '3.3.0',
          releaseDate: new Date('2023-05-18'),
          isDeprecated: false,
          knownVulnerabilities: []
        }
      ],
      detectionPatterns: {
        filePatterns: ['vue.config.js'],
        contentPatterns: ['new Vue(', 'createApp('],
        packagePatterns: ['"vue":'] 
      }
    },
    {
      name: 'Django',
      type: 'python-framework',
      category: 'backend',
      versions: [
        {
          version: '2.2',
          releaseDate: new Date('2019-04-01'),
          endOfLifeDate: new Date('2022-04-01'),
          isDeprecated: true,
          knownVulnerabilities: [
            {
              id: 'CVE-2021-3281',
              severity: 'high',
              title: 'Potential directory traversal via uploaded files',
              description: 'Django 2.2 before 2.2.18 has a potential directory traversal via FileField',
              publishedDate: new Date('2021-02-01'),
              affectedVersions: '>=2.2,<2.2.18',
              patchedVersions: '>=2.2.18',
              recommendation: 'Upgrade to Django 2.2.18 or higher'
            }
          ]
        },
        {
          version: '3.2',
          releaseDate: new Date('2021-04-06'),
          endOfLifeDate: new Date('2024-04-01'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '4.0',
          releaseDate: new Date('2021-12-07'),
          endOfLifeDate: new Date('2023-04-01'),
          isDeprecated: true,
          knownVulnerabilities: []
        },
        {
          version: '4.1',
          releaseDate: new Date('2022-08-03'),
          endOfLifeDate: new Date('2023-12-01'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '4.2',
          releaseDate: new Date('2023-04-05'),
          endOfLifeDate: new Date('2024-12-01'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '5.0',
          releaseDate: new Date('2023-12-04'),
          isDeprecated: false,
          knownVulnerabilities: []
        }
      ],
      detectionPatterns: {
        filePatterns: ['manage.py', 'settings.py'],
        contentPatterns: ['import django', 'from django'],
        packagePatterns: ['django==']
      }
    },
    {
      name: 'Express',
      type: 'node-framework',
      category: 'backend',
      versions: [
        {
          version: '4.17.1',
          releaseDate: new Date('2019-05-26'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '4.18.0',
          releaseDate: new Date('2022-04-24'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '5.0.0-alpha.8',
          releaseDate: new Date('2021-03-17'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '5.0.0-beta.1',
          releaseDate: new Date('2023-03-24'),
          isDeprecated: false,
          knownVulnerabilities: []
        }
      ],
      detectionPatterns: {
        filePatterns: [],
        contentPatterns: ['require(\'express\')', 'import express'],
        packagePatterns: ['"express":']
      }
    },
    {
      name: 'Spring Boot',
      type: 'java-framework',
      category: 'backend',
      versions: [
        {
          version: '2.5.0',
          releaseDate: new Date('2021-05-20'),
          endOfSupportDate: new Date('2022-05-19'),
          isDeprecated: true,
          knownVulnerabilities: [
            {
              id: 'CVE-2022-22965',
              severity: 'critical',
              title: 'Spring Framework RCE via Data Binding',
              description: 'Spring Framework RCE via Data Binding on JDK 9+',
              publishedDate: new Date('2022-03-31'),
              affectedVersions: '>=2.5.0,<2.5.12',
              patchedVersions: '>=2.5.12',
              recommendation: 'Upgrade to Spring Boot 2.5.12 or newer'
            }
          ]
        },
        {
          version: '2.6.0',
          releaseDate: new Date('2021-11-19'),
          endOfSupportDate: new Date('2022-11-24'),
          isDeprecated: true,
          knownVulnerabilities: []
        },
        {
          version: '2.7.0',
          releaseDate: new Date('2022-05-19'),
          endOfSupportDate: new Date('2023-05-18'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '3.0.0',
          releaseDate: new Date('2022-11-24'),
          isDeprecated: false,
          knownVulnerabilities: []
        },
        {
          version: '3.1.0',
          releaseDate: new Date('2023-05-18'),
          isDeprecated: false,
          knownVulnerabilities: []
        }
      ],
      detectionPatterns: {
        filePatterns: ['pom.xml', 'build.gradle'],
        contentPatterns: ['@SpringBootApplication', 'org.springframework.boot'],
        packagePatterns: ['spring-boot-starter']
      }
    }
  ];
}

/**
 * Detect used frameworks in the given directory
 */
async function detectUsedFrameworks(
  rootDirectory: string,
  frameworkDb: FrameworkRecord[]
): Promise<DetectedFramework[]> {
  try {
    const detectedFrameworks: DetectedFramework[] = [];
    
    // For each framework in the database, check if it's used
    for (const framework of frameworkDb) {
      try {
        log.info(`Checking for framework: ${framework.name}`);
        
        // Check for framework by file patterns
        for (const pattern of framework.detectionPatterns.filePatterns) {
          const matches = await glob(path.join(rootDirectory, '**', pattern), {
            ignore: ['**/node_modules/**', '**/vendor/**', '**/.git/**']
          });
          
          if (matches.length > 0) {
            log.info(`Detected framework ${framework.name} by file pattern ${pattern}`);
            
            // For each match, check content patterns to validate and get version
            for (const match of matches) {
              try {
                const content = await readFileAsync(match, 'utf8');
                let version: string | undefined;
                let detectionConfidence: 'low' | 'medium' | 'high' = 'medium';
                
                // Try to extract version from package.json, pom.xml, etc.
                if (path.basename(match) === 'package.json') {
                  try {
                    const packageJson = JSON.parse(content);
                    
                    // Check dependencies and devDependencies
                    if (packageJson.dependencies && packageJson.dependencies[framework.name.toLowerCase()]) {
                      version = packageJson.dependencies[framework.name.toLowerCase()].replace(/[^0-9.]/g, '');
                      detectionConfidence = 'high';
                    } else if (packageJson.devDependencies && packageJson.devDependencies[framework.name.toLowerCase()]) {
                      version = packageJson.devDependencies[framework.name.toLowerCase()].replace(/[^0-9.]/g, '');
                      detectionConfidence = 'high';
                    }
                    
                    // Special cases for frameworks with different package names
                    if (framework.name === 'React' && !version) {
                      if (packageJson.dependencies && packageJson.dependencies['react']) {
                        version = packageJson.dependencies['react'].replace(/[^0-9.]/g, '');
                        detectionConfidence = 'high';
                      }
                    } else if (framework.name === 'Angular' && !version) {
                      if (packageJson.dependencies && packageJson.dependencies['@angular/core']) {
                        version = packageJson.dependencies['@angular/core'].replace(/[^0-9.]/g, '');
                        detectionConfidence = 'high';
                      }
                    }
                  } catch (jsonError) {
                    log.warn(`Error parsing package.json: ${match}`, { error: jsonError });
                  }
                } else if (path.basename(match) === 'pom.xml') {
                  // Extract version from Maven POM
                  const versionMatch = content.match(new RegExp(`<artifactId>${framework.name.toLowerCase()}[^<]*</artifactId>[\s\S]*?<version>([^<]+)</version>`));
                  if (versionMatch) {
                    version = versionMatch[1];
                    detectionConfidence = 'high';
                  }
                } else if (path.basename(match) === 'build.gradle' || path.basename(match) === 'build.gradle.kts') {
                  // Extract version from Gradle build file
                  const versionMatch = content.match(new RegExp(`${framework.name.toLowerCase()}[^:\n]*:([^:\n\s'"]+)`));
                  if (versionMatch) {
                    version = versionMatch[1];
                    detectionConfidence = 'high';
                  }
                } else if (path.basename(match) === 'requirements.txt') {
                  // Extract version from Python requirements
                  const versionMatch = content.match(new RegExp(`${framework.name.toLowerCase()}==([\d.]+)`));
                  if (versionMatch) {
                    version = versionMatch[1];
                    detectionConfidence = 'high';
                  }
                }
                
                // If we found a match, add it to detected frameworks
                if (detectionConfidence === 'high' || framework.detectionPatterns.contentPatterns.some(p => content.includes(p))) {
                  // Don't add duplicates
                  if (!detectedFrameworks.some(df => df.name === framework.name)) {
                    detectedFrameworks.push({
                      name: framework.name,
                      type: framework.type,
                      category: framework.category,
                      version,
                      location: match,
                      detectionConfidence,
                      detectionMethod: 'file_pattern'
                    });
                  } else if (version) {
                    // If we already detected this framework but now have a version, update it
                    const existing = detectedFrameworks.find(df => df.name === framework.name);
                    if (existing && !existing.version) {
                      existing.version = version;
                      existing.location = match;
                      existing.detectionConfidence = detectionConfidence;
                    }
                  }
                }
              } catch (contentError) {
                log.warn(`Error reading file content: ${match}`, { error: contentError });
              }
            }
          }
        }
        
        // If we haven't detected the framework yet, try content patterns
        if (!detectedFrameworks.some(df => df.name === framework.name) && framework.detectionPatterns.contentPatterns.length > 0) {
          // This is a simplified version - in reality we would use a more efficient
          // approach like 'grep' or specialized tools to search for content patterns
          const filePatterns = ['**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx', '**/*.py', '**/*.java', '**/*.rb', '**/*.php'];
          
          for (const filePattern of filePatterns) {
            const matches = await glob(path.join(rootDirectory, filePattern), {
              ignore: ['**/node_modules/**', '**/vendor/**', '**/.git/**']
            });
            
            for (const match of matches) {
              try {
                const content = await readFileAsync(match, 'utf8');
                
                // Check if any content pattern matches
                if (framework.detectionPatterns.contentPatterns.some(p => content.includes(p))) {
                  log.info(`Detected framework ${framework.name} by content pattern in ${match}`);
                  
                  // Don't add duplicates
                  if (!detectedFrameworks.some(df => df.name === framework.name)) {
                    detectedFrameworks.push({
                      name: framework.name,
                      type: framework.type,
                      category: framework.category,
                      version: undefined, // We don't know the version from just content patterns
                      location: match,
                      detectionConfidence: 'medium',
                      detectionMethod: 'content_pattern'
                    });
                  }
                  
                  // Stop after first match for this framework
                  break;
                }
              } catch (contentError) {
                log.warn(`Error reading file content: ${match}`, { error: contentError });
              }
            }
            
            // If we found the framework, stop searching
            if (detectedFrameworks.some(df => df.name === framework.name)) {
              break;
            }
          }
        }
      } catch (frameworkError) {
        log.warn(`Error checking for framework: ${framework.name}`, { error: frameworkError });
      }
    }
    
    return detectedFrameworks;
  } catch (error) {
    log.error('Error detecting used frameworks', { error });
    return [];
  }
}

/**
 * Generate a migration path for a framework
 */
function generateMigrationPath(
  name: string,
  currentVersion: string,
  latestVersion: string,
  frameworkRecord: FrameworkRecord
): string {
  // Sort all versions between current and latest
  const allVersions = frameworkRecord.versions
    .filter(v => compareVersions(v.version, currentVersion) > 0 && compareVersions(v.version, latestVersion) <= 0)
    .sort((a, b) => compareVersions(a.version, b.version));
  
  if (allVersions.length === 0) {
    return `Upgrade directly from ${currentVersion} to ${latestVersion}`;
  }
  
  // Create migration path
  const path = [`Start with ${name} ${currentVersion}`];
  
  for (const version of allVersions) {
    path.push(`Upgrade to ${name} ${version.version}${version.migrationNotes ? ` (${version.migrationNotes})` : ''}`);
  }
  
  return path.join(' → ');
}

/**
 * Generate a recommendation for addressing a framework issue
 */
function generateRecommendation(
  name: string,
  currentVersion: string,
  latestVersion: string,
  isOutdated: boolean,
  isDeprecated: boolean,
  isEol: boolean,
  isSupportEnding: boolean,
  daysUntilEol?: number,
  daysUntilSupportEnds?: number,
  hasVulnerabilities: boolean,
  alternatives?: { name: string, url: string, migrationGuideUrl?: string }[]
): string {
  const recommendations: string[] = [];
  
  if (isOutdated) {
    recommendations.push(`Update ${name} from ${currentVersion} to ${latestVersion}`);
  }
  
  if (isDeprecated) {
    if (alternatives && alternatives.length > 0) {
      const alternative = alternatives[0];
      recommendations.push(`Consider migrating from deprecated ${name} to ${alternative.name}${alternative.migrationGuideUrl ? ` (see guide: ${alternative.migrationGuideUrl})` : ''}`);
    } else {
      recommendations.push(`Replace deprecated framework ${name} with a supported alternative`);
    }
  }
  
  if (isEol) {
    recommendations.push(`${name} ${currentVersion} has reached end-of-life, immediate upgrade is critical`);
  } else if (daysUntilEol !== undefined && daysUntilEol < 180) {
    recommendations.push(`${name} ${currentVersion} will reach end-of-life in ${daysUntilEol} days, plan migration soon`);
  }
  
  if (isSupportEnding) {
    recommendations.push(`${name} ${currentVersion} is no longer supported, update immediately`);
  } else if (daysUntilSupportEnds !== undefined && daysUntilSupportEnds < 180) {
    recommendations.push(`Support for ${name} ${currentVersion} will end in ${daysUntilSupportEnds} days, plan update`);
  }
  
  if (hasVulnerabilities) {
    recommendations.push(`Address security vulnerabilities in ${name} ${currentVersion} by updating to latest version`);
  }
  
  // Return combined recommendations
  return recommendations.join('. ');
}

/**
 * Convert severity to a numeric security impact score
 */
function securityImpactFromSeverity(severity: 'low' | 'medium' | 'high' | 'critical'): number {
  switch (severity) {
    case 'critical': return 5;
    case 'high': return 4;
    case 'medium': return 3;
    case 'low': return 2;
    default: return 1;
  }
}
