import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import { FrameworkIssue, VulnerabilityInfo } from '../types/scanning';
import { compareVersions, formatDate, estimateBusinessImpact } from '../utils/scanner-utils';
import { log } from '../utils/logging';

const readFileAsync = promisify(fs.readFile);

/**
 * Configuration for framework scanning
 */
export interface FrameworkScannerConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Which framework categories to check
  frameworkCategories: Array<'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other'>;
  
  // Whether to check for vulnerabilities
  checkVulnerabilities: boolean;
  
  // Whether to check for end of life/support dates
  checkEndOfLife: boolean;
  
  // Whether to estimate migration effort
  estimateMigrationEffort: boolean;
  
  // Whether to estimate business impact
  estimateBusinessImpact: boolean;
  
  // Minimum age in days to report (0 = report all)
  minimumAgeInDays: number;
  
  // Skip frameworks with specific names
  ignoreFrameworks?: string[];
  
  // Skip frameworks matching specific patterns
  ignorePatterns?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Path to custom framework database (if any)
  customFrameworkDbPath?: string;
}

/**
 * Database of known frameworks with their version detection methods
 */
interface FrameworkDatabase {
  // Map of framework name to detection rules
  frameworks: Record<string, FrameworkDetectionRule>;
  
  // Map of framework name to known vulnerabilities
  vulnerabilities: Record<string, FrameworkVulnerability[]>;
  
  // Map of framework name to end-of-life/support information
  lifecycleInfo: Record<string, FrameworkLifecycleInfo>;
  
  // Last updated timestamp
  lastUpdated: Date;
}

/**
 * Rules for detecting a framework and its version
 */
interface FrameworkDetectionRule {
  // Framework name
  name: string;
  
  // Framework category
  category: 'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other';
  
  // Framework type (e.g., 'js-framework', 'php-cms', 'database')
  type: string;
  
  // File patterns to search for (glob patterns)
  filePatterns: string[];
  
  // Files to ignore (glob patterns)
  ignorePatterns?: string[];
  
  // Regular expressions to use for version detection
  versionDetectionRegexes: {
    // File pattern to match
    filePattern: string;
    // Regex to extract version
    regex: string;
    // Regex group index for version
    versionGroup: number;
  }[];
  
  // Package.json dependencies to check (for JavaScript frameworks)
  packageJsonDependencies?: string[];
  
  // Composer.json dependencies to check (for PHP frameworks)
  composerJsonDependencies?: string[];
  
  // Gemfile dependencies to check (for Ruby frameworks)
  gemfileDependencies?: string[];
  
  // Requirements.txt dependencies to check (for Python frameworks)
  requirementsTxtDependencies?: string[];
  
  // Latest known version
  latestVersion: string;
  
  // URL for version information
  versionInfoUrl?: string;
  
  // Migration guide URL
  migrationGuideUrl?: string;
}

/**
 * Vulnerability information for a framework
 */
interface FrameworkVulnerability {
  // Framework name
  frameworkName: string;
  
  // Affected versions
  affectedVersions: string;
  
  // Patched versions
  patchedVersions?: string;
  
  // CVE ID
  cveId?: string;
  
  // Vulnerability title
  title: string;
  
  // Detailed description
  description: string;
  
  // CVSS score
  cvssScore?: number;
  
  // Severity
  severity: 'low' | 'medium' | 'high' | 'critical';
  
  // URL for more information
  infoUrl?: string;
  
  // Published date
  publishedDate?: Date;
  
  // Recommendation to fix
  recommendation?: string;
}

/**
 * Lifecycle information for a framework
 */
interface FrameworkLifecycleInfo {
  // Framework name
  frameworkName: string;
  
  // End of life date
  endOfLifeDate?: Date;
  
  // End of support date
  endOfSupportDate?: Date;
  
  // Whether the framework is deprecated
  isDeprecated: boolean;
  
  // Date when framework was deprecated
  deprecatedDate?: Date;
  
  // Recommended alternative
  recommendedAlternative?: string;
  
  // Migration difficulty (1-5)
  migrationDifficulty?: number;
  
  // URL for more information
  infoUrl?: string;
}

/**
 * Scanner for detecting outdated frameworks and technologies
 */
export async function scanFrameworks(
  config: FrameworkScannerConfig
): Promise<FrameworkIssue[]> {
  try {
    log.info('Starting framework scanner');
    const issues: FrameworkIssue[] = [];
    
    // Load framework database
    const frameworkDb = await loadFrameworkDatabase(config);
    
    log.info(`Loaded framework database with ${Object.keys(frameworkDb.frameworks).length} frameworks`);
    
    // Detect frameworks for each category
    for (const category of config.frameworkCategories) {
      try {
        log.info(`Scanning for ${category} frameworks`);
        
        // Get frameworks for this category
        const categoryFrameworks = Object.values(frameworkDb.frameworks)
          .filter(f => f.category === category);
        
        log.info(`Found ${categoryFrameworks.length} framework definitions for category ${category}`);
        
        // Detect each framework
        for (const framework of categoryFrameworks) {
          try {
            // Skip ignored frameworks
            if (config.ignoreFrameworks && config.ignoreFrameworks.includes(framework.name)) {
              log.info(`Skipping ignored framework: ${framework.name}`);
              continue;
            }
            
            // Skip frameworks matching ignore patterns
            if (config.ignorePatterns && 
                config.ignorePatterns.some(pattern => new RegExp(pattern).test(framework.name))) {
              log.info(`Skipping framework matching ignore pattern: ${framework.name}`);
              continue;
            }
            
            // Detect this framework
            log.info(`Detecting framework: ${framework.name}`);
            const detectedVersions = await detectFrameworkVersion(config.rootDirectory, framework);
            
            if (detectedVersions.length === 0) {
              log.info(`Framework not detected: ${framework.name}`);
              continue;
            }
            
            log.info(`Framework detected: ${framework.name}, versions: ${detectedVersions.join(', ')}`);
            
            // Process each detected version
            for (const detected of detectedVersions) {
              try {
                const { version, location } = detected;
                
                // Check if outdated
                const isOutdated = compareVersions(version, framework.latestVersion) < 0;
                
                // Get lifecycle information
                const lifecycleInfo = frameworkDb.lifecycleInfo[framework.name];
                const isDeprecated = lifecycleInfo?.isDeprecated || false;
                
                // Get vulnerabilities
                let vulnerabilities: VulnerabilityInfo[] = [];
                if (config.checkVulnerabilities) {
                  vulnerabilities = await getFrameworkVulnerabilities(
                    framework.name, 
                    version, 
                    frameworkDb.vulnerabilities
                  );
                }
                
                // Skip if not outdated, not deprecated, and no vulnerabilities
                if (!isOutdated && !isDeprecated && vulnerabilities.length === 0) {
                  log.info(`Framework ${framework.name} version ${version} is current and has no issues`);
                  continue;
                }
                
                // Create issue
                const issue: FrameworkIssue = {
                  name: framework.name,
                  currentVersion: version,
                  latestVersion: framework.latestVersion,
                  isOutdated,
                  isDeprecated,
                  category: framework.category,
                  type: framework.type,
                  location,
                  vulnerabilities,
                  detectedAt: new Date()
                };
                
                // Add lifecycle information if configured
                if (config.checkEndOfLife && lifecycleInfo) {
                  issue.endOfLifeDate = lifecycleInfo.endOfLifeDate;
                  issue.endOfSupportDate = lifecycleInfo.endOfSupportDate;
                  
                  if (lifecycleInfo.recommendedAlternative) {
                    issue.migrationPath = `Migrate to ${lifecycleInfo.recommendedAlternative}. `;
                    
                    if (framework.migrationGuideUrl) {
                      issue.migrationPath += `See migration guide: ${framework.migrationGuideUrl}`;
                    }
                  }
                }
                
                // Estimate migration effort if configured
                if (config.estimateMigrationEffort && lifecycleInfo) {
                  issue.migrationEffort = lifecycleInfo.migrationDifficulty || estimateMigrationEffort(
                    framework.name,
                    isOutdated,
                    isDeprecated,
                    vulnerabilities.length > 0
                  );
                }
                
                // Estimate business impact if configured
                if (config.estimateBusinessImpact) {
                  issue.businessImpact = estimateBusinessImpact(
                    isOutdated,
                    isDeprecated,
                    vulnerabilities.length > 0,
                    framework.category === 'system' || framework.type.includes('core')
                  );
                  
                  issue.securityImpact = vulnerabilities.length > 0 ? 
                    Math.max(...vulnerabilities.map(v => securityImpactFromSeverity(v.severity))) : 1;
                }
                
                // Add to issues list
                issues.push(issue);
                log.info(`Added issue for framework ${framework.name} version ${version}`);
              } catch (versionError) {
                log.warn(`Error processing framework version: ${framework.name}`, { error: versionError });
              }
            }
          } catch (frameworkError) {
            log.warn(`Error detecting framework: ${framework.name}`, { error: frameworkError });
          }
        }
      } catch (categoryError) {
        log.error(`Error scanning ${category} frameworks`, { error: categoryError });
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
 * Load the framework database
 */
async function loadFrameworkDatabase(
  config: FrameworkScannerConfig
): Promise<FrameworkDatabase> {
  // In a real implementation, this would load from a file or API
  // For this example, we'll return a small hardcoded database
  
  return {
    frameworks: {
      'react': {
        name: 'React',
        category: 'frontend',
        type: 'js-framework',
        filePatterns: ['**/package.json', '**/node_modules/react/package.json'],
        versionDetectionRegexes: [
          {
            filePattern: '**/package.json',
            regex: '"react"\s*:\s*"([^"]+)"',
            versionGroup: 1
          }
        ],
        packageJsonDependencies: ['react'],
        latestVersion: '18.2.0',
        versionInfoUrl: 'https://reactjs.org/versions',
        migrationGuideUrl: 'https://reactjs.org/blog/2022/03/08/react-18-upgrade-guide.html'
      },
      'angular': {
        name: 'Angular',
        category: 'frontend',
        type: 'js-framework',
        filePatterns: ['**/package.json', '**/angular.json'],
        versionDetectionRegexes: [
          {
            filePattern: '**/package.json',
            regex: '"@angular/core"\s*:\s*"([^"]+)"',
            versionGroup: 1
          }
        ],
        packageJsonDependencies: ['@angular/core'],
        latestVersion: '17.0.0',
        versionInfoUrl: 'https://angular.io/guide/versions',
        migrationGuideUrl: 'https://update.angular.io/'
      },
      'vue': {
        name: 'Vue.js',
        category: 'frontend',
        type: 'js-framework',
        filePatterns: ['**/package.json'],
        versionDetectionRegexes: [
          {
            filePattern: '**/package.json',
            regex: '"vue"\s*:\s*"([^"]+)"',
            versionGroup: 1
          }
        ],
        packageJsonDependencies: ['vue'],
        latestVersion: '3.3.4',
        versionInfoUrl: 'https://github.com/vuejs/vue/releases',
        migrationGuideUrl: 'https://v3-migration.vuejs.org/'
      },
      'django': {
        name: 'Django',
        category: 'backend',
        type: 'python-framework',
        filePatterns: ['**/requirements.txt', '**/requirements/*.txt', '**/setup.py', '**/pyproject.toml'],
        versionDetectionRegexes: [
          {
            filePattern: '**/requirements.txt',
            regex: 'django==([\d.]+)',
            versionGroup: 1
          },
          {
            filePattern: '**/setup.py',
            regex: 'django[>=~]=([\d.]+)',
            versionGroup: 1
          }
        ],
        requirementsTxtDependencies: ['django'],
        latestVersion: '4.2.7',
        versionInfoUrl: 'https://www.djangoproject.com/download/',
        migrationGuideUrl: 'https://docs.djangoproject.com/en/4.2/howto/upgrade-version/'
      },
      'node': {
        name: 'Node.js',
        category: 'backend',
        type: 'js-runtime',
        filePatterns: ['**/package.json', '**/.nvmrc', '**/.node-version'],
        versionDetectionRegexes: [
          {
            filePattern: '**/.nvmrc',
            regex: '([\d.]+)',
            versionGroup: 1
          },
          {
            filePattern: '**/.node-version',
            regex: '([\d.]+)',
            versionGroup: 1
          },
          {
            filePattern: '**/package.json',
            regex: '"node"\s*:\s*"([^"]+)"',
            versionGroup: 1
          }
        ],
        latestVersion: '20.5.0',
        versionInfoUrl: 'https://nodejs.org/en/download/releases/'
      },
      'express': {
        name: 'Express',
        category: 'backend',
        type: 'js-framework',
        filePatterns: ['**/package.json'],
        versionDetectionRegexes: [
          {
            filePattern: '**/package.json',
            regex: '"express"\s*:\s*"([^"]+)"',
            versionGroup: 1
          }
        ],
        packageJsonDependencies: ['express'],
        latestVersion: '4.18.2',
        versionInfoUrl: 'https://expressjs.com/'
      }
    },
    vulnerabilities: {
      'react': [
        {
          frameworkName: 'React',
          affectedVersions: '<16.5.0',
          patchedVersions: '>=16.5.0',
          cveId: 'CVE-2018-6341',
          title: 'React XSS vulnerability through attributes',
          description: 'A vulnerability in React DOM allowed passing malicious attributes through to HTML elements.',
          cvssScore: 7.2,
          severity: 'high',
          infoUrl: 'https://github.com/facebook/react/releases/tag/v16.5.0',
          publishedDate: new Date('2018-08-01'),
          recommendation: 'Upgrade to React 16.5.0 or newer'
        }
      ],
      'django': [
        {
          frameworkName: 'Django',
          affectedVersions: '<3.2.16',
          patchedVersions: '>=3.2.16',
          cveId: 'CVE-2022-41323',
          title: 'Potential denial-of-service vulnerability in internationalized URLs',
          description: 'A vulnerability in Django could allow an attacker to cause an infinite loop in certain URL processing.',
          cvssScore: 7.5,
          severity: 'high',
          infoUrl: 'https://www.djangoproject.com/weblog/2022/oct/04/security-releases/',
          publishedDate: new Date('2022-10-04'),
          recommendation: 'Upgrade to Django 3.2.16, 4.0.8, or 4.1.2 or newer'
        }
      ]
    },
    lifecycleInfo: {
      'django': {
        frameworkName: 'Django',
        endOfLifeDate: new Date('2025-04-01'),
        endOfSupportDate: new Date('2024-04-01'),
        isDeprecated: false,
        migrationDifficulty: 3,
        infoUrl: 'https://www.djangoproject.com/download/#supported-versions'
      },
      'node': {
        frameworkName: 'Node.js',
        endOfLifeDate: new Date('2023-09-30'),
        endOfSupportDate: new Date('2023-06-01'),
        isDeprecated: false,
        migrationDifficulty: 2,
        infoUrl: 'https://nodejs.org/en/about/releases/'
      },
      'angular.js': {
        frameworkName: 'AngularJS',
        endOfLifeDate: new Date('2022-01-01'),
        endOfSupportDate: new Date('2021-12-31'),
        isDeprecated: true,
        deprecatedDate: new Date('2021-12-31'),
        recommendedAlternative: 'Angular (Angular 2+)',
        migrationDifficulty: 4,
        infoUrl: 'https://blog.angular.io/discontinued-long-term-support-for-angularjs-1-67a8c73710e1'
      }
    },
    lastUpdated: new Date()
  };
}

/**
 * Result of framework version detection
 */
interface DetectedFrameworkVersion {
  version: string;
  location: string;
}

/**
 * Detect framework versions in the project
 */
async function detectFrameworkVersion(
  rootDirectory: string,
  framework: FrameworkDetectionRule
): Promise<DetectedFrameworkVersion[]> {
  const results: DetectedFrameworkVersion[] = [];
  
  // Process each file pattern
  for (const pattern of framework.filePatterns) {
    try {
      // Build the full pattern with the root directory
      const fullPattern = path.join(rootDirectory, pattern);
      
      // Get ignore patterns
      const ignorePatterns = framework.ignorePatterns?.map(p => path.join(rootDirectory, p)) || [];
      
      // Find matching files
      const files = await glob(fullPattern, {
        ignore: [...ignorePatterns, '**/node_modules/**'],
        nodir: true
      });
      
      // Process each file
      for (const file of files) {
        try {
          // Read file content
          const content = await readFileAsync(file, 'utf8');
          
          // Look for version using regex
          for (const versionRule of framework.versionDetectionRegexes) {
            try {
              // Check if this rule applies to this file
              const filePatternRegex = new RegExp(versionRule.filePattern.replace(/\*\*/g, '.*'));
              if (!filePatternRegex.test(file)) {
                continue;
              }
              
              // Apply regex to extract version
              const versionRegex = new RegExp(versionRule.regex, 'i');
              const match = content.match(versionRegex);
              
              if (match && match[versionRule.versionGroup]) {
                const version = match[versionRule.versionGroup].trim();
                
                results.push({
                  version,
                  location: file
                });
                
                // Break after first successful detection for this file
                break;
              }
            } catch (ruleError) {
              log.warn(`Error applying version detection rule for ${framework.name}`, { error: ruleError });
            }
          }
          
          // Special case for package.json dependencies
          if (path.basename(file) === 'package.json' && framework.packageJsonDependencies) {
            try {
              const packageJson = JSON.parse(content);
              
              // Check dependencies
              for (const dep of framework.packageJsonDependencies) {
                if (packageJson.dependencies && packageJson.dependencies[dep]) {
                  const version = packageJson.dependencies[dep].replace(/^[^\d]+/, '');
                  
                  results.push({
                    version,
                    location: file
                  });
                }
                
                // Also check devDependencies
                if (packageJson.devDependencies && packageJson.devDependencies[dep]) {
                  const version = packageJson.devDependencies[dep].replace(/^[^\d]+/, '');
                  
                  results.push({
                    version,
                    location: file
                  });
                }
              }
            } catch (jsonError) {
              log.warn(`Error parsing package.json at ${file}`, { error: jsonError });
            }
          }
        } catch (fileError) {
          log.warn(`Error reading file ${file}`, { error: fileError });
        }
      }
    } catch (patternError) {
      log.warn(`Error processing file pattern ${pattern}`, { error: patternError });
    }
  }
  
  return results;
}

/**
 * Get vulnerabilities for a framework version
 */
async function getFrameworkVulnerabilities(
  frameworkName: string,
  version: string,
  vulnerabilityDatabase: Record<string, FrameworkVulnerability[]>
): Promise<VulnerabilityInfo[]> {
  try {
    // Get vulnerabilities for this framework
    const frameworkVulnerabilities = vulnerabilityDatabase[frameworkName] || [];
    
    // Filter to those affecting this version
    const affectingVulnerabilities = frameworkVulnerabilities.filter(v => {
      // Check if this version is in the affected range
      // In a real implementation, this would use proper semver range checking
      return v.affectedVersions.includes(version) || 
             (v.affectedVersions.includes('<') && compareVersions(version, v.affectedVersions.replace('<', '')) < 0);
    });
    
    // Map to VulnerabilityInfo format
    return affectingVulnerabilities.map(v => ({
      id: v.cveId || `${frameworkName}-${v.title.replace(/\s+/g, '-').toLowerCase()}`,
      severity: v.severity,
      cvssScore: v.cvssScore,
      title: v.title,
      description: v.description,
      infoUrl: v.infoUrl,
      publishedDate: v.publishedDate,
      affectedVersions: v.affectedVersions,
      patchedVersions: v.patchedVersions,
      recommendation: v.recommendation
    }));
  } catch (error) {
    log.warn(`Error getting vulnerabilities for ${frameworkName} ${version}`, { error });
    return [];
  }
}

/**
 * Estimate migration effort based on framework and its state
 */
function estimateMigrationEffort(
  frameworkName: string,
  isOutdated: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean
): number {
  // Start with a base effort level
  let effort = 2;
  
  // Adjust based on conditions
  if (isDeprecated) effort += 2;
  if (isOutdated) effort += 1;
  if (hasVulnerabilities) effort += 1;
  
  // Adjust based on known difficult migrations
  const highEffortFrameworks = ['angular.js', 'spring', 'django', 'ruby-on-rails'];
  if (highEffortFrameworks.some(f => frameworkName.toLowerCase().includes(f))) {
    effort += 1;
  }
  
  // Cap at 5
  return Math.min(5, effort);
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
