import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { exec } from 'child_process';
import { FrameworkIssue, VulnerabilityInfo } from '../types/scanning';
import { compareVersions, daysBetween } from '../utils/scanner-utils';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

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
  
  // Custom framework version files locations
  customVersionLocations?: Record<string, string[]>;
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
}

/**
 * Framework definition structure used for detection
 */
interface FrameworkDefinition {
  name: string;
  category: 'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other';
  type: string;
  detectionPatterns: {
    // File patterns to look for
    filePatterns: string[];
    // Content patterns to match in the files
    contentPatterns?: string[];
    // Package patterns to look for in package.json
    packagePatterns?: string[];
    // Custom detection function
    customDetection?: (fileContent: string, filePath: string) => boolean;
  };
  versionDetection: {
    // How to detect the version
    strategy: 'file' | 'package' | 'command' | 'api' | 'content';
    // Details based on the strategy
    details: any;
  };
  // URL to check latest version
  latestVersionUrl?: string;
  // End of life information URL
  endOfLifeUrl?: string;
  // Known security vulnerabilities URL
  securityAdvisoriesUrl?: string;
  // Migration path information
  migrationPath?: string;
}

/**
 * Framework version information
 */
interface FrameworkInfo {
  name: string;
  category: 'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other';
  type: string;
  version: string;
  detectedAt: string;
  latestVersion?: string;
  endOfLifeDate?: Date;
  endOfSupportDate?: Date;
}

/**
 * Scan project for outdated frameworks and technologies
 */
export async function scanFrameworks(
  config: FrameworkScannerConfig
): Promise<FrameworkIssue[]> {
  try {
    log.info('Starting framework scanner');
    
    const issues: FrameworkIssue[] = [];
    
    // Get all framework definitions that match requested categories
    const frameworkDefinitions = getFrameworkDefinitions(config.frameworkCategories);
    log.info(`Loaded ${frameworkDefinitions.length} framework definitions for detection`);
    
    // Detect frameworks in use
    const detectedFrameworks = await detectFrameworks(frameworkDefinitions, config);
    log.info(`Detected ${detectedFrameworks.length} frameworks in use`);
    
    // Check each framework for issues
    for (const framework of detectedFrameworks) {
      try {
        // Skip ignored frameworks
        if (config.ignoreFrameworks && config.ignoreFrameworks.includes(framework.name)) {
          continue;
        }
        
        // Skip frameworks matching ignore patterns
        if (config.ignorePatterns && 
            config.ignorePatterns.some(pattern => new RegExp(pattern).test(framework.name))) {
          continue;
        }
        
        // Get the latest version
        const latestVersion = framework.latestVersion || 
          await getLatestFrameworkVersion(framework.name, framework.type);
        
        if (!latestVersion) {
          continue; // Skip if we can't determine the latest version
        }
        
        const isOutdated = compareVersions(framework.version, latestVersion) < 0;
        
        // Only report if outdated or meets the minimum age requirement
        if (isOutdated || 
            daysBetween(new Date(framework.detectedAt), new Date()) >= config.minimumAgeInDays) {
          
          // Gather additional information
          let endOfLifeDate = framework.endOfLifeDate;
          let endOfSupportDate = framework.endOfSupportDate;
          
          if (config.checkEndOfLife && (!endOfLifeDate || !endOfSupportDate)) {
            const eolInfo = await getFrameworkEOLInfo(framework.name, framework.version, framework.type);
            endOfLifeDate = eolInfo.endOfLifeDate || undefined;
            endOfSupportDate = eolInfo.endOfSupportDate || undefined;
          }
          
          // Get vulnerabilities if enabled
          let vulnerabilities: VulnerabilityInfo[] = [];
          if (config.checkVulnerabilities) {
            vulnerabilities = await getFrameworkVulnerabilities(
              framework.name, 
              framework.version, 
              framework.type
            );
          }
          
          // Create the issue record
          const issue: FrameworkIssue = {
            name: framework.name,
            currentVersion: framework.version,
            latestVersion: latestVersion,
            isOutdated,
            isDeprecated: !!endOfLifeDate && endOfLifeDate < new Date(),
            category: framework.category,
            type: framework.type,
            location: framework.detectedAt,
            endOfLifeDate,
            endOfSupportDate,
            vulnerabilities,
            detectedAt: new Date(),
          };
          
          // Add migration information if requested
          if (config.estimateMigrationEffort) {
            issue.migrationPath = await getFrameworkMigrationPath(framework.name, framework.version, latestVersion);
            issue.migrationEffort = estimateMigrationEffort(framework.name, framework.version, latestVersion);
          }
          
          // Add business impact if requested
          if (config.estimateBusinessImpact) {
            issue.businessImpact = estimateBusinessImpact(
              framework.name, 
              isOutdated, 
              !!vulnerabilities.length,
              endOfLifeDate
            );
            
            // Also estimate security impact
            issue.securityImpact = estimateSecurityImpact(
              framework.name,
              vulnerabilities,
              endOfLifeDate
            );
          }
          
          issues.push(issue);
        }
      } catch (frameworkError) {
        log.warn(`Error checking framework ${framework.name}@${framework.version}`, { error: frameworkError });
      }
    }
    
    log.info(`Completed framework scanning. Found ${issues.length} issues`);
    return issues;
  } catch (error) {
    log.error('Error during framework scanning', { error });
    return [];
  }
}

/**
 * Get framework definitions for the given categories
 */
function getFrameworkDefinitions(
  categories: Array<'frontend' | 'backend' | 'mobile' | 'database' | 'devops' | 'system' | 'other'>
): FrameworkDefinition[] {
  // In a real implementation, this would come from a database or configuration file
  // Here we'll define a few examples manually
  const allDefinitions: FrameworkDefinition[] = [
    // Frontend frameworks
    {
      name: 'React',
      category: 'frontend',
      type: 'UI Framework',
      detectionPatterns: {
        filePatterns: ['package.json'],
        packagePatterns: ['react', 'react-dom']
      },
      versionDetection: {
        strategy: 'package',
        details: {
          packageName: 'react'
        }
      },
      latestVersionUrl: 'https://api.github.com/repos/facebook/react/releases/latest',
      endOfLifeUrl: 'https://reactjs.org/blog/',
      securityAdvisoriesUrl: 'https://github.com/facebook/react/security/advisories'
    },
    {
      name: 'Angular',
      category: 'frontend',
      type: 'UI Framework',
      detectionPatterns: {
        filePatterns: ['package.json', 'angular.json'],
        packagePatterns: ['@angular/core']
      },
      versionDetection: {
        strategy: 'package',
        details: {
          packageName: '@angular/core'
        }
      },
      latestVersionUrl: 'https://api.github.com/repos/angular/angular/releases/latest',
      endOfLifeUrl: 'https://angular.io/guide/releases',
      securityAdvisoriesUrl: 'https://github.com/angular/angular/security/advisories',
      migrationPath: 'https://update.angular.io/'
    },
    {
      name: 'Vue.js',
      category: 'frontend',
      type: 'UI Framework',
      detectionPatterns: {
        filePatterns: ['package.json'],
        packagePatterns: ['vue']
      },
      versionDetection: {
        strategy: 'package',
        details: {
          packageName: 'vue'
        }
      },
      latestVersionUrl: 'https://api.github.com/repos/vuejs/vue/releases/latest',
      endOfLifeUrl: 'https://v3.vuejs.org/guide/migration/introduction.html',
      securityAdvisoriesUrl: 'https://github.com/vuejs/vue/security/advisories'
    },
    
    // Backend frameworks
    {
      name: 'Express.js',
      category: 'backend',
      type: 'Web Framework',
      detectionPatterns: {
        filePatterns: ['package.json'],
        packagePatterns: ['express']
      },
      versionDetection: {
        strategy: 'package',
        details: {
          packageName: 'express'
        }
      },
      latestVersionUrl: 'https://api.github.com/repos/expressjs/express/releases/latest',
      securityAdvisoriesUrl: 'https://github.com/expressjs/express/security/advisories'
    },
    {
      name: 'Django',
      category: 'backend',
      type: 'Web Framework',
      detectionPatterns: {
        filePatterns: ['requirements.txt', 'Pipfile', 'setup.py', 'pyproject.toml'],
        contentPatterns: ['django', 'Django']
      },
      versionDetection: {
        strategy: 'command',
        details: {
          command: 'python -c "import django; print(django.get_version())"'
        }
      },
      latestVersionUrl: 'https://www.djangoproject.com/download/',
      endOfLifeUrl: 'https://www.djangoproject.com/download/#supported-versions',
      securityAdvisoriesUrl: 'https://docs.djangoproject.com/en/stable/releases/security/'
    },
    {
      name: 'Spring Boot',
      category: 'backend',
      type: 'Application Framework',
      detectionPatterns: {
        filePatterns: ['pom.xml', 'build.gradle'],
        contentPatterns: ['org.springframework.boot', 'spring-boot']
      },
      versionDetection: {
        strategy: 'content',
        details: {
          filePattern: 'pom.xml',
          regex: '<spring-boot\.version>([\d\.]+)<\/spring-boot\.version>'
        }
      },
      latestVersionUrl: 'https://api.github.com/repos/spring-projects/spring-boot/releases/latest',
      endOfLifeUrl: 'https://spring.io/projects/spring-boot#support',
      securityAdvisoriesUrl: 'https://spring.io/security'
    },
    
    // Database technologies
    {
      name: 'MongoDB',
      category: 'database',
      type: 'NoSQL Database',
      detectionPatterns: {
        filePatterns: ['package.json'],
        packagePatterns: ['mongodb', 'mongoose']
      },
      versionDetection: {
        strategy: 'command',
        details: {
          command: 'mongod --version'
        }
      },
      latestVersionUrl: 'https://www.mongodb.com/try/download/community',
      endOfLifeUrl: 'https://www.mongodb.com/support-policy',
      securityAdvisoriesUrl: 'https://www.mongodb.com/alerts'
    }
    // Additional framework definitions would be defined here
  ];
  
  // Filter by requested categories
  return allDefinitions.filter(def => categories.includes(def.category));
}

/**
 * Detect frameworks used in the project
 */
async function detectFrameworks(
  frameworkDefinitions: FrameworkDefinition[],
  config: FrameworkScannerConfig
): Promise<FrameworkInfo[]> {
  const detectedFrameworks: FrameworkInfo[] = [];
  
  // For each framework definition, check if it's used in the project
  for (const definition of frameworkDefinitions) {
    try {
      // First check if any of the file patterns exist
      const matchingFiles: string[] = [];
      
      for (const pattern of definition.detectionPatterns.filePatterns) {
        const foundFiles = await globFiles(path.join(config.rootDirectory, '**', pattern));
        matchingFiles.push(...foundFiles);
      }
      
      if (matchingFiles.length === 0) {
        continue; // No matching files found, skip to next framework
      }
      
      // Check content patterns if defined
      let contentMatched = !definition.detectionPatterns.contentPatterns || 
        definition.detectionPatterns.contentPatterns.length === 0;
      
      if (!contentMatched) {
        for (const filePath of matchingFiles) {
          const content = fs.readFileSync(filePath, 'utf8');
          
          if (definition.detectionPatterns.contentPatterns!.some(pattern => 
              content.includes(pattern) || new RegExp(pattern).test(content))) {
            contentMatched = true;
            break;
          }
        }
      }
      
      if (!contentMatched) {
        continue; // Content patterns didn't match, skip to next framework
      }
      
      // Check package patterns if defined
      let packageMatched = !definition.detectionPatterns.packagePatterns || 
        definition.detectionPatterns.packagePatterns.length === 0;
      
      if (!packageMatched) {
        const packageJsonFiles = matchingFiles.filter(file => path.basename(file) === 'package.json');
        
        for (const packagePath of packageJsonFiles) {
          try {
            const packageContent = fs.readFileSync(packagePath, 'utf8');
            const packageJson = JSON.parse(packageContent);
            
            const dependencies = {
              ...packageJson.dependencies,
              ...packageJson.devDependencies
            };
            
            if (definition.detectionPatterns.packagePatterns!.some(pattern => 
                Object.keys(dependencies).includes(pattern) || 
                Object.keys(dependencies).some(dep => dep.includes(pattern)))) {
              packageMatched = true;
              break;
            }
          } catch (packageError) {
            log.warn(`Error parsing package.json at ${packagePath}`, { error: packageError });
          }
        }
      }
      
      if (!packageMatched) {
        continue; // Package patterns didn't match, skip to next framework
      }
      
      // If we got here, the framework is detected - now get its version
      const version = await detectFrameworkVersion(definition, matchingFiles, config);
      
      if (version) {
        detectedFrameworks.push({
          name: definition.name,
          category: definition.category,
          type: definition.type,
          version,
          detectedAt: matchingFiles[0] // Use the first matching file as the detection point
        });
      }
    } catch (detectionError) {
      log.warn(`Error detecting framework ${definition.name}`, { error: detectionError });
    }
  }
  
  return detectedFrameworks;
}

/**
 * Find files matching a glob pattern
 */
async function globFiles(pattern: string): Promise<string[]> {
  // Using a dynamic import for glob as it's an ESM module in newer versions
  const { glob } = await import('glob');
  return glob(pattern);
}

/**
 * Detect the version of a framework
 */
async function detectFrameworkVersion(
  definition: FrameworkDefinition,
  matchingFiles: string[],
  config: FrameworkScannerConfig
): Promise<string | null> {
  try {
    // Check if there are custom version locations defined
    if (config.customVersionLocations && config.customVersionLocations[definition.name]) {
      for (const versionPath of config.customVersionLocations[definition.name]) {
        if (fs.existsSync(versionPath)) {
          const content = fs.readFileSync(versionPath, 'utf8');
          // Try to extract version with a simple regex - this would need to be improved
          const versionMatch = content.match(/(version|Version)\s*[=:]\s*[\'"](\d+\.\d+\.\d+)[\'"]/i);
          if (versionMatch && versionMatch[2]) {
            return versionMatch[2];
          }
        }
      }
    }
    
    // Use the framework's version detection strategy
    switch (definition.versionDetection.strategy) {
      case 'package':
        return detectVersionFromPackage(
          definition.versionDetection.details.packageName,
          matchingFiles
        );
        
      case 'command':
        return detectVersionFromCommand(
          definition.versionDetection.details.command,
          config.apiTimeoutMs
        );
        
      case 'file':
        return detectVersionFromFile(
          definition.versionDetection.details.filePath,
          definition.versionDetection.details.regex
        );
        
      case 'content':
        return detectVersionFromContent(
          definition.versionDetection.details.filePattern,
          definition.versionDetection.details.regex,
          matchingFiles
        );
        
      // Add other strategies as needed
        
      default:
        log.warn(`Unsupported version detection strategy: ${definition.versionDetection.strategy}`);
        return null;
    }
  } catch (error) {
    log.warn(`Error detecting version for ${definition.name}`, { error });
    return null;
  }
}

/**
 * Detect version from package.json dependencies
 */
async function detectVersionFromPackage(
  packageName: string,
  matchingFiles: string[]
): Promise<string | null> {
  const packageJsonFiles = matchingFiles.filter(file => path.basename(file) === 'package.json');
  
  for (const packagePath of packageJsonFiles) {
    try {
      const packageContent = fs.readFileSync(packagePath, 'utf8');
      const packageJson = JSON.parse(packageContent);
      
      const dependencies = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies
      };
      
      if (dependencies[packageName]) {
        // Clean the version (remove ^, ~, etc.)
        return dependencies[packageName].replace(/^[^\d]+/, '');
      }
    } catch (packageError) {
      log.warn(`Error parsing package.json at ${packagePath}`, { error: packageError });
    }
  }
  
  return null;
}

/**
 * Detect version by executing a command
 */
async function detectVersionFromCommand(
  command: string,
  timeoutMs: number
): Promise<string | null> {
  try {
    const { stdout } = await execAsync(command, { timeout: timeoutMs });
    
    // Try to extract version with a regex
    const versionMatch = stdout.match(/(\d+\.\d+\.\d+)/);
    if (versionMatch && versionMatch[1]) {
      return versionMatch[1];
    }
    
    return null;
  } catch (commandError) {
    log.warn(`Error executing command: ${command}`, { error: commandError });
    return null;
  }
}

/**
 * Detect version from a specific file
 */
async function detectVersionFromFile(
  filePath: string,
  regexPattern: string
): Promise<string | null> {
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      const regex = new RegExp(regexPattern);
      const match = content.match(regex);
      
      if (match && match[1]) {
        return match[1];
      }
    }
    
    return null;
  } catch (fileError) {
    log.warn(`Error reading file: ${filePath}`, { error: fileError });
    return null;
  }
}

/**
 * Detect version from file content
 */
async function detectVersionFromContent(
  filePattern: string,
  regexPattern: string,
  matchingFiles: string[]
): Promise<string | null> {
  const relevantFiles = matchingFiles.filter(file => 
    filePattern === '*' || path.basename(file) === filePattern);
  
  for (const filePath of relevantFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const regex = new RegExp(regexPattern);
      const match = content.match(regex);
      
      if (match && match[1]) {
        return match[1];
      }
    } catch (contentError) {
      log.warn(`Error reading file: ${filePath}`, { error: contentError });
    }
  }
  
  return null;
}

/**
 * Get the latest version of a framework
 */
async function getLatestFrameworkVersion(
  frameworkName: string,
  frameworkType: string
): Promise<string | null> {
  // In a real implementation, this would query the appropriate sources
  // For this example, we'll return mock data
  switch (frameworkName) {
    case 'React':
      return '18.2.0';
    case 'Angular':
      return '16.0.0';
    case 'Vue.js':
      return '3.3.4';
    case 'Express.js':
      return '4.18.2';
    case 'Django':
      return '4.2.0';
    case 'Spring Boot':
      return '3.1.0';
    case 'MongoDB':
      return '6.0.0';
    default:
      return null;
  }
}

/**
 * Get framework end-of-life information
 */
async function getFrameworkEOLInfo(
  frameworkName: string,
  version: string,
  frameworkType: string
): Promise<{ endOfLifeDate?: Date; endOfSupportDate?: Date }> {
  // In a real implementation, this would query appropriate sources
  // For this example, we'll return mock data
  const today = new Date();
  const sixMonthsAhead = new Date(today);
  sixMonthsAhead.setMonth(today.getMonth() + 6);
  
  const oneYearAhead = new Date(today);
  oneYearAhead.setFullYear(today.getFullYear() + 1);
  
  const sixMonthsAgo = new Date(today);
  sixMonthsAgo.setMonth(today.getMonth() - 6);
  
  switch (frameworkName) {
    case 'Angular':
      // Old versions are considered EOL
      if (version.startsWith('7.') || version.startsWith('8.')) {
        return {
          endOfLifeDate: sixMonthsAgo,
          endOfSupportDate: sixMonthsAgo
        };
      }
      break;
    case 'Django':
      // Old versions have approaching EOL
      if (version.startsWith('2.')) {
        return {
          endOfLifeDate: sixMonthsAhead,
          endOfSupportDate: sixMonthsAhead
        };
      }
      break;
  }
  
  // Default - no EOL dates
  return {};
}

/**
 * Get framework vulnerabilities
 */
async function getFrameworkVulnerabilities(
  frameworkName: string,
  version: string,
  frameworkType: string
): Promise<VulnerabilityInfo[]> {
  // In a real implementation, this would query security advisories
  // For this example, we'll return mock data for one framework
  if (frameworkName === 'Spring Boot' && version.startsWith('2.')) {
    return [{
      id: 'CVE-2022-22965',
      cvssScore: 9.8,
      severity: 'critical',
      title: 'Spring Framework RCE via Data Binding',
      description: 'A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.',
      infoUrl: 'https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement',
      publishedDate: new Date('2022-03-31'),
      affectedVersions: '2.5.11+, 2.6.0-2.6.5',
      patchedVersions: '2.5.12+, 2.6.6+',
      recommendation: 'Upgrade to Spring Boot 2.6.6 or 2.5.12'
    }];
  }
  
  return [];
}

/**
 * Get framework migration path information
 */
async function getFrameworkMigrationPath(
  frameworkName: string,
  currentVersion: string,
  targetVersion: string
): Promise<string | undefined> {
  // In a real implementation, this would provide actual migration guides
  // For this example, we'll return mock data
  switch (frameworkName) {
    case 'Angular':
      return `https://update.angular.io/?v=${currentVersion}-${targetVersion}`;
    case 'React':
      return 'https://reactjs.org/blog/2022/03/08/react-18-upgrade-guide.html';
    case 'Vue.js':
      if (currentVersion.startsWith('2.') && targetVersion.startsWith('3.')) {
        return 'https://v3.vuejs.org/guide/migration/introduction.html';
      }
      break;
    case 'Django':
      return `https://docs.djangoproject.com/en/${targetVersion.split('.')[0]}.${targetVersion.split('.')[1]}/howto/upgrade-version/`;
  }
  
  return undefined;
}

/**
 * Estimate the effort required to migrate a framework
 */
function estimateMigrationEffort(
  frameworkName: string,
  currentVersion: string,
  targetVersion: string
): number {
  // Effort on a scale of 1-5
  // 1: Simple dependency update, minimal code changes
  // 2: Some code changes but straightforward
  // 3: Moderate refactoring needed
  // 4: Significant refactoring needed
  // 5: Major rewrite or architectural changes
  
  // Major version upgrades typically require more effort
  const currentMajor = parseInt(currentVersion.split('.')[0], 10);
  const targetMajor = parseInt(targetVersion.split('.')[0], 10);
  
  if (isNaN(currentMajor) || isNaN(targetMajor)) {
    return 3; // Default to moderate if version parsing fails
  }
  
  const majorVersionJump = targetMajor - currentMajor;
  
  if (majorVersionJump === 0) {
    return 1; // Minor or patch version upgrade
  }
  
  if (majorVersionJump === 1) {
    // One major version jump
    switch (frameworkName) {
      case 'Angular': return 4; // Angular major upgrades are significant
      case 'React': return 2; // React typically maintains better backward compatibility
      case 'Vue.js': return 3; // Vue 2 to 3 had breaking changes
      case 'Django': return 2; // Django has good upgrade paths
      case 'Spring Boot': return 3;
      default: return 2;
    }
  }
  
  if (majorVersionJump > 1) {
    // Multiple major version jumps
    switch (frameworkName) {
      case 'Angular': return 5; // Multiple Angular major upgrades are very difficult
      case 'React': return 3; // Multiple React versions still manageable
      case 'Vue.js': return 4; // Multiple Vue versions more challenging
      case 'Django': return 3; // Multiple Django versions require attention
      case 'Spring Boot': return 4;
      default: return 3;
    }
  }
  
  return 3; // Default to moderate
}

/**
 * Estimate the business impact of not updating a framework
 */
function estimateBusinessImpact(
  frameworkName: string,
  isOutdated: boolean,
  hasVulnerabilities: boolean,
  endOfLifeDate?: Date
): number {
  // Business impact on a scale of 1-5
  // 1: Minimal impact
  // 2: Minor impact
  // 3: Moderate impact
  // 4: Significant impact
  // 5: Critical business impact
  
  let score = 1;
  
  // Frameworks that have reached end of life
  if (endOfLifeDate && endOfLifeDate < new Date()) {
    score += 2;
  }
  
  // Frameworks approaching end of life (within 6 months)
  if (endOfLifeDate) {
    const sixMonthsLater = new Date();
    sixMonthsLater.setMonth(sixMonthsLater.getMonth() + 6);
    
    if (endOfLifeDate < sixMonthsLater) {
      score += 1;
    }
  }
  
  // Security vulnerabilities are a significant business risk
  if (hasVulnerabilities) {
    score += 2;
  }
  
  // Simply being outdated is a moderate risk
  if (isOutdated) {
    score += 1;
  }
  
  // Adjust based on framework type
  switch (frameworkName) {
    // Critical backend frameworks have higher business impact
    case 'Spring Boot':
    case 'Django':
    case 'Express.js':
      score += 1;
      break;
      
    // Database technologies can have significant impact on business
    case 'MongoDB':
    case 'MySQL':
    case 'PostgreSQL':
      score += 1;
      break;
  }
  
  // Cap at 5
  return Math.min(5, score);
}

/**
 * Estimate the security impact of not updating a framework
 */
function estimateSecurityImpact(
  frameworkName: string,
  vulnerabilities: VulnerabilityInfo[],
  endOfLifeDate?: Date
): number {
  // Security impact on a scale of 1-5
  // 1: Minimal security impact
  // 2: Minor security concerns
  // 3: Moderate security risks
  // 4: Significant security risks
  // 5: Critical security implications
  
  let score = 1;
  
  // End of life frameworks pose security risks
  if (endOfLifeDate && endOfLifeDate < new Date()) {
    score += 2;
  }
  
  // Score based on vulnerability severity
  if (vulnerabilities.length > 0) {
    let hasCritical = false;
    let hasHigh = false;
    let hasMedium = false;
    
    for (const vuln of vulnerabilities) {
      if (vuln.severity === 'critical') hasCritical = true;
      else if (vuln.severity === 'high') hasHigh = true;
      else if (vuln.severity === 'medium') hasMedium = true;
    }
    
    if (hasCritical) score += 3;
    else if (hasHigh) score += 2;
    else if (hasMedium) score += 1;
    
    // Multiple vulnerabilities increase the risk
    if (vulnerabilities.length > 5) score += 1;
  }
  
  // Certain frameworks have higher security impact when outdated
  switch (frameworkName) {
    // Security-critical frameworks
    case 'Spring Security':
    case 'Django':
    case 'Express.js':
      score += 1;
      break;
  }
  
  // Cap at 5
  return Math.min(5, score);
}
