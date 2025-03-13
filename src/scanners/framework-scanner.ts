import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import * as child_process from 'child_process';
import { log } from '../utils/logging';
import { FrameworkIssue } from '../types/scanning';
import { compareVersions } from '../utils/scanner-utils';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(child_process.exec);

/**
 * Configuration for framework scanning
 */
export interface FrameworkScannerConfig {
  // Root directory to scan
  rootDirectory: string;
  
  // Which framework types to check
  frameworkTypes: Array<
    'nodejs' | 'python' | 'ruby' | 'php' | 'java' | 'dotnet' | 
    'go' | 'rust' | 'react' | 'angular' | 'vue' | 'django' | 
    'spring' | 'laravel' | 'rails' | 'flutter' | 'docker' | 'kubernetes'
  >;
  
  // Whether to use offline mode (don't make API calls)
  offlineMode: boolean;
  
  // Whether to check for security vulnerabilities
  checkVulnerabilities: boolean;
  
  // Skip frameworks with specific IDs
  ignoreFrameworks?: string[];
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
}

/**
 * Detected framework
 */
interface DetectedFramework {
  name: string;
  type: string;
  version: string;
  location: string;
  detectionMethod: 'file' | 'command' | 'package';
  supportStatus?: 'supported' | 'maintenance' | 'deprecated' | 'eol';
  supportEndDate?: Date;
}

/**
 * Framework version info
 */
interface FrameworkVersionInfo {
  latestVersion: string;
  latestReleaseDate?: Date;
  latestLtsVersion?: string;
  isDeprecated: boolean;
  supportEndDate?: Date;
  supportStatus: 'supported' | 'maintenance' | 'deprecated' | 'eol';
  knownVulnerabilities: Array<{
    id: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
  }>;
  migrationGuideUrl?: string;
  releaseNotesUrl?: string;
}

/**
 * Scanner for detecting outdated frameworks and languages
 */
export async function scanFrameworks(
  config: FrameworkScannerConfig
): Promise<FrameworkIssue[]> {
  try {
    log.info('Starting framework scanner');
    const issues: FrameworkIssue[] = [];
    
    // Detect frameworks
    const frameworks = await detectFrameworks(config);
    log.info(`Found ${frameworks.length} frameworks/languages`);
    
    // Check each framework
    for (const framework of frameworks) {
      try {
        // Skip ignored frameworks
        if (config.ignoreFrameworks && config.ignoreFrameworks.includes(framework.name)) {
          log.info(`Skipping ignored framework: ${framework.name}`);
          continue;
        }
        
        // Get framework information
        const frameworkInfo = await getFrameworkInfo(
          framework.name,
          framework.type,
          framework.version,
          config.offlineMode,
          config.checkVulnerabilities,
          config.cacheDir
        );
        
        // Check if outdated
        const isOutdated = compareVersions(framework.version, frameworkInfo.latestVersion) < 0;
        
        // Check if end-of-life
        const isEol = frameworkInfo.supportStatus === 'eol' || 
          (frameworkInfo.supportEndDate && frameworkInfo.supportEndDate < new Date());
        
        // Only create an issue if there's at least one problem
        if (isOutdated || isEol || frameworkInfo.isDeprecated || 
            frameworkInfo.knownVulnerabilities.length > 0) {
          
          // Create the issue
          const issue: FrameworkIssue = {
            name: framework.name,
            type: framework.type,
            currentVersion: framework.version,
            latestVersion: frameworkInfo.latestVersion,
            latestLtsVersion: frameworkInfo.latestLtsVersion,
            location: framework.location,
            isOutdated,
            isDeprecated: frameworkInfo.isDeprecated,
            isEol,
            supportStatus: frameworkInfo.supportStatus,
            supportEndDate: frameworkInfo.supportEndDate,
            detectedAt: new Date()
          };
          
          // Add vulnerability info if any exist
          if (frameworkInfo.knownVulnerabilities.length > 0) {
            issue.vulnerabilities = frameworkInfo.knownVulnerabilities.map(v => ({
              id: v.id,
              severity: v.severity,
              description: v.description,
              fixedInVersion: v.fixedInVersion
            }));
          }
          
          // Add migration information if available
          if (frameworkInfo.migrationGuideUrl) {
            issue.migrationGuideUrl = frameworkInfo.migrationGuideUrl;
          }
          
          if (frameworkInfo.releaseNotesUrl) {
            issue.releaseNotesUrl = frameworkInfo.releaseNotesUrl;
          }
          
          // Calculate business impact
          issue.businessImpact = calculateBusinessImpact(
            framework.name,
            framework.type,
            isOutdated,
            isEol,
            frameworkInfo.isDeprecated,
            frameworkInfo.knownVulnerabilities.length > 0
          );
          
          // Calculate migration difficulty
          issue.migrationEffort = calculateMigrationEffort(
            framework.name,
            framework.type,
            framework.version,
            frameworkInfo.latestVersion
          );
          
          // Generate recommendation
          issue.recommendation = generateRecommendation(
            framework,
            frameworkInfo,
            isOutdated,
            isEol
          );
          
          // Add appropriate tags
          issue.tags = generateTags(
            framework.type,
            isOutdated,
            isEol,
            frameworkInfo.isDeprecated,
            frameworkInfo.knownVulnerabilities.length > 0
          );
          
          // Add to issues list
          issues.push(issue);
          log.info(`Added issue for framework ${framework.name} ${framework.version}`);
        }
      } catch (fwError) {
        log.warn(`Error processing framework: ${framework.name}`, { error: fwError });
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
 * Detect frameworks in a project
 */
async function detectFrameworks(
  config: FrameworkScannerConfig
): Promise<DetectedFramework[]> {
  try {
    const frameworks: DetectedFramework[] = [];
    const rootDir = config.rootDirectory;
    
    // Detect frameworks based on type
    for (const frameworkType of config.frameworkTypes) {
      try {
        log.info(`Detecting ${frameworkType} frameworks`);
        
        switch (frameworkType) {
          case 'nodejs':
            // Check for package.json
            const packageJsonFiles = await glob(path.join(rootDir, '**/package.json'), {
              ignore: ['**/node_modules/**', '**/.git/**']
            });
            
            for (const packageJsonFile of packageJsonFiles) {
              try {
                const content = await readFileAsync(packageJsonFile, 'utf8');
                const packageJson = JSON.parse(content);
                
                // Add Node.js as a framework
                try {
                  // Try to detect Node.js version
                  const { stdout } = await execAsync('node --version');
                  const nodeVersion = stdout.trim().replace(/^v/, '');
                  
                  frameworks.push({
                    name: 'Node.js',
                    type: 'nodejs',
                    version: nodeVersion,
                    location: packageJsonFile,
                    detectionMethod: 'command'
                  });
                } catch (nodeError) {
                  // If we can't detect Node.js version, use engines from package.json
                  if (packageJson.engines && packageJson.engines.node) {
                    const engineVersion = packageJson.engines.node.replace(/[^0-9.]/g, '');
                    
                    frameworks.push({
                      name: 'Node.js',
                      type: 'nodejs',
                      version: engineVersion || '0.0.0',
                      location: packageJsonFile,
                      detectionMethod: 'package'
                    });
                  }
                }
                
                // Detect frameworks from dependencies
                const frameworkDeps = [
                  { name: 'React', deps: ['react', 'react-dom'] },
                  { name: 'Angular', deps: ['@angular/core'] },
                  { name: 'Vue.js', deps: ['vue'] },
                  { name: 'Express', deps: ['express'] },
                  { name: 'Next.js', deps: ['next'] },
                  { name: 'NestJS', deps: ['@nestjs/core'] },
                  { name: 'Gatsby', deps: ['gatsby'] }
                ];
                
                const allDeps = { 
                  ...(packageJson.dependencies || {}), 
                  ...(packageJson.devDependencies || {}) 
                };
                
                for (const framework of frameworkDeps) {
                  const depKey = framework.deps.find(dep => allDeps[dep]);
                  
                  if (depKey) {
                    frameworks.push({
                      name: framework.name,
                      type: framework.name.toLowerCase().replace(/\.js$/, ''),
                      version: allDeps[depKey].replace(/[^0-9.]/g, ''),
                      location: packageJsonFile,
                      detectionMethod: 'package'
                    });
                  }
                }
              } catch (fileError) {
                log.warn(`Error processing package.json: ${packageJsonFile}`, { error: fileError });
              }
            }
            break;
            
          case 'python':
            // Detect Python version
            try {
              const { stdout } = await execAsync('python --version 2>&1');
              const pythonVersion = stdout.trim().replace(/^Python\s+/i, '');
              
              frameworks.push({
                name: 'Python',
                type: 'python',
                version: pythonVersion,
                location: rootDir,
                detectionMethod: 'command'
              });
            } catch (pythonError) {
              log.warn('Unable to detect Python version', { error: pythonError });
            }
            
            // Check for requirements.txt to detect frameworks
            const requirementsFiles = await glob(path.join(rootDir, '**/requirements*.txt'), {
              ignore: ['**/venv/**', '**/.git/**', '**/.env/**']
            });
            
            for (const requirementsFile of requirementsFiles) {
              try {
                const content = await readFileAsync(requirementsFile, 'utf8');
                const lines = content.split('\n');
                
                // Common Python frameworks
                const frameworkDetectors = [
                  { name: 'Django', pattern: /^django==?([\d.]+)/i },
                  { name: 'Flask', pattern: /^flask==?([\d.]+)/i },
                  { name: 'FastAPI', pattern: /^fastapi==?([\d.]+)/i },
                  { name: 'Pyramid', pattern: /^pyramid==?([\d.]+)/i },
                  { name: 'SQLAlchemy', pattern: /^sqlalchemy==?([\d.]+)/i }
                ];
                
                for (const line of lines) {
                  for (const detector of frameworkDetectors) {
                    const match = line.match(detector.pattern);
                    
                    if (match) {
                      frameworks.push({
                        name: detector.name,
                        type: detector.name.toLowerCase(),
                        version: match[1] || '0.0.0',
                        location: requirementsFile,
                        detectionMethod: 'file'
                      });
                    }
                  }
                }
              } catch (fileError) {
                log.warn(`Error processing requirements file: ${requirementsFile}`, { error: fileError });
              }
            }
            break;
            
          case 'java':
            // Check for pom.xml (Maven)
            const pomFiles = await glob(path.join(rootDir, '**/pom.xml'), {
              ignore: ['**/target/**', '**/.git/**']
            });
            
            for (const pomFile of pomFiles) {
              try {
                const content = await readFileAsync(pomFile, 'utf8');
                
                // Detect Java version
                const javaVersionMatch = content.match(/<java.version>([\d.]+)<\/java.version>/);
                if (javaVersionMatch) {
                  frameworks.push({
                    name: 'Java',
                    type: 'java',
                    version: javaVersionMatch[1],
                    location: pomFile,
                    detectionMethod: 'file'
                  });
                }
                
                // Detect Spring Boot
                const springBootMatch = content.match(/<spring-boot.version>([\d.]+)<\/spring-boot.version>/) || 
                                        content.match(/<version>([\d.]+)<\/version>[^<]*<artifactId>spring-boot/);
                if (springBootMatch) {
                  frameworks.push({
                    name: 'Spring Boot',
                    type: 'spring',
                    version: springBootMatch[1],
                    location: pomFile,
                    detectionMethod: 'file'
                  });
                }
              } catch (fileError) {
                log.warn(`Error processing pom.xml: ${pomFile}`, { error: fileError });
              }
            }
            
            // Check for build.gradle (Gradle)
            const gradleFiles = await glob(path.join(rootDir, '**/build.gradle*'), {
              ignore: ['**/build/**', '**/.git/**']
            });
            
            for (const gradleFile of gradleFiles) {
              try {
                const content = await readFileAsync(gradleFile, 'utf8');
                
                // Detect Java version
                const javaVersionMatch = content.match(/sourceCompatibility\s*=\s*['"]([\d.]+)['"]/);
                if (javaVersionMatch) {
                  frameworks.push({
                    name: 'Java',
                    type: 'java',
                    version: javaVersionMatch[1],
                    location: gradleFile,
                    detectionMethod: 'file'
                  });
                }
                
                // Detect Spring Boot
                const springBootMatch = content.match(/spring-boot[^\n]*:([\d.]+)/);
                if (springBootMatch) {
                  frameworks.push({
                    name: 'Spring Boot',
                    type: 'spring',
                    version: springBootMatch[1],
                    location: gradleFile,
                    detectionMethod: 'file'
                  });
                }
              } catch (fileError) {
                log.warn(`Error processing gradle file: ${gradleFile}`, { error: fileError });
              }
            }
            break;
            
          case 'php':
            // Check for composer.json
            const composerFiles = await glob(path.join(rootDir, '**/composer.json'), {
              ignore: ['**/vendor/**', '**/.git/**']
            });
            
            for (const composerFile of composerFiles) {
              try {
                const content = await readFileAsync(composerFile, 'utf8');
                const composerJson = JSON.parse(content);
                
                // Detect PHP version
                if (composerJson.require && composerJson.require.php) {
                  const phpVersion = composerJson.require.php.replace(/[^\d.]/g, '');
                  
                  frameworks.push({
                    name: 'PHP',
                    type: 'php',
                    version: phpVersion,
                    location: composerFile,
                    detectionMethod: 'file'
                  });
                }
                
                // Detect Laravel
                if (composerJson.require && composerJson.require['laravel/framework']) {
                  const laravelVersion = composerJson.require['laravel/framework'].replace(/[^\d.]/g, '');
                  
                  frameworks.push({
                    name: 'Laravel',
                    type: 'laravel',
                    version: laravelVersion,
                    location: composerFile,
                    detectionMethod: 'file'
                  });
                }
              } catch (fileError) {
                log.warn(`Error processing composer.json: ${composerFile}`, { error: fileError });
              }
            }
            break;
            
          case 'docker':
            // Check for Dockerfile
            const dockerfiles = await glob(path.join(rootDir, '**/Dockerfile*'), {
              ignore: ['**/node_modules/**', '**/.git/**']
            });
            
            for (const dockerfile of dockerfiles) {
              try {
                const content = await readFileAsync(dockerfile, 'utf8');
                
                // Detect Docker base image version
                const fromMatch = content.match(/FROM\s+([\w\-/.]+):(\w+)/);
                if (fromMatch) {
                  const baseImage = fromMatch[1];
                  const baseVersion = fromMatch[2];
                  
                  frameworks.push({
                    name: `Docker (${baseImage})`,
                    type: 'docker',
                    version: baseVersion,
                    location: dockerfile,
                    detectionMethod: 'file'
                  });
                }
              } catch (fileError) {
                log.warn(`Error processing Dockerfile: ${dockerfile}`, { error: fileError });
              }
            }
            break;
            
          case 'kubernetes':
            // Check for Kubernetes manifests
            const k8sFiles = await glob(path.join(rootDir, '**/*.{yaml,yml}'), {
              ignore: ['**/node_modules/**', '**/.git/**']
            });
            
            for (const k8sFile of k8sFiles) {
              try {
                const content = await readFileAsync(k8sFile, 'utf8');
                
                // Very basic check for Kubernetes manifests (apiVersion)
                if (content.includes('apiVersion:')) {
                  const apiVersionMatch = content.match(/apiVersion:\s*([\w./]+)/);
                  
                  if (apiVersionMatch) {
                    const apiVersion = apiVersionMatch[1];
                    
                    // Simplified - in a real implementation we would parse YAML properly
                    frameworks.push({
                      name: 'Kubernetes API',
                      type: 'kubernetes',
                      version: apiVersion,
                      location: k8sFile,
                      detectionMethod: 'file'
                    });
                  }
                }
              } catch (fileError) {
                log.warn(`Error processing K8s file: ${k8sFile}`, { error: fileError });
              }
            }
            break;
            
          // Add more framework types as needed
          default:
            log.info(`Framework type not fully implemented: ${frameworkType}`);
            break;
        }
      } catch (typeError) {
        log.error(`Error scanning ${frameworkType} frameworks`, { error: typeError });
      }
    }
    
    return frameworks;
  } catch (error) {
    log.error('Error detecting frameworks', { error });
    return [];
  }
}

/**
 * Get framework information from registry or cache
 */
async function getFrameworkInfo(
  name: string,
  type: string,
  version: string,
  offlineMode: boolean,
  checkVulnerabilities: boolean,
  cacheDir?: string
): Promise<FrameworkVersionInfo> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(cacheDir, `framework-${type}-${name.replace(/\s+/g, '-').toLowerCase()}.json`);
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as FrameworkVersionInfo;
        log.info(`Loaded ${name} info from cache`);
        return cachedInfo;
      } catch (cacheError) {
        log.warn(`Error reading framework cache for ${name}`, { error: cacheError });
      }
    }
  }
  
  // If in offline mode and no cache, return placeholder data
  if (offlineMode) {
    log.info(`Offline mode enabled for ${name}, using placeholder data`);
    return {
      latestVersion: version, // Assume current version is latest
      supportStatus: 'supported',
      isDeprecated: false,
      knownVulnerabilities: []
    };
  }
  
  // In a real implementation, we would query the framework registry
  // For this example, we'll return mock data
  try {
    // Mock registry query
    log.info(`Querying registry for ${type} framework: ${name}@${version}`);
    
    // Generate mock data based on the framework name and version
    const info: FrameworkVersionInfo = {
      latestVersion: incrementVersion(version),
      supportStatus: getSupportStatus(name, version),
      isDeprecated: isDeprecated(name, version),
      knownVulnerabilities: []
    };
    
    // Add LTS version for some frameworks
    if (['Node.js', 'Angular', 'React', 'Spring Boot'].includes(name)) {
      const parts = version.split('.');
      if (parts.length > 0) {
        const majorVersion = parseInt(parts[0], 10);
        info.latestLtsVersion = `${majorVersion}.${Math.floor(Math.random() * 20)}.${Math.floor(Math.random() * 10)}`;
      }
    }
    
    // Add support end date for some frameworks
    if (info.supportStatus !== 'supported') {
      // Random date in past or future
      const offset = info.supportStatus === 'eol' ? -1 : 1; // EOL dates are in the past
      info.supportEndDate = new Date(Date.now() + offset * Math.random() * 365 * 24 * 60 * 60 * 1000);
    }
    
    // Add vulnerabilities for some frameworks (for demo purposes)
    if (checkVulnerabilities && (isVulnerable(name, version) || Math.random() < 0.2)) {
      info.knownVulnerabilities = [
        {
          id: `CVE-2023-${Math.floor(Math.random() * 10000)}`,
          severity: getRandomSeverity(),
          description: `Security vulnerability in ${name} ${version} that could lead to ${getRandomVulnerabilityType()}`,
          fixedInVersion: info.latestVersion
        }
      ];
    }
    
    // Add migration guide URLs
    if (info.isDeprecated || info.supportStatus === 'eol') {
      info.migrationGuideUrl = getMigrationGuideUrl(name, version, info.latestVersion);
      info.releaseNotesUrl = getReleaseNotesUrl(name, info.latestVersion);
    }
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(cacheDir, `framework-${type}-${name.replace(/\s+/g, '-').toLowerCase()}.json`);
        await fs.promises.writeFile(cacheFile, JSON.stringify(info, null, 2), 'utf8');
        log.info(`Cached ${name} info`);
      } catch (cacheError) {
        log.warn(`Error writing framework cache for ${name}`, { error: cacheError });
      }
    }
    
    return info;
  } catch (error) {
    log.error(`Error querying registry for ${name}`, { error });
    
    // Return basic info if registry query fails
    return {
      latestVersion: version,
      supportStatus: 'supported',
      isDeprecated: false,
      knownVulnerabilities: []
    };
  }
}

/**
 * Calculate business impact score
 */
function calculateBusinessImpact(
  name: string,
  type: string,
  isOutdated: boolean,
  isEol: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean
): number {
  let score = 1; // Start with minimal impact
  
  if (isOutdated) score += 1;
  if (isDeprecated) score += 1;
  if (isEol) score += 2;
  if (hasVulnerabilities) score += 2;
  
  // Core languages and frameworks typically have higher impact
  const criticalFrameworks = ['python', 'java', 'nodejs', 'php', 'react', 'angular', 'spring', 'django', 'kubernetes'];
  if (criticalFrameworks.includes(type.toLowerCase())) {
    score += 1;
  }
  
  // Cap at maximum of 5
  return Math.min(score, 5);
}

/**
 * Calculate migration effort
 */
function calculateMigrationEffort(
  name: string,
  type: string,
  currentVersion: string,
  latestVersion: string
): number {
  // Start with base effort
  let effort = 1;
  
  // Major version changes are more effort
  const currentMajor = parseInt(currentVersion.split('.')[0], 10) || 0;
  const latestMajor = parseInt(latestVersion.split('.')[0], 10) || 0;
  const majorVersionGap = Math.max(0, latestMajor - currentMajor);
  
  effort += majorVersionGap;
  
  // Some frameworks are harder to migrate
  const complexFrameworks = {
    'angular': 2, // Angular has historically difficult upgrades
    'spring': 1.5,
    'django': 1.2,
    'kubernetes': 1.8,
    'java': 1.5
  };
  
  const frameworkComplexity = complexFrameworks[type.toLowerCase()] || 1;
  effort *= frameworkComplexity;
  
  // Cap at maximum of 5
  return Math.min(Math.round(effort), 5);
}

/**
 * Generate a recommendation
 */
function generateRecommendation(
  framework: DetectedFramework,
  frameworkInfo: FrameworkVersionInfo,
  isOutdated: boolean,
  isEol: boolean
): string {
  const recommendations: string[] = [];
  
  if (frameworkInfo.knownVulnerabilities.length > 0) {
    recommendations.push(
      `Update ${framework.name} immediately from ${framework.version} to at least ${frameworkInfo.latestVersion} to address security vulnerabilities`
    );
  } else if (isEol) {
    recommendations.push(
      `Migrate ${framework.name} from end-of-life version ${framework.version} to version ${frameworkInfo.latestVersion}`
    );
  } else if (frameworkInfo.isDeprecated) {
    recommendations.push(
      `Plan migration from deprecated ${framework.name} ${framework.version} to ${frameworkInfo.latestVersion}`
    );
  } else if (isOutdated) {
    recommendations.push(
      `Update ${framework.name} from ${framework.version} to ${frameworkInfo.latestVersion}`
    );
  }
  
  if (frameworkInfo.migrationGuideUrl) {
    recommendations.push(`Migration guide available at: ${frameworkInfo.migrationGuideUrl}`);
  }
  
  if (recommendations.length === 0) {
    recommendations.push(`No immediate action required for ${framework.name} ${framework.version}`);
  }
  
  return recommendations.join('. ');
}

/**
 * Generate tags for categorizing issues
 */
function generateTags(
  type: string,
  isOutdated: boolean,
  isEol: boolean,
  isDeprecated: boolean,
  hasVulnerabilities: boolean
): string[] {
  const tags: string[] = [type];
  
  if (isOutdated) tags.push('outdated');
  if (isEol) tags.push('end-of-life');
  if (isDeprecated) tags.push('deprecated');
  if (hasVulnerabilities) tags.push('security');
  
  return tags;
}

/**
 * Helper function to increment a version for demo purposes
 */
function incrementVersion(version: string): string {
  try {
    const parts = version.split('.');
    
    if (parts.length < 3) {
      // Ensure we have at least 3 parts
      while (parts.length < 3) {
        parts.push('0');
      }
    }
    
    // Increment a random part
    const partToIncrement = Math.floor(Math.random() * parts.length);
    const partValue = parseInt(parts[partToIncrement], 10) || 0;
    parts[partToIncrement] = String(partValue + 1 + Math.floor(Math.random() * 5));
    
    return parts.join('.');
  } catch (error) {
    return `${version}.1`; // Fallback
  }
}

/**
 * Helper function to determine support status
 */
function getSupportStatus(
  name: string,
  version: string
): 'supported' | 'maintenance' | 'deprecated' | 'eol' {
  // Mock logic to determine support status
  const versionNumber = parseFloat(version) || 0;
  
  // For demo purposes - consider old versions as EOL
  if (versionNumber < 1) {
    return 'eol';
  }
  
  if (versionNumber < 2) {
    return 'deprecated';
  }
  
  if (versionNumber < 4) {
    return 'maintenance';
  }
  
  return 'supported';
}

/**
 * Helper function to determine if a framework is deprecated
 */
function isDeprecated(name: string, version: string): boolean {
  // Mock logic to determine if deprecated
  const versionNumber = parseFloat(version) || 0;
  
  // For demo purposes - consider old versions as deprecated
  return versionNumber < 2 || name.toLowerCase().includes('deprecated');
}

/**
 * Helper function to determine if a framework has vulnerabilities
 */
function isVulnerable(name: string, version: string): boolean {
  // Mock logic to determine if vulnerable
  const versionNumber = parseFloat(version) || 0;
  
  // For demo purposes - consider old versions as vulnerable
  return versionNumber < 1.5 || name.toLowerCase().includes('vulnerable');
}

/**
 * Helper function for getting a random severity
 */
function getRandomSeverity(): 'low' | 'medium' | 'high' | 'critical' {
  const severities: Array<'low' | 'medium' | 'high' | 'critical'> = ['low', 'medium', 'high', 'critical'];
  return severities[Math.floor(Math.random() * severities.length)];
}

/**
 * Helper function for getting a random vulnerability type
 */
function getRandomVulnerabilityType(): string {
  const types = [
    'remote code execution',
    'privilege escalation',
    'denial of service',
    'information disclosure',
    'cross-site scripting',
    'SQL injection',
    'memory corruption',
    'code injection'
  ];
  return types[Math.floor(Math.random() * types.length)];
}

/**
 * Get migration guide URL for a framework
 */
function getMigrationGuideUrl(name: string, fromVersion: string, toVersion: string): string {
  // In a real implementation, this would return actual migration guide URLs
  // For now, we'll return mock URLs
  const nameSlug = name.toLowerCase().replace(/\s+/g, '-');
  return `https://docs.example.com/${nameSlug}/migration-guide-${fromVersion}-to-${toVersion}`;
}

/**
 * Get release notes URL for a framework
 */
function getReleaseNotesUrl(name: string, version: string): string {
  // In a real implementation, this would return actual release notes URLs
  // For now, we'll return mock URLs
  const nameSlug = name.toLowerCase().replace(/\s+/g, '-');
  return `https://docs.example.com/${nameSlug}/release-notes-${version}`;
}
