import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { exec } from 'child_process';
import { glob } from 'glob';
import { log } from '../utils/logging';
import { FrameworkIssue, ScannerConfig } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(exec);

/**
 * Configuration specific to framework scanning
 */
export interface FrameworkScannerConfig extends ScannerConfig {
  // Framework and tech stack types to scan
  frameworkTypes?: Array<
    | 'frontend'
    | 'backend'
    | 'database'
    | 'cloud'
    | 'mobile'
    | 'desktop'
    | 'devops'
    | 'testing'
    | 'security'
    | 'ml'
    | 'ai'
    | 'iot'
  >;
  
  // Programming languages to include in scan
  languages?: string[];
  
  // Custom framework knowledge base path
  knowledgeBasePath?: string;
  
  // Whether to check for known vulnerabilities
  checkVulnerabilities?: boolean;
  
  // Whether to assess migration complexity
  assessMigrationComplexity?: boolean;
  
  // Custom vulnerability database paths
  vulnerabilityDbPaths?: {
    frameworks?: string;
  };
  
  // Frameworks to exclude from scanning
  excludeFrameworks?: string[];
  
  // Whether to examine git history for framework usage patterns
  examineGitHistory?: boolean;
  
  // Maximum depth of file scanning
  maxScanDepth?: number;
  
  // Whether to scan remote resources (e.g., deployed applications)
  scanRemoteResources?: boolean;
  
  // Remote endpoints to scan (if scanRemoteResources is true)
  remoteEndpoints?: {
    url: string;
    type: string;
    auth?: {
      type: 'basic' | 'token' | 'oauth';
      credentials: string; // token or base64 encoded username:password for basic auth
    };
  }[];
}

/**
 * Information about a framework or technology
 */
interface FrameworkInfo {
  name: string;
  version?: string;
  type: string; // frontend, backend, database, etc.
  language?: string; // javascript, python, java, etc.
  detectionMethod: 'manifest' | 'code-scan' | 'build-artifacts' | 'git-history' | 'remote-scan';
  detectionConfidence: number; // 0.0 to 1.0
  location?: string; // file path or URL where detected
  latestVersion?: string;
  isOutdated?: boolean;
  isVulnerable?: boolean;
  isDeprecated?: boolean;
  isEndOfLife?: boolean;
  endOfLifeDate?: Date;
  lastUpdated?: Date;
  usageExtent?: number; // 0.0 to 1.0, how much this framework is used in the codebase
  usageFiles?: string[]; // files using this framework
  dependentComponents?: string[]; // other components that depend on this framework
  documentationUrl?: string;
  upgradeGuideUrl?: string;
  vulnerabilities?: {
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    cveIds?: string[];
    affectedVersions?: string;
    fixedInVersion?: string;
    url?: string;
  }[];
  migrationComplexity?: {
    level: 'low' | 'medium' | 'high' | 'very-high';
    factors: string[];
    estimatedEffortDays?: number;
    potentialIssues?: string[];
    requiredSkills?: string[];
  };
  endOfLifeDetails?: {
    announcementDate?: Date;
    endOfLifeUrl?: string;
    recommendedAlternatives?: string[];
    migrationPath?: string;
  };
}

/**
 * Main function to scan for outdated frameworks and technologies
 */
export async function scanFrameworks(
  config: FrameworkScannerConfig
): Promise<FrameworkIssue[]> {
  try {
    log.info('Starting framework and technology scanner');
    const issues: FrameworkIssue[] = [];
    
    // Determine which types of frameworks to scan
    const frameworkTypes = config.frameworkTypes || [
      'frontend', 'backend', 'database', 'cloud',
      'mobile', 'desktop', 'devops', 'testing',
      'security', 'ml', 'ai', 'iot'
    ];
    log.info(`Scanning for frameworks of types: ${frameworkTypes.join(', ')}`);
    
    // Collect frameworks from various detection methods
    const frameworks: FrameworkInfo[] = [];
    
    // Scan manifest files (package.json, requirements.txt, pom.xml, etc.)
    try {
      log.info('Scanning manifest files for frameworks');
      const manifestFrameworks = await detectFrameworksFromManifests(config);
      frameworks.push(...manifestFrameworks);
      log.info(`Found ${manifestFrameworks.length} frameworks from manifest files`);
    } catch (manifestError) {
      log.error('Error detecting frameworks from manifests', { error: manifestError });
    }
    
    // Scan code files for imports and usage patterns
    try {
      log.info('Scanning code files for framework usage');
      const codeFrameworks = await detectFrameworksFromCode(config);
      frameworks.push(...codeFrameworks);
      log.info(`Found ${codeFrameworks.length} frameworks from code scanning`);
    } catch (codeError) {
      log.error('Error detecting frameworks from code', { error: codeError });
    }
    
    // Scan build artifacts (if available)
    try {
      log.info('Scanning build artifacts for frameworks');
      const artifactFrameworks = await detectFrameworksFromArtifacts(config);
      frameworks.push(...artifactFrameworks);
      log.info(`Found ${artifactFrameworks.length} frameworks from build artifacts`);
    } catch (artifactError) {
      log.error('Error detecting frameworks from artifacts', { error: artifactError });
    }
    
    // Examine git history for framework usage patterns (if configured)
    if (config.examineGitHistory) {
      try {
        log.info('Examining git history for framework usage');
        const gitFrameworks = await detectFrameworksFromGitHistory(config);
        frameworks.push(...gitFrameworks);
        log.info(`Found ${gitFrameworks.length} frameworks from git history`);
      } catch (gitError) {
        log.error('Error detecting frameworks from git history', { error: gitError });
      }
    }
    
    // Scan remote resources (if configured)
    if (config.scanRemoteResources && config.remoteEndpoints) {
      try {
        log.info('Scanning remote endpoints for frameworks');
        const remoteFrameworks = await detectFrameworksFromRemote(config);
        frameworks.push(...remoteFrameworks);
        log.info(`Found ${remoteFrameworks.length} frameworks from remote scanning`);
      } catch (remoteError) {
        log.error('Error detecting frameworks from remote endpoints', { error: remoteError });
      }
    }
    
    log.info(`Found total of ${frameworks.length} frameworks to analyze`);
    
    // Deduplicate frameworks (same framework detected by multiple methods)
    const uniqueFrameworks = deduplicateFrameworks(frameworks);
    log.info(`After deduplication, analyzing ${uniqueFrameworks.length} unique frameworks`);
    
    // Filter frameworks based on type if specified
    let filteredFrameworks = uniqueFrameworks;
    if (frameworkTypes.length < 12) { // if not all types are included
      filteredFrameworks = filteredFrameworks.filter(fw => 
        frameworkTypes.includes(fw.type as any)
      );
      log.info(`Filtered to ${filteredFrameworks.length} frameworks of specified types`);
    }
    
    // Filter by language if specified
    if (config.languages && config.languages.length > 0) {
      filteredFrameworks = filteredFrameworks.filter(fw => 
        !fw.language || config.languages!.includes(fw.language)
      );
      log.info(`Filtered to ${filteredFrameworks.length} frameworks in specified languages`);
    }
    
    // Filter out excluded frameworks
    if (config.excludeFrameworks && config.excludeFrameworks.length > 0) {
      filteredFrameworks = filteredFrameworks.filter(fw => {
        return !config.excludeFrameworks!.some(excluded => {
          if (excluded === fw.name) {
            return true;
          }
          if (excluded.includes('*')) {
            const pattern = excluded.replace(/\*/g, '.*');
            return new RegExp(`^${pattern}$`).test(fw.name);
          }
          return false;
        });
      });
      log.info(`Filtered out excluded frameworks, ${filteredFrameworks.length} remaining`);
    }
    
    // Process each framework
    for (const fw of filteredFrameworks) {
      try {
        log.info(`Checking framework: ${fw.name}${fw.version ? ` (${fw.version})` : ''} for ${fw.type}`);
        
        // Check for issues
        await checkFrameworkForIssues(fw, config);
        
        // Create issue for problematic frameworks
        if (fw.isOutdated || 
            fw.isVulnerable || 
            fw.isDeprecated || 
            fw.isEndOfLife) {
          
          const issue: FrameworkIssue = {
            detectedAt: new Date(),
            name: fw.name,
            type: fw.type,
            language: fw.language,
            currentVersion: fw.version,
            latestVersion: fw.latestVersion,
            isOutdated: fw.isOutdated || false,
            isVulnerable: fw.isVulnerable || false,
            vulnerabilities: fw.vulnerabilities || [],
            isDeprecated: fw.isDeprecated || false,
            isEndOfLife: fw.isEndOfLife || false,
            endOfLifeDate: fw.endOfLifeDate,
            endOfLifeDetails: fw.endOfLifeDetails,
            detectionMethod: fw.detectionMethod,
            detectionConfidence: fw.detectionConfidence,
            location: fw.location,
            usageExtent: fw.usageExtent,
            usageFiles: fw.usageFiles,
            migrationComplexity: fw.migrationComplexity,
            documentationUrl: fw.documentationUrl,
            upgradeGuideUrl: fw.upgradeGuideUrl,
            riskLevel: calculateRiskLevel(fw),
            recommendation: generateRecommendation(fw),
            tags: generateTags(fw)
          };
          
          issues.push(issue);
        }
      } catch (fwError) {
        log.error(`Error checking framework ${fw.name}`, { error: fwError });
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
 * Detect frameworks from manifest files
 */
async function detectFrameworksFromManifests(
  config: FrameworkScannerConfig
): Promise<FrameworkInfo[]> {
  const frameworks: FrameworkInfo[] = [];
  
  try {
    // Find package.json files (Node.js/JavaScript/TypeScript)
    const packageJsonPaths = await glob('**/package.json', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/node_modules/**',
        '**/bower_components/**',
        '**/dist/**',
        '**/build/**'
      ]
    });
    
    // Process each package.json
    for (const packageJsonPath of packageJsonPaths) {
      try {
        const content = await readFileAsync(packageJsonPath, 'utf8');
        const packageJson = JSON.parse(content);
        
        // Map of known frameworks to their types
        const jsFrameworks: Record<string, string> = {
          'react': 'frontend',
          'vue': 'frontend',
          'angular': 'frontend',
          'next': 'frontend',
          'nuxt': 'frontend',
          'svelte': 'frontend',
          'express': 'backend',
          'koa': 'backend',
          'hapi': 'backend',
          'nest': 'backend',
          'fastify': 'backend',
          'meteor': 'backend',
          'jquery': 'frontend',
          'bootstrap': 'frontend',
          'tailwindcss': 'frontend',
          'material-ui': 'frontend',
          '@mui/material': 'frontend',
          '@angular/core': 'frontend',
          '@nestjs/core': 'backend',
          'mongoose': 'database',
          'sequelize': 'database',
          'typeorm': 'database',
          'prisma': 'database',
          'electron': 'desktop',
          'react-native': 'mobile',
          'ionic': 'mobile',
          'capacitor': 'mobile',
          'cordova': 'mobile',
          'jest': 'testing',
          'mocha': 'testing',
          'cypress': 'testing',
          'tensorflow': 'ai',
          'aws-sdk': 'cloud',
          '@aws-sdk/client-s3': 'cloud',
          '@azure/storage-blob': 'cloud',
          '@google-cloud/storage': 'cloud',
          'firebase': 'cloud',
          'docker': 'devops',
          'kubernetes': 'devops',
          'helmet': 'security',
          'passport': 'security'
        };
        
        // Check dependencies
        const allDeps = {
          ...(packageJson.dependencies || {}),
          ...(packageJson.devDependencies || {})
        };
        
        for (const [name, versionStr] of Object.entries(allDeps)) {
          // Skip packages that don't match our known frameworks
          if (!jsFrameworks[name] && !Object.keys(jsFrameworks).some(fw => 
            name.startsWith(`${fw}/`) || name.startsWith(`${fw}-`)
          )) {
            // Still check for major frameworks by pattern
            const isFramework = (
              name.includes('framework') ||
              name.endsWith('-js') ||
              name.endsWith('-ts') ||
              name.includes('cloud') ||
              name.includes('ui-') ||
              name.includes('-ui') ||
              name.includes('-template') ||
              name.includes('-starter')
            );
            
            if (!isFramework) {
              continue;
            }
          }
          
          const version = String(versionStr).replace(/[^0-9.]/g, '');
          let type = 'frontend'; // Default type
          
          // Determine the type if it's a known framework
          if (jsFrameworks[name]) {
            type = jsFrameworks[name];
          } else {
            // Try to determine type from package name
            if (name.includes('server') || name.includes('backend') || name.includes('api')) {
              type = 'backend';
            } else if (name.includes('db') || name.includes('database') || name.includes('sql') || name.includes('storage')) {
              type = 'database';
            } else if (name.includes('test') || name.includes('spec') || name.includes('assert')) {
              type = 'testing';
            } else if (name.includes('aws') || name.includes('azure') || name.includes('cloud') || name.includes('firebase')) {
              type = 'cloud';
            } else if (name.includes('mobile') || name.includes('ios') || name.includes('android')) {
              type = 'mobile';
            } else if (name.includes('desktop') || name.includes('electron')) {
              type = 'desktop';
            } else if (name.includes('docker') || name.includes('kubernetes') || name.includes('deploy')) {
              type = 'devops';
            } else if (name.includes('security') || name.includes('auth') || name.includes('crypto')) {
              type = 'security';
            } else if (name.includes('ai') || name.includes('ml') || name.includes('tensorflow') || name.includes('torch')) {
              type = 'ai';
            }
          }
          
          frameworks.push({
            name,
            version,
            type,
            language: 'javascript', // or typescript potentially
            detectionMethod: 'manifest',
            detectionConfidence: 0.9,
            location: packageJsonPath,
            usageFiles: [packageJsonPath]
          });
        }
        
      } catch (packageJsonError) {
        log.warn(`Error processing package.json at ${packageJsonPath}`, { error: packageJsonError });
      }
    }
    
    // Find requirements.txt files (Python)
    const requirementsPaths = await glob('**/requirements{,.*}.txt', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/venv/**',
        '**/.venv/**',
        '**/env/**',
        '**/.env/**'
      ]
    });
    
    // Map of known Python frameworks to their types
    const pythonFrameworks: Record<string, string> = {
      'django': 'backend',
      'flask': 'backend',
      'fastapi': 'backend',
      'tornado': 'backend',
      'sqlalchemy': 'database',
      'django-rest-framework': 'backend',
      'numpy': 'ai',
      'pandas': 'ai',
      'scikit-learn': 'ai',
      'tensorflow': 'ai',
      'pytorch': 'ai',
      'torch': 'ai',
      'pytest': 'testing',
      'unittest': 'testing',
      'boto3': 'cloud',
      'azure-storage': 'cloud',
      'google-cloud-storage': 'cloud',
      'dash': 'frontend',
      'streamlit': 'frontend',
      'kivy': 'mobile',
      'requests': 'backend',
      'httpx': 'backend',
      'aiohttp': 'backend',
      'pyramid': 'backend',
      'celery': 'backend',
      'scrapy': 'backend',
      'dash': 'frontend',
      'pyspark': 'ai'
    };
    
    // Process each requirements.txt
    for (const requirementsPath of requirementsPaths) {
      try {
        const content = await readFileAsync(requirementsPath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Parse the requirement line
          const reqLine = line.split('#')[0].trim(); // Remove inline comments
          const parts = reqLine.split(/[=<>!~]+/);
          const name = parts[0].trim();
          const version = parts.length > 1 ? parts[1].trim() : undefined;
          
          // Skip packages that don't match our known frameworks
          if (!pythonFrameworks[name] && !Object.keys(pythonFrameworks).some(fw => 
            name.startsWith(`${fw}-`) || name.endsWith(`-${fw}`)
          )) {
            // Still check for major frameworks by pattern
            const isFramework = (
              name.includes('framework') ||
              name.includes('cloud') ||
              name.includes('-template') ||
              name.includes('-starter')
            );
            
            if (!isFramework) {
              continue;
            }
          }
          
          let type = 'backend'; // Default type for Python
          
          // Determine the type if it's a known framework
          if (pythonFrameworks[name]) {
            type = pythonFrameworks[name];
          } else {
            // Try to determine type from package name
            if (name.includes('api') || name.includes('server') || name.includes('web')) {
              type = 'backend';
            } else if (name.includes('db') || name.includes('database') || name.includes('sql')) {
              type = 'database';
            } else if (name.includes('test') || name.includes('pytest')) {
              type = 'testing';
            } else if (name.includes('aws') || name.includes('azure') || name.includes('cloud')) {
              type = 'cloud';
            } else if (name.includes('ui') || name.includes('gui') || name.includes('dashboard')) {
              type = 'frontend';
            } else if (name.includes('ml') || name.includes('ai') || name.includes('learn') || name.includes('neural')) {
              type = 'ai';
            }
          }
          
          frameworks.push({
            name,
            version,
            type,
            language: 'python',
            detectionMethod: 'manifest',
            detectionConfidence: 0.9,
            location: requirementsPath,
            usageFiles: [requirementsPath]
          });
        }
      } catch (requirementsError) {
        log.warn(`Error processing requirements.txt at ${requirementsPath}`, { error: requirementsError });
      }
    }
    
    // Find pom.xml files (Java/Maven)
    const pomPaths = await glob('**/pom.xml', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/target/**'
      ]
    });
    
    // Map of known Java frameworks to their types
    const javaFrameworks: Record<string, string> = {
      'org.springframework': 'backend',
      'org.springframework.boot': 'backend',
      'org.hibernate': 'database',
      'com.google.guava': 'backend',
      'javax.servlet': 'backend',
      'org.eclipse.jetty': 'backend',
      'com.fasterxml.jackson': 'backend',
      'org.apache.tomcat': 'backend',
      'org.junit': 'testing',
      'org.testng': 'testing',
      'org.mockito': 'testing',
      'com.amazonaws': 'cloud',
      'com.azure': 'cloud',
      'com.google.cloud': 'cloud',
      'org.apache.kafka': 'backend',
      'org.apache.hadoop': 'backend',
      'org.apache.spark': 'ai',
      'org.deeplearning4j': 'ai',
      'org.slf4j': 'backend',
      'io.vertx': 'backend',
      'io.quarkus': 'backend',
      'io.micronaut': 'backend',
      'org.apache.commons': 'backend',
      'org.apache.logging': 'backend',
      'com.zaxxer.hikari': 'database',
      'org.apache.maven': 'devops'
    };
    
    // Process each pom.xml
    for (const pomPath of pomPaths) {
      try {
        const content = await readFileAsync(pomPath, 'utf8');
        
        // Simple approach to extract dependencies - for a complete solution a proper XML parser would be better
        const dependencyMatches = content.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];
        
        for (const depMatch of dependencyMatches) {
          const groupIdMatch = depMatch.match(/<groupId>([^<]+)<\/groupId>/);
          const artifactIdMatch = depMatch.match(/<artifactId>([^<]+)<\/artifactId>/);
          const versionMatch = depMatch.match(/<version>([^<]+)<\/version>/);
          
          if (groupIdMatch && artifactIdMatch) {
            const groupId = groupIdMatch[1].trim();
            const artifactId = artifactIdMatch[1].trim();
            const version = versionMatch ? versionMatch[1].trim() : undefined;
            
            const name = `${groupId}:${artifactId}`;
            
            // Check if this is a known framework by checking the groupId
            let isKnownFramework = false;
            let type = 'backend'; // Default type for Java
            
            for (const [knownGroup, knownType] of Object.entries(javaFrameworks)) {
              if (groupId.startsWith(knownGroup)) {
                isKnownFramework = true;
                type = knownType;
                break;
              }
            }
            
            if (!isKnownFramework) {
              // Check for framework indicators in artifactId
              const isFramework = (
                artifactId.includes('framework') ||
                artifactId.includes('platform') ||
                artifactId.includes('starter') ||
                artifactId.includes('boot') ||
                artifactId.includes('server') ||
                artifactId.includes('cloud') ||
                artifactId.includes('template')
              );
              
              if (!isFramework) {
                continue;
              }
              
              // Try to determine type from artifact name
              if (artifactId.includes('db') || artifactId.includes('database') || artifactId.includes('jdbc') || artifactId.includes('sql')) {
                type = 'database';
              } else if (artifactId.includes('test')) {
                type = 'testing';
              } else if (artifactId.includes('aws') || artifactId.includes('azure') || artifactId.includes('cloud')) {
                type = 'cloud';
              } else if (artifactId.includes('ui') || artifactId.includes('web') || artifactId.includes('mvc')) {
                type = 'frontend';
              } else if (artifactId.includes('ml') || artifactId.includes('ai') || artifactId.includes('analytics')) {
                type = 'ai';
              }
            }
            
            frameworks.push({
              name,
              version,
              type,
              language: 'java',
              detectionMethod: 'manifest',
              detectionConfidence: 0.85,
              location: pomPath,
              usageFiles: [pomPath]
            });
          }
        }
      } catch (pomError) {
        log.warn(`Error processing pom.xml at ${pomPath}`, { error: pomError });
      }
    }
    
    // Find build.gradle files (Gradle)
    const gradlePaths = await glob('**/build.gradle{,.kts}', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/build/**'
      ]
    });
    
    // Process each build.gradle (similar to Maven approach)
    for (const gradlePath of gradlePaths) {
      try {
        const content = await readFileAsync(gradlePath, 'utf8');
        
        // Very basic parsing approach - a proper Gradle parser would be better
        const dependencyMatches = content.match(/(?:implementation|api|compile)(?:\s|\()(?:'|")([^:]+):([^:]+):([^'"]+)(?:'|")\)?/g) || [];
        
        for (const depMatch of dependencyMatches) {
          const parts = depMatch.match(/(?:implementation|api|compile)(?:\s|\()(?:'|")([^:]+):([^:]+):([^'"]+)(?:'|")\)?/);
          
          if (parts && parts.length >= 4) {
            const groupId = parts[1].trim();
            const artifactId = parts[2].trim();
            const version = parts[3].trim();
            
            const name = `${groupId}:${artifactId}`;
            
            // Same logic as Maven to identify frameworks
            let isKnownFramework = false;
            let type = 'backend'; // Default type for Java
            
            for (const [knownGroup, knownType] of Object.entries(javaFrameworks)) {
              if (groupId.startsWith(knownGroup)) {
                isKnownFramework = true;
                type = knownType;
                break;
              }
            }
            
            if (!isKnownFramework) {
              // Check for framework indicators in artifactId
              const isFramework = (
                artifactId.includes('framework') ||
                artifactId.includes('platform') ||
                artifactId.includes('starter') ||
                artifactId.includes('boot') ||
                artifactId.includes('server') ||
                artifactId.includes('cloud') ||
                artifactId.includes('template')
              );
              
              if (!isFramework) {
                continue;
              }
              
              // Same type detection logic as Maven
              if (artifactId.includes('db') || artifactId.includes('database') || artifactId.includes('jdbc') || artifactId.includes('sql')) {
                type = 'database';
              } else if (artifactId.includes('test')) {
                type = 'testing';
              } else if (artifactId.includes('aws') || artifactId.includes('azure') || artifactId.includes('cloud')) {
                type = 'cloud';
              } else if (artifactId.includes('ui') || artifactId.includes('web') || artifactId.includes('mvc')) {
                type = 'frontend';
              } else if (artifactId.includes('ml') || artifactId.includes('ai') || artifactId.includes('analytics')) {
                type = 'ai';
              }
            }
            
            frameworks.push({
              name,
              version,
              type,
              language: 'java',
              detectionMethod: 'manifest',
              detectionConfidence: 0.85,
              location: gradlePath,
              usageFiles: [gradlePath]
            });
          }
        }
      } catch (gradleError) {
        log.warn(`Error processing build.gradle at ${gradlePath}`, { error: gradleError });
      }
    }
    
    // Find Gemfile files (Ruby)
    const gemfilePaths = await glob('**/Gemfile', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || [])
      ]
    });
    
    // Map of known Ruby frameworks to their types
    const rubyFrameworks: Record<string, string> = {
      'rails': 'backend',
      'sinatra': 'backend',
      'hanami': 'backend',
      'roda': 'backend',
      'grape': 'backend',
      'activerecord': 'database',
      'sequel': 'database',
      'mongoid': 'database',
      'rspec': 'testing',
      'minitest': 'testing',
      'cucumber': 'testing',
      'aws-sdk': 'cloud',
      'azure-storage': 'cloud',
      'google-cloud': 'cloud',
      'devise': 'security',
      'pundit': 'security',
      'sidekiq': 'backend',
      'resque': 'backend',
      'capistrano': 'devops',
      'sass': 'frontend',
      'bootstrap': 'frontend',
      'jquery-rails': 'frontend'
    };
    
    // Process each Gemfile
    for (const gemfilePath of gemfilePaths) {
      try {
        const content = await readFileAsync(gemfilePath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Find gem declarations
          const gemMatch = line.match(/gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?/);
          
          if (gemMatch) {
            const name = gemMatch[1].trim();
            const version = gemMatch[2] ? gemMatch[2].trim() : undefined;
            
            // Skip gems that don't match our known frameworks
            if (!rubyFrameworks[name] && !Object.keys(rubyFrameworks).some(fw => 
              name.startsWith(`${fw}-`) || name.endsWith(`-${fw}`)
            )) {
              // Still check for major frameworks by pattern
              const isFramework = (
                name.includes('framework') ||
                name.includes('rails') ||
                name.includes('-template') ||
                name.includes('-starter')
              );
              
              if (!isFramework) {
                continue;
              }
            }
            
            let type = 'backend'; // Default type for Ruby
            
            // Determine the type if it's a known framework
            if (rubyFrameworks[name]) {
              type = rubyFrameworks[name];
            } else {
              // Try to determine type from gem name
              if (name.includes('api') || name.includes('server') || name.includes('web')) {
                type = 'backend';
              } else if (name.includes('db') || name.includes('database') || name.includes('sql')) {
                type = 'database';
              } else if (name.includes('test') || name.includes('spec')) {
                type = 'testing';
              } else if (name.includes('aws') || name.includes('azure') || name.includes('cloud')) {
                type = 'cloud';
              } else if (name.includes('ui') || name.includes('view') || name.includes('assets')) {
                type = 'frontend';
              }
            }
            
            frameworks.push({
              name,
              version,
              type,
              language: 'ruby',
              detectionMethod: 'manifest',
              detectionConfidence: 0.9,
              location: gemfilePath,
              usageFiles: [gemfilePath]
            });
          }
        }
      } catch (gemfileError) {
        log.warn(`Error processing Gemfile at ${gemfilePath}`, { error: gemfileError });
      }
    }
    
    // Find composer.json files (PHP)
    const composerPaths = await glob('**/composer.json', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/vendor/**'
      ]
    });
    
    // Map of known PHP frameworks to their types
    const phpFrameworks: Record<string, string> = {
      'laravel/framework': 'backend',
      'symfony/symfony': 'backend',
      'slim/slim': 'backend',
      'yiisoft/yii2': 'backend',
      'codeigniter/framework': 'backend',
      'cakephp/cakephp': 'backend',
      'doctrine/orm': 'database',
      'illuminate/database': 'database',
      'phpunit/phpunit': 'testing',
      'phpspec/phpspec': 'testing',
      'behat/behat': 'testing',
      'aws/aws-sdk-php': 'cloud',
      'microsoft/azure-storage': 'cloud',
      'google/cloud': 'cloud',
      'guzzlehttp/guzzle': 'backend',
      'symfony/http-client': 'backend',
      'twig/twig': 'frontend',
      'smarty/smarty': 'frontend',
      'twbs/bootstrap': 'frontend',
      'vlucas/phpdotenv': 'backend',
      'monolog/monolog': 'backend',
      'filp/whoops': 'backend'
    };
    
    // Process each composer.json
    for (const composerPath of composerPaths) {
      try {
        const content = await readFileAsync(composerPath, 'utf8');
        const composerJson = JSON.parse(content);
        
        // Check dependencies
        const allDeps = {
          ...(composerJson.require || {}),
          ...(composerJson['require-dev'] || {})
        };
        
        for (const [name, versionStr] of Object.entries(allDeps)) {
          // Skip PHP itself and ext-* requirements
          if (name === 'php' || name.startsWith('ext-')) {
            continue;
          }
          
          // Skip packages that don't match our known frameworks
          if (!phpFrameworks[name] && !Object.keys(phpFrameworks).some(fw => 
            name.startsWith(`${fw}/`) || name.startsWith(`${fw}-`)
          )) {
            // Still check for major frameworks by pattern
            const isFramework = (
              name.includes('framework') ||
              name.includes('platform') ||
              name.includes('-bundle') ||
              name.includes('-template') ||
              name.includes('-starter')
            );
            
            if (!isFramework) {
              continue;
            }
          }
          
          const version = String(versionStr).replace(/[^0-9.]/g, '');
          let type = 'backend'; // Default type for PHP
          
          // Determine the type if it's a known framework
          if (phpFrameworks[name]) {
            type = phpFrameworks[name];
          } else {
            // Try to determine type from package name
            if (name.includes('api') || name.includes('server') || name.includes('http')) {
              type = 'backend';
            } else if (name.includes('db') || name.includes('database') || name.includes('sql')) {
              type = 'database';
            } else if (name.includes('test') || name.includes('spec')) {
              type = 'testing';
            } else if (name.includes('aws') || name.includes('azure') || name.includes('cloud')) {
              type = 'cloud';
            } else if (name.includes('ui') || name.includes('view') || name.includes('template')) {
              type = 'frontend';
            }
          }
          
          frameworks.push({
            name,
            version,
            type,
            language: 'php',
            detectionMethod: 'manifest',
            detectionConfidence: 0.9,
            location: composerPath,
            usageFiles: [composerPath]
          });
        }
      } catch (composerError) {
        log.warn(`Error processing composer.json at ${composerPath}`, { error: composerError });
      }
    }
    
    // Find .csproj files (.NET)
    const csprojPaths = await glob('**/*.csproj', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || []),
        '**/bin/**',
        '**/obj/**'
      ]
    });
    
    // Map of known .NET frameworks to their types
    const dotnetFrameworks: Record<string, string> = {
      'Microsoft.AspNetCore': 'backend',
      'Microsoft.EntityFrameworkCore': 'database',
      'Microsoft.Extensions': 'backend',
      'Microsoft.NETCore.App': 'backend',
      'Microsoft.AspNetCore.Mvc': 'backend',
      'Microsoft.AspNetCore.SpaServices': 'frontend',
      'Microsoft.Data.SqlClient': 'database',
      'Npgsql.EntityFrameworkCore': 'database',
      'MSTest': 'testing',
      'NUnit': 'testing',
      'xunit': 'testing',
      'Moq': 'testing',
      'AWSSDK': 'cloud',
      'Azure.Storage': 'cloud',
      'Google.Cloud': 'cloud',
      'Microsoft.ML': 'ai',
      'Newtonsoft.Json': 'backend',
      'Swashbuckle': 'backend',
      'Serilog': 'backend',
      'NLog': 'backend'
    };
    
    // Process each .csproj file
    for (const csprojPath of csprojPaths) {
      try {
        const content = await readFileAsync(csprojPath, 'utf8');
        
        // Extract PackageReference elements - a proper XML parser would be better
        const packageRefMatches = content.match(/<PackageReference\s+[^>]*>/g) || [];
        
        for (const pkgRef of packageRefMatches) {
          const includeMatch = pkgRef.match(/Include="([^"]+)"/i);
          const versionMatch = pkgRef.match(/Version="([^"]+)"/i);
          
          if (includeMatch) {
            const name = includeMatch[1].trim();
            const version = versionMatch ? versionMatch[1].trim() : undefined;
            
            // Skip packages that don't match our known frameworks
            let isKnownFramework = false;
            let type = 'backend'; // Default type for .NET
            
            for (const [knownPackage, knownType] of Object.entries(dotnetFrameworks)) {
              if (name.startsWith(knownPackage)) {
                isKnownFramework = true;
                type = knownType;
                break;
              }
            }
            
            if (!isKnownFramework) {
              // Still check for major frameworks by pattern
              const isFramework = (
                name.includes('Framework') ||
                name.includes('Platform') ||
                name.includes('Template') ||
                name.includes('SDK') ||
                name.includes('Core') ||
                name.includes('Infrastructure')
              );
              
              if (!isFramework) {
                continue;
              }
              
              // Try to determine type from package name
              if (name.includes('Api') || name.includes('Server') || name.includes('Web')) {
                type = 'backend';
              } else if (name.includes('Db') || name.includes('Database') || name.includes('Sql')) {
                type = 'database';
              } else if (name.includes('Test') || name.includes('MSTest') || name.includes('XUnit')) {
                type = 'testing';
              } else if (name.includes('AWS') || name.includes('Azure') || name.includes('Cloud')) {
                type = 'cloud';
              } else if (name.includes('UI') || name.includes('View') || name.includes('Razor')) {
                type = 'frontend';
              }
            }
            
            frameworks.push({
              name,
              version,
              type,
              language: 'csharp',
              detectionMethod: 'manifest',
              detectionConfidence: 0.85,
              location: csprojPath,
              usageFiles: [csprojPath]
            });
          }
        }
        
        // Also check for TargetFramework to determine .NET version
        const targetFrameworkMatch = content.match(/<TargetFramework>([^<]+)<\/TargetFramework>/);
        if (targetFrameworkMatch) {
          const frameworkName = targetFrameworkMatch[1].trim();
          let version: string | undefined;
          
          // Parse version from target framework name
          if (frameworkName.startsWith('netcoreapp')) {
            version = frameworkName.replace('netcoreapp', '');
          } else if (frameworkName.startsWith('net')) {
            version = frameworkName.replace('net', '');
            // Handle 'net5.0', 'net6.0', etc.
            if (version.includes('.')) {
              version = version;
            }
            // Handle 'net40', 'net45', etc.
            else if (version.length === 2) {
              version = `${version[0]}.${version[1]}`;
            }
          }
          
          if (version) {
            frameworks.push({
              name: '.NET Framework',
              version,
              type: 'backend',
              language: 'csharp',
              detectionMethod: 'manifest',
              detectionConfidence: 0.95,
              location: csprojPath,
              usageFiles: [csprojPath]
            });
          }
        }
      } catch (csprojError) {
        log.warn(`Error processing .csproj at ${csprojPath}`, { error: csprojError });
      }
    }
    
    // Find go.mod files (Go)
    const goModPaths = await glob('**/go.mod', {
      cwd: config.rootDir,
      absolute: true,
      ignore: [
        ...(config.excludePaths || [])
      ]
    });
    
    // Map of known Go frameworks to their types
    const goFrameworks: Record<string, string> = {
      'github.com/gin-gonic/gin': 'backend',
      'github.com/gorilla/mux': 'backend',
      'github.com/labstack/echo': 'backend',
      'github.com/gofiber/fiber': 'backend',
      'github.com/go-chi/chi': 'backend',
      'github.com/jinzhu/gorm': 'database',
      'gorm.io/gorm': 'database',
      'github.com/go-sql-driver/mysql': 'database',
      'github.com/lib/pq': 'database',
      'github.com/stretchr/testify': 'testing',
      'github.com/aws/aws-sdk-go': 'cloud',
      'github.com/Azure/azure-sdk-for-go': 'cloud',
      'cloud.google.com/go': 'cloud',
      'github.com/docker/docker': 'devops',
      'k8s.io/client-go': 'devops',
      'github.com/prometheus/client_golang': 'devops',
      'github.com/sirupsen/logrus': 'backend',
      'go.uber.org/zap': 'backend',
      'github.com/spf13/cobra': 'backend',
      'github.com/spf13/viper': 'backend',
      'github.com/tensorflow/tensorflow': 'ai'
    };
    
    // Process each go.mod file
    for (const goModPath of goModPaths) {
      try {
        const content = await readFileAsync(goModPath, 'utf8');
        const lines = content.split('\n');
        
        // Get module name (first line: module github.com/example/myproject)
        const moduleLine = lines.find(line => line.trim().startsWith('module '));
        const moduleName = moduleLine ? moduleLine.replace('module', '').trim() : 'unknown';
        
        // Get Go version
        const goLine = lines.find(line => line.trim().startsWith('go '));
        const goVersion = goLine ? goLine.replace('go', '').trim() : undefined;
        
        if (goVersion) {
          frameworks.push({
            name: 'Go',
            version: goVersion,
            type: 'backend',
            language: 'go',
            detectionMethod: 'manifest',
            detectionConfidence: 0.95,
            location: goModPath,
            usageFiles: [goModPath]
          });
        }
        
        // Find require sections
        let inRequireBlock = false;
        for (const line of lines) {
          const trimmedLine = line.trim();
          
          if (trimmedLine === 'require (') {
            inRequireBlock = true;
            continue;
          }
          
          if (inRequireBlock && trimmedLine === ')') {
            inRequireBlock = false;
            continue;
          }
          
          // Single-line require: require github.com/example/package v1.2.3
          if (trimmedLine.startsWith('require ') && !inRequireBlock) {
            const parts = trimmedLine.replace('require ', '').trim().split(' ');
            if (parts.length >= 2) {
              const name = parts[0].trim();
              const version = parts[1].trim();
              
              // Check if this is a known framework
              let isKnownFramework = false;
              let type = 'backend'; // Default type for Go
              
              for (const [knownPackage, knownType] of Object.entries(goFrameworks)) {
                if (name.includes(knownPackage)) {
                  isKnownFramework = true;
                  type = knownType;
                  break;
                }
              }
              
              if (!isKnownFramework) {
                // Still check for major frameworks by pattern
                const isFramework = (
                  name.includes('framework') ||
                  name.includes('platform') ||
                  name.includes('server') ||
                  name.includes('api') ||
                  name.includes('web') ||
                  name.includes('database') ||
                  name.includes('cloud')
                );
                
                if (!isFramework) {
                  continue;
                }
                
                // Try to determine type from package name
                if (name.includes('api') || name.includes('server') || name.includes('web') || name.includes('http')) {
                  type = 'backend';
                } else if (name.includes('db') || name.includes('database') || name.includes('sql')) {
                  type = 'database';
                } else if (name.includes('test')) {
                  type = 'testing';
                } else if (name.includes('aws') || name.includes('azure') || name.includes('cloud')) {
                  type = 'cloud';
                } else if (name.includes('docker') || name.includes('kubernetes') || name.includes('k8s')) {
                  type = 'devops';
                }
              }
              
              frameworks.push({
                name,
                version,
                type,
                language: 'go',
                detectionMethod: 'manifest',
                detectionConfidence: 0.85,
                location: goModPath,
                usageFiles: [goModPath]
              });
            }
          }
          
          // Multi-line require block
          if (inRequireBlock && trimmedLine && !trimmedLine.startsWith('//')) {
            const parts = trimmedLine.split(' ');
            if (parts.length >= 2) {
              const name = parts[0].trim();
              const version = parts[1].trim();
              
              // Same framework detection logic as single-line requires
              let isKnownFramework = false;
              let type = 'backend'; // Default type for Go
              
              for (const [knownPackage, knownType] of Object.entries(goFrameworks)) {
                if (name.includes(knownPackage)) {
                  isKnownFramework = true;
                  type = knownType;
                  break;
                }
              }
              
              if (!isKnownFramework) {
                const isFramework = (
                  name.includes('framework') ||
                  name.includes('platform') ||
                  name.includes('server') ||
                  name.includes('api') ||
                  name.includes('web') ||
                  name.includes('database') ||
                  name.includes('cloud')
                );
                
                if (!isFramework) {
                  continue;
                }
                
                if (name.includes('api') || name.includes('server') || name.includes('web') || name.includes('http')) {
                  type = 'backend';
                } else if (name.includes('db') || name.includes('database') || name.includes('sql')) {
                  type = 'database';
                } else if (name.includes('test')) {
                  type = 'testing';
                } else if (name.includes('aws') || name.includes('azure') || name.includes('cloud')) {
                  type = 'cloud';
                } else if (name.includes('docker') || name.includes('kubernetes') || name.includes('k8s')) {
                  type = 'devops';
                }
              }
              
              frameworks.push({
                name,
                version,
                type,
                language: 'go',
                detectionMethod: 'manifest',
                detectionConfidence: 0.85,
                location: goModPath,
                usageFiles: [goModPath]
              });
            }
          }
        }
      } catch (goModError) {
        log.warn(`Error processing go.mod at ${goModPath}`, { error: goModError });
      }
    }
    
  } catch (error) {
    log.error('Error detecting frameworks from manifests', { error });
  }
  
  return frameworks;
}

/**
 * Detect frameworks from code files (imports, usage patterns)
 */
async function detectFrameworksFromCode(
  config: FrameworkScannerConfig
): Promise<FrameworkInfo[]> {
  const frameworks: FrameworkInfo[] = [];
  
  try {
    // Define which languages to scan based on config or default to common ones
    const languages = config.languages || [
      'javascript', 'typescript', 'python', 'java', 'ruby', 'php', 'csharp', 'go'
    ];
    
    // Define file extensions for each language
    const fileExtensions: Record<string, string[]> = {
      'javascript': ['.js', '.jsx', '.mjs'],
      'typescript': ['.ts', '.tsx'],
      'python': ['.py'],
      'java': ['.java'],
      'ruby': ['.rb'],
      'php': ['.php'],
      'csharp': ['.cs'],
      'go': ['.go']
    };
    
    // Generate glob patterns for each language's file extensions
    const filePatterns: string[] = [];
    for (const lang of languages) {
      if (fileExtensions[lang]) {
        filePatterns.push(...fileExtensions[lang].map(ext => `**/*${ext}`));
      }
    }
    
    // Find all relevant code files
    const codePaths: string[] = [];
    for (const pattern of filePatterns) {
      const paths = await glob(pattern, {
        cwd: config.rootDir,
        absolute: true,
        ignore: [
          ...(config.excludePaths || []),
          '**/node_modules/**',
          '**/bower_components/**',
          '**/vendor/**',
          '**/dist/**',
          '**/build/**',
          '**/bin/**',
          '**/obj/**',
          '**/.git/**'
        ]
      });
      codePaths.push(...paths);
    }
    
    // Limit the number of files to scan based on maxScanDepth
    const maxFiles = config.maxScanDepth || 1000;
    const filesToScan = codePaths.slice(0, maxFiles);
    
    log.info(`Found ${codePaths.length} code files, scanning ${filesToScan.length} (maxScanDepth: ${maxFiles})`);
    
    // Process each file based on its language
    for (const filePath of filesToScan) {
      try {
        const content = await readFileAsync(filePath, 'utf8');
        const ext = path.extname(filePath).toLowerCase();
        
        // Detect language from file extension
        let language: string | undefined;
        for (const [lang, extensions] of Object.entries(fileExtensions)) {
          if (extensions.includes(ext)) {
            language = lang;
            break;
          }
        }
        
        if (!language) {
          continue; // Skip files with unknown languages
        }
        
        // Call the appropriate detector based on language
        let detectedFrameworks: FrameworkInfo[] = [];
        
        switch (language) {
          case 'javascript':
          case 'typescript':
            detectedFrameworks = detectJsFrameworks(content, filePath, language);
            break;
          case 'python':
            detectedFrameworks = detectPythonFrameworks(content, filePath);
            break;
          case 'java':
            detectedFrameworks = detectJavaFrameworks(content, filePath);
            break;
          case 'ruby':
            detectedFrameworks = detectRubyFrameworks(content, filePath);
            break;
          case 'php':
            detectedFrameworks = detectPhpFrameworks(content, filePath);
            break;
          case 'csharp':
            detectedFrameworks = detectCSharpFrameworks(content, filePath);
            break;
          case 'go':
            detectedFrameworks = detectGoFrameworks(content, filePath);
            break;
        }
        
        frameworks.push(...detectedFrameworks);
      } catch (fileError) {
        // Skip files that can't be read or parsed
        log.debug(`Error processing file ${filePath}`, { error: fileError });
      }
    }
  } catch (error) {
    log.error('Error detecting frameworks from code', { error });
  }
  
  return frameworks;
}

/**
 * Detect JavaScript/TypeScript frameworks from code
 */
function detectJsFrameworks(
  content: string,
  filePath: string,
  language: string
): FrameworkInfo[] {
  const frameworks: FrameworkInfo[] = [];
  
  // Map of import/require patterns to framework info
  const frameworkPatterns: Record<string, { name: string, type: string }> = {
    'react': { name: 'React', type: 'frontend' },
    'vue': { name: 'Vue.js', type: 'frontend' },
    'angular': { name: 'Angular', type: 'frontend' },
    'svelte': { name: 'Svelte', type: 'frontend' },
    'express': { name: 'Express.js', type: 'backend' },
    'koa': { name: 'Koa.js', type: 'backend' },
    'next': { name: 'Next.js', type: 'frontend' },
    'nuxt': { name: 'Nuxt.js', type: 'frontend' },
    'gatsby': { name: 'Gatsby', type: 'frontend' },
    'jquery': { name: 'jQuery', type: 'frontend' },
    'axios': { name: 'Axios', type: 'backend' },
    'graphql': { name: 'GraphQL', type: 'backend' },
    'apollo': { name: 'Apollo', type: 'backend' },
    'mongoose': { name: 'Mongoose', type: 'database' },
    'sequelize': { name: 'Sequelize', type: 'database' },
    'typeorm': { name: 'TypeORM', type: 'database' },
    'redux': { name: 'Redux', type: 'frontend' },
    'mobx': { name: 'MobX', type: 'frontend' },
    'socket.io': { name: 'Socket.IO', type: 'backend' },
    'aws-sdk': { name: 'AWS SDK', type: 'cloud' },
    'firebase': { name: 'Firebase', type: 'cloud' },
    '@azure/': { name: 'Azure SDK', type: 'cloud' },
    '@google-cloud/': { name: 'Google Cloud SDK', type: 'cloud' },
    'jest': { name: 'Jest', type: 'testing' },
    'mocha': { name: 'Mocha', type: 'testing' },
    'chai': { name: 'Chai', type: 'testing' },
    'cypress': { name: 'Cypress', type: 'testing' },
    'puppeteer': { name: 'Puppeteer', type: 'testing' },
    'tensorflow': { name: 'TensorFlow.js', type: 'ai' },
    '@tensorflow/': { name: 'TensorFlow.js', type: 'ai' },
    '@material-ui/': { name: 'Material-UI', type: 'frontend' },
    '@mui/': { name: 'MUI', type: 'frontend' },
    'bootstrap': { name: 'Bootstrap', type: 'frontend' },
    'tailwindcss': { name: 'Tailwind CSS', type: 'frontend' },
    'styled-components': { name: 'styled-components', type: 'frontend' },
    'emotion': { name: 'Emotion', type: 'frontend' },
    'antd': { name: 'Ant Design', type: 'frontend' },
    'webpack': { name: 'Webpack', type: 'devops' },
    'babel': { name: 'Babel', type: 'devops' },
    'eslint': { name: 'ESLint', type: 'devops' },
    'prettier': { name: 'Prettier', type: 'devops' }
  };
  
  // Look for import statements (ES modules)
  const importRegex = /import\s+.*?from\s+['"]([^'"]+)['"];?/g;
  let match;
  while ((match = importRegex.exec(content)) !== null) {
    const importPath = match[1];
    
    // Check if this import matches one of our known frameworks
    for (const [pattern, info] of Object.entries(frameworkPatterns)) {
      if (importPath === pattern || importPath.startsWith(`${pattern}/`)) {
        frameworks.push({
          name: info.name,
          type: info.type,
          language,
          detectionMethod: 'code-scan',
          detectionConfidence: 0.8,
          location: filePath,
          usageFiles: [filePath]
        });
        break;
      }
    }
  }
  
  // Look for require statements (CommonJS)
  const requireRegex = /(?:const|let|var)\s+.*?=\s+require\(['"]([^'"]+)['"]\);?/g;
  while ((match = requireRegex.exec(content)) !== null) {
    const requirePath = match[1];
    
    // Check if this require matches one of our known frameworks
    for (const [pattern, info] of Object.entries(frameworkPatterns)) {
      if (requirePath === pattern || requirePath.startsWith(`${pattern}/`)) {
        frameworks.push({
          name: info.name,
          type: info.type,
          language,
          detectionMethod: 'code-scan',
          detectionConfidence: 0.8,
          location: filePath,
          usageFiles: [filePath]
        });
        break;
      }
    }
  }
  
  // Look for framework-specific usage patterns
  if (content.includes('React.') || content.includes('ReactDOM.') || content.includes('useState(') || content.includes('useEffect(')) {
    frameworks.push({
      name: 'React',
      type: 'frontend',
      language,
      detectionMethod: 'code-scan',
      detectionConfidence: 0.7,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('Vue.') || content.includes('new Vue(') || content.includes('createApp(')) {
    frameworks.push({
      name: 'Vue.js',
      type: 'frontend',
      language,
      detectionMethod: 'code-scan',
      detectionConfidence: 0.7,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('@Component') || content.includes('@NgModule') || content.includes('@Injectable')) {
    frameworks.push({
      name: 'Angular',
      type: 'frontend',
      language,
      detectionMethod: 'code-scan',
      detectionConfidence: 0.8,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('app.use(') || content.includes('app.get(') || content.includes('app.post(') || content.includes('app.listen(')) {
    frameworks.push({
      name: 'Express.js',
      type: 'backend',
      language,
      detectionMethod: 'code-scan',
      detectionConfidence: 0.6,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  return frameworks;
}

/**
 * Detect Python frameworks from code
 */
function detectPythonFrameworks(
  content: string,
  filePath: string
): FrameworkInfo[] {
  const frameworks: FrameworkInfo[] = [];
  
  // Map of import patterns to framework info
  const frameworkPatterns: Record<string, { name: string, type: string }> = {
    'django': { name: 'Django', type: 'backend' },
    'flask': { name: 'Flask', type: 'backend' },
    'fastapi': { name: 'FastAPI', type: 'backend' },
    'tornado': { name: 'Tornado', type: 'backend' },
    'sqlalchemy': { name: 'SQLAlchemy', type: 'database' },
    'pandas': { name: 'pandas', type: 'ai' },
    'numpy': { name: 'NumPy', type: 'ai' },
    'sklearn': { name: 'scikit-learn', type: 'ai' },
    'tensorflow': { name: 'TensorFlow', type: 'ai' },
    'torch': { name: 'PyTorch', type: 'ai' },
    'pytest': { name: 'pytest', type: 'testing' },
    'unittest': { name: 'unittest', type: 'testing' },
    'boto3': { name: 'Boto3', type: 'cloud' },
    'botocore': { name: 'Boto3', type: 'cloud' },
    'azure': { name: 'Azure SDK', type: 'cloud' },
    'google.cloud': { name: 'Google Cloud SDK', type: 'cloud' },
    'requests': { name: 'Requests', type: 'backend' },
    'aiohttp': { name: 'aiohttp', type: 'backend' },
    'streamlit': { name: 'Streamlit', type: 'frontend' },
    'dash': { name: 'Dash', type: 'frontend' },
    'kivy': { name: 'Kivy', type: 'frontend' },
    'pymongo': { name: 'PyMongo', type: 'database' },
    'psycopg2': { name: 'psycopg2', type: 'database' },
    'celery': { name: 'Celery', type: 'backend' },
    'pydantic': { name: 'Pydantic', type: 'backend' },
    'pyramid': { name: 'Pyramid', type: 'backend' },
    'scrapy': { name: 'Scrapy', type: 'backend' },
    'matplotlib': { name: 'Matplotlib', type: 'ai' },
    'seaborn': { name: 'Seaborn', type: 'ai' },
    'transformers': { name: 'Hugging Face Transformers', type: 'ai' }
  };
  
  // Look for import statements
  const importRegex = /(?:import|from)\s+([\w.]+)(?:\s+import|$)/g;
  let match;
  while ((match = importRegex.exec(content)) !== null) {
    const importPath = match[1];
    
    // Check if this import matches one of our known frameworks
    for (const [pattern, info] of Object.entries(frameworkPatterns)) {
      if (importPath === pattern || importPath.startsWith(`${pattern}.`)) {
        frameworks.push({
          name: info.name,
          type: info.type,
          language: 'python',
          detectionMethod: 'code-scan',
          detectionConfidence: 0.8,
          location: filePath,
          usageFiles: [filePath]
        });
        break;
      }
    }
  }
  
  // Look for framework-specific usage patterns
  if (content.includes('def test_') && (content.includes('@pytest') || content.includes('pytest.') || content.includes('assert '))) {
    frameworks.push({
      name: 'pytest',
      type: 'testing',
      language: 'python',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.7,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('app = Flask(') || content.includes('Blueprint(')) {
    frameworks.push({
      name: 'Flask',
      type: 'backend',
      language: 'python',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('models.Model') || content.includes('django.') || content.includes('@admin.register')) {
    frameworks.push({
      name: 'Django',
      type: 'backend',
      language: 'python',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.8,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('FastAPI(') || content.includes('@app.') || content.includes('APIRouter(')) {
    frameworks.push({
      name: 'FastAPI',
      type: 'backend',
      language: 'python',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('pd.DataFrame') || content.includes('pandas.DataFrame')) {
    frameworks.push({
      name: 'pandas',
      type: 'ai',
      language: 'python',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('np.array') || content.includes('numpy.array')) {
    frameworks.push({
      name: 'NumPy',
      type: 'ai',
      language: 'python',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('torch.') || content.includes('nn.Module')) {
    frameworks.push({
      name: 'PyTorch',
      type: 'ai',
      language: 'python',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  return frameworks;
}

/**
 * Detect Java frameworks from code
 */
function detectJavaFrameworks(
  content: string,
  filePath: string
): FrameworkInfo[] {
  const frameworks: FrameworkInfo[] = [];
  
  // Map of import patterns to framework info
  const frameworkPatterns: Record<string, { name: string, type: string }> = {
    'org.springframework': { name: 'Spring Framework', type: 'backend' },
    'org.springframework.boot': { name: 'Spring Boot', type: 'backend' },
    'org.hibernate': { name: 'Hibernate', type: 'database' },
    'javax.persistence': { name: 'JPA', type: 'database' },
    'jakarta.persistence': { name: 'JPA', type: 'database' },
    'javax.servlet': { name: 'Servlet API', type: 'backend' },
    'jakarta.servlet': { name: 'Servlet API', type: 'backend' },
    'com.fasterxml.jackson': { name: 'Jackson', type: 'backend' },
    'org.junit': { name: 'JUnit', type: 'testing' },
    'org.testng': { name: 'TestNG', type: 'testing' },
    'org.mockito': { name: 'Mockito', type: 'testing' },
    'com.amazonaws': { name: 'AWS SDK for Java', type: 'cloud' },
    'com.azure': { name: 'Azure SDK for Java', type: 'cloud' },
    'com.google.cloud': { name: 'Google Cloud SDK for Java', type: 'cloud' },
    'org.apache.kafka': { name: 'Kafka', type: 'backend' },
    'org.slf4j': { name: 'SLF4J', type: 'backend' },
    'lombok': { name: 'Lombok', type: 'backend' },
    'io.vertx': { name: 'Vert.x', type: 'backend' },
    'io.quarkus': { name: 'Quarkus', type: 'backend' },
    'io.micronaut': { name: 'Micronaut', type: 'backend' },
    'org.apache.logging.log4j': { name: 'Log4j', type: 'backend' },
    'org.apache.commons': { name: 'Apache Commons', type: 'backend' }
  };
  
  // Look for import statements
  const importRegex = /import\s+([\w.]+\*?);/g;
  let match;
  while ((match = importRegex.exec(content)) !== null) {
    const importPath = match[1];
    
    // Check if this import matches one of our known frameworks
    for (const [pattern, info] of Object.entries(frameworkPatterns)) {
      if (importPath.startsWith(pattern)) {
        frameworks.push({
          name: info.name,
          type: info.type,
          language: 'java',
          detectionMethod: 'code-scan',
          detectionConfidence: 0.8,
          location: filePath,
          usageFiles: [filePath]
        });
        break;
      }
    }
  }
  
  // Look for framework-specific annotations and usage patterns
  if (content.includes('@Controller') || content.includes('@RestController') || 
      content.includes('@Service') || content.includes('@Repository') || 
      content.includes('@Component') || content.includes('@Autowired')) {
    frameworks.push({
      name: 'Spring Framework',
      type: 'backend',
      language: 'java',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('@SpringBootApplication') || content.includes('SpringApplication.run')) {
    frameworks.push({
      name: 'Spring Boot',
      type: 'backend',
      language: 'java',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.95,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('@Entity') || content.includes('@Table') || 
      content.includes('@Column') || content.includes('@Id')) {
    frameworks.push({
      name: 'JPA',
      type: 'database',
      language: 'java',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.8,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('@Test') || content.includes('assertEquals') || 
      content.includes('assertThat') || content.includes('Mockito.')) {
    frameworks.push({
      name: 'JUnit',
      type: 'testing',
      language: 'java',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.8,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  return frameworks;
}

/**
 * Detect Ruby frameworks from code
 */
function detectRubyFrameworks(
  content: string,
  filePath: string
): FrameworkInfo[] {
  const frameworks: FrameworkInfo[] = [];
  
  // Map of require/include patterns to framework info
  const frameworkPatterns: Record<string, { name: string, type: string }> = {
    'rails': { name: 'Ruby on Rails', type: 'backend' },
    'sinatra': { name: 'Sinatra', type: 'backend' },
    'active_record': { name: 'ActiveRecord', type: 'database' },
    'activerecord': { name: 'ActiveRecord', type: 'database' },
    'sequel': { name: 'Sequel', type: 'database' },
    'rspec': { name: 'RSpec', type: 'testing' },
    'minitest': { name: 'Minitest', type: 'testing' },
    'devise': { name: 'Devise', type: 'security' },
    'pundit': { name: 'Pundit', type: 'security' },
    'sidekiq': { name: 'Sidekiq', type: 'backend' },
    'aws-sdk': { name: 'AWS SDK for Ruby', type: 'cloud' },
    'azure': { name: 'Azure SDK for Ruby', type: 'cloud' },
    'google-cloud': { name: 'Google Cloud SDK for Ruby', type: 'cloud' }
  };
  
  // Look for require statements
  const requireRegex = /require\s+['"]([\w/]+)['"]|include\s+([\w:]+)/g;
  let match;
  while ((match = requireRegex.exec(content)) !== null) {
    const requirePath = match[1] || match[2];
    
    if (!requirePath) continue;
    
    // Check if this require matches one of our known frameworks
    for (const [pattern, info] of Object.entries(frameworkPatterns)) {
      if (requirePath.includes(pattern)) {
        frameworks.push({
          name: info.name,
          type: info.type,
          language: 'ruby',
          detectionMethod: 'code-scan',
          detectionConfidence: 0.7,
          location: filePath,
          usageFiles: [filePath]
        });
        break;
      }
    }
  }
  
  // Look for framework-specific usage patterns
  if (content.includes('class') && (content.includes(' < ActiveRecord::Base') || content.includes(' < ApplicationRecord'))) {
    frameworks.push({
      name: 'Ruby on Rails',
      type: 'backend',
      language: 'ruby',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('class') && content.includes(' < ApplicationController')) {
    frameworks.push({
      name: 'Ruby on Rails',
      type: 'backend',
      language: 'ruby',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.95,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('describe') && content.includes('it ')) {
    frameworks.push({
      name: 'RSpec',
      type: 'testing',
      language: 'ruby',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.8,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('assert_') || content.includes('class') && content.includes(' < Minitest::Test')) {
    frameworks.push({
      name: 'Minitest',
      type: 'testing',
      language: 'ruby',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.8,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  return frameworks;
}

/**
 * Detect PHP frameworks from code
 */
function detectPhpFrameworks(
  content: string,
  filePath: string
): FrameworkInfo[] {
  const frameworks: FrameworkInfo[] = [];
  
  // Map of namespace/use patterns to framework info
  const frameworkPatterns: Record<string, { name: string, type: string }> = {
    'Laravel': { name: 'Laravel', type: 'backend' },
    'Illuminate\\': { name: 'Laravel', type: 'backend' },
    'Symfony\\': { name: 'Symfony', type: 'backend' },
    'Slim\\': { name: 'Slim', type: 'backend' },
    'CodeIgniter\\': { name: 'CodeIgniter', type: 'backend' },
    'Yii': { name: 'Yii', type: 'backend' },
    'CakePHP\\': { name: 'CakePHP', type: 'backend' },
    'Doctrine\\': { name: 'Doctrine', type: 'database' },
    'PHPUnit\\': { name: 'PHPUnit', type: 'testing' },
    'Mockery': { name: 'Mockery', type: 'testing' },
    'AWS\\': { name: 'AWS SDK for PHP', type: 'cloud' },
    'Azure\\': { name: 'Azure SDK for PHP', type: 'cloud' },
    'Google\\Cloud': { name: 'Google Cloud SDK for PHP', type: 'cloud' },
    'GuzzleHttp\\': { name: 'Guzzle', type: 'backend' },
    'Twig\\': { name: 'Twig', type: 'frontend' },
    'Smarty': { name: 'Smarty', type: 'frontend' }
  };
  
  // Look for namespace and use statements
  const namespaceRegex = /(?:namespace|use)\s+([\w\\]+)/g;
  let match;
  while ((match = namespaceRegex.exec(content)) !== null) {
    const namespacePath = match[1];
    
    // Check if this namespace/use matches one of our known frameworks
    for (const [pattern, info] of Object.entries(frameworkPatterns)) {
      if (namespacePath.startsWith(pattern) || namespacePath.includes(`\\${pattern}`)) {
        frameworks.push({
          name: info.name,
          type: info.type,
          language: 'php',
          detectionMethod: 'code-scan',
          detectionConfidence: 0.8,
          location: filePath,
          usageFiles: [filePath]
        });
        break;
      }
    }
  }
  
  // Look for framework-specific usage patterns
  if (content.includes('extends Controller') || content.includes('extends BaseController') ||
      content.includes('use AuthorizesRequests') || content.includes('use Illuminate\\Foundation')) {
    frameworks.push({
      name: 'Laravel',
      type: 'backend',
      language: 'php',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('extends TestCase') || content.includes('->assertInstanceOf') ||
      content.includes('PHPUnit') || content.includes('@test')) {
    frameworks.push({
      name: 'PHPUnit',
      type: 'testing',
      language: 'php',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.8,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('Doctrine\\ORM') || content.includes('@ORM\\') ||
      content.includes('@Entity') || content.includes('@Column')) {
    frameworks.push({
      name: 'Doctrine',
      type: 'database',
      language: 'php',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('class') && content.includes('extends Model')) {
    frameworks.push({
      name: 'Laravel Eloquent',
      type: 'database',
      language: 'php',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  return frameworks;
}

/**
 * Detect C# frameworks from code
 */
function detectCSharpFrameworks(
  content: string,
  filePath: string
): FrameworkInfo[] {
  const frameworks: FrameworkInfo[] = [];
  
  // Map of using patterns to framework info
  const frameworkPatterns: Record<string, { name: string, type: string }> = {
    'Microsoft.AspNetCore': { name: 'ASP.NET Core', type: 'backend' },
    'Microsoft.EntityFrameworkCore': { name: 'Entity Framework Core', type: 'database' },
    'Microsoft.Extensions': { name: '.NET Extensions', type: 'backend' },
    'System.Web': { name: 'ASP.NET', type: 'backend' },
    'System.Data.Entity': { name: 'Entity Framework', type: 'database' },
    'Microsoft.Data.SqlClient': { name: 'SQL Client', type: 'database' },
    'System.Data.SqlClient': { name: 'SQL Client', type: 'database' },
    'Npgsql': { name: 'Npgsql', type: 'database' },
    'MySql': { name: 'MySQL Connector', type: 'database' },
    'NUnit': { name: 'NUnit', type: 'testing' },
    'Xunit': { name: 'xUnit', type: 'testing' },
    'Microsoft.VisualStudio.TestTools': { name: 'MSTest', type: 'testing' },
    'Moq': { name: 'Moq', type: 'testing' },
    'Amazon.': { name: 'AWS SDK for .NET', type: 'cloud' },
    'Microsoft.Azure': { name: 'Azure SDK for .NET', type: 'cloud' },
    'Google.Cloud': { name: 'Google Cloud SDK for .NET', type: 'cloud' },
    'Microsoft.ML': { name: 'ML.NET', type: 'ai' },
    'Serilog': { name: 'Serilog', type: 'backend' },
    'NLog': { name: 'NLog', type: 'backend' },
    'Microsoft.Extensions.Logging': { name: '.NET Logging', type: 'backend' },
    'Microsoft.AspNetCore.Mvc': { name: 'ASP.NET Core MVC', type: 'backend' },
    'Microsoft.AspNetCore.Razor': { name: 'Razor', type: 'frontend' },
    'Microsoft.AspNetCore.Blazor': { name: 'Blazor', type: 'frontend' },
    'Newtonsoft.Json': { name: 'Newtonsoft.Json', type: 'backend' },
    'System.Text.Json': { name: 'System.Text.Json', type: 'backend' }
  };
  
  // Look for using statements
  const usingRegex = /using\s+([\w.]+);/g;
  let match;
  while ((match = usingRegex.exec(content)) !== null) {
    const usingPath = match[1];
    
    // Check if this using matches one of our known frameworks
    for (const [pattern, info] of Object.entries(frameworkPatterns)) {
      if (usingPath.startsWith(pattern)) {
        frameworks.push({
          name: info.name,
          type: info.type,
          language: 'csharp',
          detectionMethod: 'code-scan',
          detectionConfidence: 0.8,
          location: filePath,
          usageFiles: [filePath]
        });
        break;
      }
    }
  }
  
  // Look for framework-specific usage patterns
  if (content.includes('[ApiController]') || content.includes('Controller') && 
      (content.includes(' IActionResult ') || content.includes(' ActionResult '))) {
    frameworks.push({
      name: 'ASP.NET Core MVC',
      type: 'backend',
      language: 'csharp',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('DbContext') || content.includes('OnModelCreating') ||
      content.includes('[Table(') || content.includes('[Column(')) {
    frameworks.push({
      name: 'Entity Framework Core',
      type: 'database',
      language: 'csharp',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('[Fact]') || content.includes('[Theory]') || 
      content.includes('using Xunit;')) {
    frameworks.push({
      name: 'xUnit',
      type: 'testing',
      language: 'csharp',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('[Test]') || content.includes('[TestCase]') || 
      content.includes('using NUnit.Framework;')) {
    frameworks.push({
      name: 'NUnit',
      type: 'testing',
      language: 'csharp',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('[TestMethod]') || content.includes('[TestClass]') || 
      content.includes('using Microsoft.VisualStudio.TestTools.UnitTesting;')) {
    frameworks.push({
      name: 'MSTest',
      type: 'testing',
      language: 'csharp',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  return frameworks;
}

/**
 * Detect Go frameworks from code
 */
function detectGoFrameworks(
  content: string,
  filePath: string
): FrameworkInfo[] {
  const frameworks: FrameworkInfo[] = [];
  
  // Map of import patterns to framework info
  const frameworkPatterns: Record<string, { name: string, type: string }> = {
    'github.com/gin-gonic/gin': { name: 'Gin', type: 'backend' },
    'github.com/gorilla/mux': { name: 'Gorilla Mux', type: 'backend' },
    'github.com/labstack/echo': { name: 'Echo', type: 'backend' },
    'github.com/gofiber/fiber': { name: 'Fiber', type: 'backend' },
    'github.com/go-chi/chi': { name: 'Chi', type: 'backend' },
    'database/sql': { name: 'database/sql', type: 'database' },
    'gorm.io/gorm': { name: 'GORM', type: 'database' },
    'github.com/jinzhu/gorm': { name: 'GORM', type: 'database' },
    'github.com/go-sql-driver/mysql': { name: 'MySQL Driver', type: 'database' },
    'github.com/lib/pq': { name: 'PostgreSQL Driver', type: 'database' },
    'github.com/stretchr/testify': { name: 'Testify', type: 'testing' },
    'testing': { name: 'testing', type: 'testing' },
    'github.com/aws/aws-sdk-go': { name: 'AWS SDK for Go', type: 'cloud' },
    'github.com/Azure/azure-sdk-for-go': { name: 'Azure SDK for Go', type: 'cloud' },
    'cloud.google.com/go': { name: 'Google Cloud SDK for Go', type: 'cloud' },
    'github.com/tensorflow/tensorflow': { name: 'TensorFlow for Go', type: 'ai' },
    'gonum.org/v1/gonum': { name: 'Gonum', type: 'ai' },
    'github.com/sirupsen/logrus': { name: 'Logrus', type: 'backend' },
    'go.uber.org/zap': { name: 'Zap', type: 'backend' },
    'github.com/spf13/viper': { name: 'Viper', type: 'backend' },
    'github.com/spf13/cobra': { name: 'Cobra', type: 'backend' },
    'github.com/golang/protobuf': { name: 'Protocol Buffers', type: 'backend' },
    'google.golang.org/grpc': { name: 'gRPC', type: 'backend' }
  };
  
  // Look for import statements
  const importRegex = /import\s+\(([\s\S]*?)\)|import\s+"([^"]+)"/g;
  let match;
  while ((match = importRegex.exec(content)) !== null) {
    const importBlock = match[1] || match[2];
    
    if (importBlock) {
      // Handle import blocks
      if (match[1]) {
        const importLines = importBlock.split('\n');
        for (const line of importLines) {
          const trimmedLine = line.trim();
          if (trimmedLine && !trimmedLine.startsWith('//')) {
            const importPath = trimmedLine.replace(/"/g, '').trim();
            
            // Check if this import matches one of our known frameworks
            for (const [pattern, info] of Object.entries(frameworkPatterns)) {
              if (importPath.startsWith(pattern)) {
                frameworks.push({
                  name: info.name,
                  type: info.type,
                  language: 'go',
                  detectionMethod: 'code-scan',
                  detectionConfidence: 0.8,
                  location: filePath,
                  usageFiles: [filePath]
                });
                break;
              }
            }
          }
        }
      } 
      // Handle single imports
      else if (match[2]) {
        const importPath = match[2];
        
        // Check if this import matches one of our known frameworks
        for (const [pattern, info] of Object.entries(frameworkPatterns)) {
          if (importPath.startsWith(pattern)) {
            frameworks.push({
              name: info.name,
              type: info.type,
              language: 'go',
              detectionMethod: 'code-scan',
              detectionConfidence: 0.8,
              location: filePath,
              usageFiles: [filePath]
            });
            break;
          }
        }
      }
    }
  }
  
  // Look for framework-specific usage patterns
  if (content.includes('gin.') || content.includes('*gin.') || 
      content.includes('gin.Default()') || content.includes('gin.New()')) {
    frameworks.push({
      name: 'Gin',
      type: 'backend',
      language: 'go',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('mux.') || content.includes('*mux.') || 
      content.includes('mux.NewRouter()')) {
    frameworks.push({
      name: 'Gorilla Mux',
      type: 'backend',
      language: 'go',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('echo.') || content.includes('*echo.') || 
      content.includes('echo.New()')) {
    frameworks.push({
      name: 'Echo',
      type: 'backend',
      language: 'go',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('gorm.') || content.includes('*gorm.') || 
      content.includes('gorm.Open') || content.includes('*gorm.DB')) {
    frameworks.push({
      name: 'GORM',
      type: 'database',
      language: 'go',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  if (content.includes('func Test') && (content.includes('testing.') || content.includes('*testing.'))) {
    frameworks.push({
      name: 'testing',
      type: 'testing',
      language: 'go',
      detectionMethod: 'code-scan',
      detectionConfidence: 0.9,
      location: filePath,
      usageFiles: [filePath]
    });
  }
  
  return frameworks;
}

/**
 * Detect frameworks from build artifacts
 */
async function detectFrameworksFromArtifacts(
  config: FrameworkScannerConfig
): Promise<FrameworkInfo[]> {
  const frameworks: FrameworkInfo[] = [];
  
  try {
    // Define common build artifact patterns to look for
    const artifactPatterns = [
      // JavaScript/TypeScript build artifacts
      '**/dist/**.js',
      '**/build/**.js',
      '**/out/**.js',
      '**/public/static/**',
      
      // Java build artifacts
      '**/target/**.jar',
      '**/build/libs/**.jar',
      '**/WEB-INF/lib/**.jar',
      
      // .NET build artifacts
      '**/bin/**.dll',
      
      // Ruby build artifacts
      '**/vendor/bundle/**',
      
      // Python build artifacts
      '**/site-packages/**',
      '**/dist/**.whl',
      '**/dist/**.egg',
      
      // Go build artifacts
      '**/vendor/**',
      
      // PHP build artifacts
      '**/vendor/composer/**'
    ];
    
    // Find all relevant build artifacts
    const artifactPaths: string[] = [];
    for (const pattern of artifactPatterns) {
      const paths = await glob(pattern, {
        cwd: config.rootDir,
        absolute: true,
        ignore: [
          ...(config.excludePaths || [])
        ]
      });
      artifactPaths.push(...paths);
    }
    
    // Limit the number of artifacts to scan
    const maxArtifacts = 100;
    const artifactsToScan = artifactPaths.slice(0, maxArtifacts);
    
    log.info(`Found ${artifactPaths.length} build artifacts, scanning ${artifactsToScan.length}`);
    
    // Scan each build artifact for framework information
    for (const artifactPath of artifactsToScan) {
      try {
        // Extract frameworks based on artifact type
        let detectedFrameworks: FrameworkInfo[] = [];
        
        // JavaScript/TypeScript artifacts
        if (artifactPath.endsWith('.js')) {
          try {
            const content = await readFileAsync(artifactPath, 'utf8');
            
            // Look for framework signatures in minified JS
            if (content.includes('React')) {
              detectedFrameworks.push({
                name: 'React',
                type: 'frontend',
                language: 'javascript',
                detectionMethod: 'build-artifacts',
                detectionConfidence: 0.7,
                location: artifactPath,
                usageFiles: [artifactPath]
              });
            }
            
            if (content.includes('Vue')) {
              detectedFrameworks.push({
                name: 'Vue.js',
                type: 'frontend',
                language: 'javascript',
                detectionMethod: 'build-artifacts',
                detectionConfidence: 0.7,
                location: artifactPath,
                usageFiles: [artifactPath]
              });
            }
            
            if (content.includes('Angular')) {
              detectedFrameworks.push({
                name: 'Angular',
                type: 'frontend',
                language: 'javascript',
                detectionMethod: 'build-artifacts',
                detectionConfidence: 0.7,
                location: artifactPath,
                usageFiles: [artifactPath]
              });
            }
          } catch (contentError) {
            // Skip files that can't be read
            continue;
          }
        }
        
        // Java artifacts
        if (artifactPath.endsWith('.jar')) {
          try {
            // Execute jar -tf command to list JAR contents
            const { stdout } = await execAsync(`jar -tf "${artifactPath}"`);
            
            if (stdout.includes('org/springframework')) {
              detectedFrameworks.push({
                name: 'Spring Framework',
                type: 'backend',
                language: 'java',
                detectionMethod: 'build-artifacts',
                detectionConfidence: 0.9,
                location: artifactPath,
                usageFiles: [artifactPath]
              });
            }
            
            if (stdout.includes('org/hibernate')) {
              detectedFrameworks.push({
                name: 'Hibernate',
                type: 'database',
                language: 'java',
                detectionMethod: 'build-artifacts',
                detectionConfidence: 0.9,
                location: artifactPath,
                usageFiles: [artifactPath]
              });
            }
          } catch (jarError) {
            // Skip JAR files that can't be processed
            continue;
          }
        }
        
        // .NET artifacts
        if (artifactPath.endsWith('.dll')) {
          // Could use tools like ilspy to analyze DLL content, but that's beyond the scope of this scanner
          const filename = path.basename(artifactPath);
          
          // Check for common .NET framework DLLs
          if (filename.startsWith('Microsoft.AspNetCore')) {
            detectedFrameworks.push({
              name: 'ASP.NET Core',
              type: 'backend',
              language: 'csharp',
              detectionMethod: 'build-artifacts',
              detectionConfidence: 0.9,
              location: artifactPath,
              usageFiles: [artifactPath]
            });
          }
          
          if (filename.startsWith('EntityFramework') || filename.startsWith('Microsoft.EntityFrameworkCore')) {
            detectedFrameworks.push({
              name: 'Entity Framework',
              type: 'database',
              language: 'csharp',
              detectionMethod: 'build-artifacts',
              detectionConfidence: 0.9,
              location: artifactPath,
              usageFiles: [artifactPath]
            });
          }
        }
        
        frameworks.push(...detectedFrameworks);
      } catch (artifactError) {
        log.debug(`Error processing artifact ${artifactPath}`, { error: artifactError });
      }
    }
  } catch (error) {
    log.error('Error detecting frameworks from artifacts', { error });
  }
  
  return frameworks;
}

/**
 * Detect frameworks from git history
 */
async function detectFrameworksFromGitHistory(
  config: FrameworkScannerConfig
): Promise<FrameworkInfo[]> {
  const frameworks: FrameworkInfo[] = [];
  
  try {
    // Check if we're in a git repository
    try {
      await execAsync('git rev-parse --is-inside-work-tree', { cwd: config.rootDir });
    } catch (gitError) {
      log.warn('Not in a git repository, skipping git history analysis');
      return [];
    }
    
    // Find important framework-related files that have been modified frequently
    const gitLog = async (file: string) => {
      try {
        const { stdout } = await execAsync(`git log --format="%H" -- "${file}"`, { cwd: config.rootDir });
        return stdout.trim().split('\n').filter(line => line.trim().length > 0).length;
      } catch (logError) {
        return 0;
      }
    };
    
    // Map of important framework files to their framework info
    const frameworkFiles: Record<string, { name: string, type: string, language: string }> = {
      'package.json': { name: 'Node.js', type: 'backend', language: 'javascript' },
      'pom.xml': { name: 'Maven', type: 'backend', language: 'java' },
      'build.gradle': { name: 'Gradle', type: 'backend', language: 'java' },
      'requirements.txt': { name: 'Python', type: 'backend', language: 'python' },
      'Gemfile': { name: 'Ruby', type: 'backend', language: 'ruby' },
      'composer.json': { name: 'PHP', type: 'backend', language: 'php' },
      'go.mod': { name: 'Go', type: 'backend', language: 'go' },
      '.csproj': { name: '.NET', type: 'backend', language: 'csharp' }
    };
    
    // Check commit history for framework files
    for (const [filename, info] of Object.entries(frameworkFiles)) {
      // Find all matching files
      const files = await glob(`**/${filename}`, {
        cwd: config.rootDir,
        absolute: true,
        ignore: [...(config.excludePaths || [])]
      });
      
      for (const file of files) {
        const commitCount = await gitLog(file);
        
        if (commitCount > 0) {
          frameworks.push({
            name: info.name,
            type: info.type,
            language: info.language,
            detectionMethod: 'git-history',
            detectionConfidence: 0.6,
            location: file,
            usageFiles: [file],
            usageExtent: Math.min(1.0, commitCount / 10) // Scale based on commit count (cap at 1.0)
          });
        }
      }
    }
    
    // Look for evidence of framework migrations in git history
    try {
      const { stdout: migrationCommits } = await execAsync(
        'git log --grep="migrate\|migration\|upgrade\|update" --pretty=format:"%s"',
        { cwd: config.rootDir }
      );
      
      const migrationLines = migrationCommits.split('\n').filter(line => line.trim().length > 0);
      
      // Common framework migration patterns
      const migrationPatterns: Record<string, { name: string, type: string, language?: string }> = {
        'react': { name: 'React', type: 'frontend', language: 'javascript' },
        'angular': { name: 'Angular', type: 'frontend', language: 'javascript' },
        'vue': { name: 'Vue.js', type: 'frontend', language: 'javascript' },
        'spring': { name: 'Spring', type: 'backend', language: 'java' },
        'django': { name: 'Django', type: 'backend', language: 'python' },
        'rails': { name: 'Ruby on Rails', type: 'backend', language: 'ruby' },
        'laravel': { name: 'Laravel', type: 'backend', language: 'php' },
        'symfony': { name: 'Symfony', type: 'backend', language: 'php' },
        'asp.net': { name: 'ASP.NET', type: 'backend', language: 'csharp' },
        'dotnet': { name: '.NET', type: 'backend', language: 'csharp' },
        'entity framework': { name: 'Entity Framework', type: 'database', language: 'csharp' },
        'ef core': { name: 'Entity Framework Core', type: 'database', language: 'csharp' },
        'hibernate': { name: 'Hibernate', type: 'database', language: 'java' },
        'jpa': { name: 'JPA', type: 'database', language: 'java' }
      };
      
      for (const line of migrationLines) {
        const lowerLine = line.toLowerCase();
        
        for (const [pattern, info] of Object.entries(migrationPatterns)) {
          if (lowerLine.includes(pattern)) {
            // Check for version numbers in the commit message
            let version: string | undefined;
            const versionMatch = lowerLine.match(new RegExp(`${pattern}\s+([0-9]+(\.[0-9]+)+)|(v[0-9]+(\.[0-9]+)+)`));
            if (versionMatch) {
              version = versionMatch[1] || versionMatch[3].substring(1); // remove 'v' prefix if present
            }
            
            frameworks.push({
              name: info.name,
              version,
              type: info.type,
              language: info.language,
              detectionMethod: 'git-history',
              detectionConfidence: 0.7,
              location: config.rootDir,
              usageExtent: 0.5 // Medium confidence since it's from commit messages
            });
            break;
          }
        }
      }
    } catch (grepError) {
      log.debug('Error searching git history for migrations', { error: grepError });
    }
  } catch (error) {
    log.error('Error detecting frameworks from git history', { error });
  }
  
  return frameworks;
}

/**
 * Detect frameworks from remote endpoints
 */
async function detectFrameworksFromRemote(
  config: FrameworkScannerConfig
): Promise<FrameworkInfo[]> {
  const frameworks: FrameworkInfo[] = [];
  
  if (!config.remoteEndpoints || config.remoteEndpoints.length === 0) {
    return frameworks;
  }
  
  try {
    for (const endpoint of config.remoteEndpoints) {
      try {
        log.info(`Scanning remote endpoint: ${endpoint.url}`);
        
        // Prepare curl command with appropriate headers
        let curlCommand = `curl -s -I "${endpoint.url}"`;
        
        // Add authentication if specified
        if (endpoint.auth) {
          switch (endpoint.auth.type) {
            case 'basic':
              curlCommand += ` -H "Authorization: Basic ${endpoint.auth.credentials}"`;
              break;
            case 'token':
              curlCommand += ` -H "Authorization: Bearer ${endpoint.auth.credentials}"`;
              break;
            case 'oauth':
              curlCommand += ` -H "Authorization: Bearer ${endpoint.auth.credentials}"`;
              break;
          }
        }
        
        // Execute the curl command to get headers
        const { stdout } = await execAsync(curlCommand);
        
        // Parse headers for framework identification
        // Many frameworks include identifying headers in HTTP responses
        const parseHeaders = (headerOutput: string): Record<string, string> => {
          const headers: Record<string, string> = {};
          const lines = headerOutput.split('\n');
          
          for (const line of lines) {
            const colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
              const name = line.substring(0, colonIndex).trim().toLowerCase();
              const value = line.substring(colonIndex + 1).trim();
              headers[name] = value;
            }
          }
          
          return headers;
        };
        
        const headers = parseHeaders(stdout);
        
        // Check for framework-specific headers
        if (headers['x-powered-by']) {
          const poweredBy = headers['x-powered-by'].toLowerCase();
          
          if (poweredBy.includes('php')) {
            frameworks.push({
              name: 'PHP',
              type: 'backend',
              language: 'php',
              detectionMethod: 'remote-scan',
              detectionConfidence: 0.9,
              location: endpoint.url,
              usageExtent: 0.7
            });
            
            if (poweredBy.includes('laravel')) {
              frameworks.push({
                name: 'Laravel',
                type: 'backend',
                language: 'php',
                detectionMethod: 'remote-scan',
                detectionConfidence: 0.9,
                location: endpoint.url,
                usageExtent: 0.7
              });
            }
          }
          
          if (poweredBy.includes('asp.net')) {
            frameworks.push({
              name: 'ASP.NET',
              type: 'backend',
              language: 'csharp',
              detectionMethod: 'remote-scan',
              detectionConfidence: 0.9,
              location: endpoint.url,
              usageExtent: 0.7
            });
          }
          
          if (poweredBy.includes('express')) {
            frameworks.push({
              name: 'Express.js',
              type: 'backend',
              language: 'javascript',
              detectionMethod: 'remote-scan',
              detectionConfidence: 0.9,
              location: endpoint.url,
              usageExtent: 0.7
            });
          }
        }
        
        if (headers['server']) {
          const server = headers['server'].toLowerCase();
          
          if (server.includes('apache')) {
            frameworks.push({
              name: 'Apache HTTP Server',
              type: 'backend',
              detectionMethod: 'remote-scan',
              detectionConfidence: 0.9,
              location: endpoint.url,
              usageExtent: 0.7
            });
          }
          
          if (server.includes('nginx')) {
            frameworks.push({
              name: 'NGINX',
              type: 'backend',
              detectionMethod: 'remote-scan',
              detectionConfidence: 0.9,
              location: endpoint.url,
              usageExtent: 0.7
            });
          }
          
          if (server.includes('microsoft-iis')) {
            frameworks.push({
              name: 'IIS',
              type: 'backend',
              detectionMethod: 'remote-scan',
              detectionConfidence: 0.9,
              location: endpoint.url,
              usageExtent: 0.7
            });
          }
        }
        
        // Get the full page content to look for more framework signatures
        curlCommand = `curl -s "${endpoint.url}"`;
        
        // Add authentication if specified (same as before)
        if (endpoint.auth) {
          switch (endpoint.auth.type) {
            case 'basic':
              curlCommand += ` -H "Authorization: Basic ${endpoint.auth.credentials}"`;
              break;
            case 'token':
              curlCommand += ` -H "Authorization: Bearer ${endpoint.auth.credentials}"`;
              break;
            case 'oauth':
              curlCommand += ` -H "Authorization: Bearer ${endpoint.auth.credentials}"`;
              break;
          }
        }
        
        // Execute the curl command to get page content
        const { stdout: content } = await execAsync(curlCommand);
        
        // Check for framework-specific content signatures
        if (content.includes('ng-') || content.includes('ng-app') || content.includes('angular')) {
          frameworks.push({
            name: 'Angular',
            type: 'frontend',
            language: 'javascript',
            detectionMethod: 'remote-scan',
            detectionConfidence: 0.8,
            location: endpoint.url,
            usageExtent: 0.7
          });
        }
        
        if (content.includes('react') || content.includes('ReactDOM')) {
          frameworks.push({
            name: 'React',
            type: 'frontend',
            language: 'javascript',
            detectionMethod: 'remote-scan',
            detectionConfidence: 0.8,
            location: endpoint.url,
            usageExtent: 0.7
          });
        }
        
        if (content.includes('vue') || content.includes('Vue.') || content.includes('v-')) {
          frameworks.push({
            name: 'Vue.js',
            type: 'frontend',
            language: 'javascript',
            detectionMethod: 'remote-scan',
            detectionConfidence: 0.8,
            location: endpoint.url,
            usageExtent: 0.7
          });
        }
        
        if (content.includes('jquery') || content.includes('jQuery')) {
          frameworks.push({
            name: 'jQuery',
            type: 'frontend',
            language: 'javascript',
            detectionMethod: 'remote-scan',
            detectionConfidence: 0.8,
            location: endpoint.url,
            usageExtent: 0.6
          });
        }
        
        if (content.includes('bootstrap')) {
          frameworks.push({
            name: 'Bootstrap',
            type: 'frontend',
            language: 'css',
            detectionMethod: 'remote-scan',
            detectionConfidence: 0.8,
            location: endpoint.url,
            usageExtent: 0.6
          });
        }
        
        if (content.includes('tailwind')) {
          frameworks.push({
            name: 'Tailwind CSS',
            type: 'frontend',
            language: 'css',
            detectionMethod: 'remote-scan',
            detectionConfidence: 0.8,
            location: endpoint.url,
            usageExtent: 0.6
          });
        }
      } catch (endpointError) {
        log.warn(`Error scanning remote endpoint ${endpoint.url}`, { error: endpointError });
      }
    }
  } catch (error) {
    log.error('Error detecting frameworks from remote endpoints', { error });
  }
  
  return frameworks;
}

/**
 * Deduplicate frameworks detected by multiple methods
 */
function deduplicateFrameworks(frameworks: FrameworkInfo[]): FrameworkInfo[] {
  const frameworkMap = new Map<string, FrameworkInfo>();
  
  for (const fw of frameworks) {
    const key = fw.name.toLowerCase();
    
    if (frameworkMap.has(key)) {
      const existing = frameworkMap.get(key)!;
      
      // Merge the framework info, preferring higher confidence detections
      if (fw.detectionConfidence > existing.detectionConfidence) {
        // Keep the higher confidence detection's base properties
        existing.type = fw.type;
        existing.language = fw.language || existing.language;
        existing.detectionMethod = fw.detectionMethod;
        existing.detectionConfidence = fw.detectionConfidence;
        existing.location = fw.location || existing.location;
      }
      
      // Merge version information (prefer concrete versions over undefined)
      if (fw.version && (!existing.version || fw.version > existing.version)) {
        existing.version = fw.version;
      }
      
      // Merge latest version information
      if (fw.latestVersion && (!existing.latestVersion || fw.latestVersion > existing.latestVersion)) {
        existing.latestVersion = fw.latestVersion;
      }
      
      // Merge usage files
      if (fw.usageFiles) {
        existing.usageFiles = [...new Set([...(existing.usageFiles || []), ...fw.usageFiles])];
      }
      
      // Merge dependent components
      if (fw.dependentComponents) {
        existing.dependentComponents = [...new Set([...(existing.dependentComponents || []), ...fw.dependentComponents])];
      }
      
      // Other properties like isOutdated, isVulnerable, etc. will be set during the checkFrameworkForIssues phase
    } else {
      frameworkMap.set(key, { ...fw });
    }
  }
  
  return Array.from(frameworkMap.values());
}

/**
 * Check framework for issues
 */
async function checkFrameworkForIssues(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Check for updates
    await checkForFrameworkUpdates(fw, config);
    
    // Check for vulnerabilities if configured
    if (config.checkVulnerabilities) {
      await checkForFrameworkVulnerabilities(fw, config);
    }
    
    // Check if framework is deprecated or approaching EOL
    await checkIfFrameworkDeprecated(fw, config);
    
    // Check for end of life status
    await checkFrameworkLifecycle(fw, config);
    
    // Assess migration complexity if configured
    if (config.assessMigrationComplexity) {
      await assessMigrationComplexity(fw, config);
    }
  } catch (error) {
    log.warn(`Error checking framework ${fw.name} for issues`, { error });
  }
}

/**
 * Check if framework has available updates
 */
async function checkForFrameworkUpdates(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Try to get latest version from the knowledge base first
    const knowledgeBaseInfo = getFrameworkInfoFromKnowledgeBase(fw.name, config);
    if (knowledgeBaseInfo && knowledgeBaseInfo.latestVersion) {
      fw.latestVersion = knowledgeBaseInfo.latestVersion;
      fw.documentationUrl = knowledgeBaseInfo.documentationUrl;
      fw.upgradeGuideUrl = knowledgeBaseInfo.upgradeGuideUrl;
    }
    
    // If we have both current and latest version, compare them
    if (fw.version && fw.latestVersion) {
      try {
        const semver = require('semver');
        fw.isOutdated = semver.lt(fw.version, fw.latestVersion);
      } catch (semverError) {
        // Basic version comparison if semver is not available
        fw.isOutdated = fw.version !== fw.latestVersion;
      }
      return;
    }
    
    // If we don't have the latest version, try to fetch it from the relevant package registry
    if (fw.language === 'javascript' || fw.language === 'typescript') {
      await checkNpmUpdates(fw, config);
    } else if (fw.language === 'python') {
      await checkPyPIUpdates(fw, config);
    } else if (fw.language === 'java') {
      await checkMavenUpdates(fw, config);
    } else if (fw.language === 'ruby') {
      await checkRubyGemsUpdates(fw, config);
    } else if (fw.language === 'php') {
      await checkPackagistUpdates(fw, config);
    } else if (fw.language === 'csharp') {
      await checkNuGetUpdates(fw, config);
    } else if (fw.language === 'go') {
      await checkGoUpdates(fw, config);
    }
  } catch (error) {
    log.warn(`Error checking updates for framework ${fw.name}`, { error });
  }
}

/**
 * Get framework info from knowledge base
 */
function getFrameworkInfoFromKnowledgeBase(
  frameworkName: string,
  config: FrameworkScannerConfig
): {
  latestVersion?: string;
  documentationUrl?: string;
  upgradeGuideUrl?: string;
  isDeprecated?: boolean;
  endOfLifeDate?: Date;
  endOfLifeDetails?: {
    announcementDate?: Date;
    endOfLifeUrl?: string;
    recommendedAlternatives?: string[];
    migrationPath?: string;
  };
} | null {
  try {
    // Check if custom knowledge base path is provided
    if (config.knowledgeBasePath && fs.existsSync(config.knowledgeBasePath)) {
      try {
        const knowledgeBase = JSON.parse(fs.readFileSync(config.knowledgeBasePath, 'utf8'));
        const normalizedName = frameworkName.toLowerCase();
        
        // Look for exact matches first
        if (knowledgeBase[normalizedName]) {
          return knowledgeBase[normalizedName];
        }
        
        // Then look for partial matches (e.g. "React" should match "react")
        for (const [name, info] of Object.entries(knowledgeBase)) {
          if (name.toLowerCase().includes(normalizedName) || normalizedName.includes(name.toLowerCase())) {
            return info as any;
          }
        }
      } catch (kbError) {
        log.warn(`Error reading framework knowledge base`, { error: kbError });
      }
    }
    
    // Alternatively, use a hardcoded knowledge base for common frameworks
    // This is a simplified version - a real implementation would have a comprehensive database
    const hardcodedKnowledgeBase: Record<string, {
      latestVersion?: string;
      documentationUrl?: string;
      upgradeGuideUrl?: string;
      isDeprecated?: boolean;
      endOfLifeDate?: Date;
      endOfLifeDetails?: {
        announcementDate?: Date;
        endOfLifeUrl?: string;
        recommendedAlternatives?: string[];
        migrationPath?: string;
      };
    }> = {
      'react': {
        latestVersion: '18.2.0',
        documentationUrl: 'https://reactjs.org/docs/getting-started.html',
        upgradeGuideUrl: 'https://reactjs.org/blog/2022/03/08/react-18-upgrade-guide.html'
      },
      'angular': {
        latestVersion: '16.0.0',
        documentationUrl: 'https://angular.io/docs',
        upgradeGuideUrl: 'https://update.angular.io/'
      },
      'vue.js': {
        latestVersion: '3.3.4',
        documentationUrl: 'https://vuejs.org/guide/introduction.html',
        upgradeGuideUrl: 'https://v3-migration.vuejs.org/'
      },
      'django': {
        latestVersion: '4.2.1',
        documentationUrl: 'https://docs.djangoproject.com/en/4.2/',
        upgradeGuideUrl: 'https://docs.djangoproject.com/en/4.2/howto/upgrade-version/'
      },
      'flask': {
        latestVersion: '2.3.2',
        documentationUrl: 'https://flask.palletsprojects.com/en/2.3.x/',
        upgradeGuideUrl: 'https://flask.palletsprojects.com/en/2.3.x/upgrading/'
      },
      'spring framework': {
        latestVersion: '6.0.9',
        documentationUrl: 'https://docs.spring.io/spring-framework/docs/current/reference/html/',
        upgradeGuideUrl: 'https://github.com/spring-projects/spring-framework/wiki/Upgrading-to-Spring-Framework-6.x'
      },
      'spring boot': {
        latestVersion: '3.1.0',
        documentationUrl: 'https://docs.spring.io/spring-boot/docs/current/reference/html/',
        upgradeGuideUrl: 'https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.0-Migration-Guide'
      },
      'laravel': {
        latestVersion: '10.10.1',
        documentationUrl: 'https://laravel.com/docs/10.x',
        upgradeGuideUrl: 'https://laravel.com/docs/10.x/upgrade'
      },
      'asp.net core': {
        latestVersion: '7.0.5',
        documentationUrl: 'https://learn.microsoft.com/en-us/aspnet/core/?view=aspnetcore-7.0',
        upgradeGuideUrl: 'https://learn.microsoft.com/en-us/aspnet/core/migration/60-70?view=aspnetcore-7.0'
      },
      'ruby on rails': {
        latestVersion: '7.0.4',
        documentationUrl: 'https://guides.rubyonrails.org/',
        upgradeGuideUrl: 'https://guides.rubyonrails.org/upgrading_ruby_on_rails.html'
      },
      'express.js': {
        latestVersion: '4.18.2',
        documentationUrl: 'https://expressjs.com/',
        upgradeGuideUrl: 'https://expressjs.com/en/guide/migrating-5.html',
        endOfLifeDetails: {
          endOfLifeUrl: 'https://expressjs.com/en/guide/migrating-5.html',
          migrationPath: 'Migrate to Express 5 or consider alternatives like Fastify or Koa'
        }
      },
      'jquery': {
        latestVersion: '3.7.0',
        documentationUrl: 'https://api.jquery.com/',
        upgradeGuideUrl: 'https://jquery.com/upgrade-guide/3.0/',
        isDeprecated: false, // Not officially deprecated but usage is declining
        endOfLifeDetails: {
          migrationPath: 'Consider using vanilla JavaScript or modern frameworks like React/Vue/Angular'
        }
      },
      'bootstrap': {
        latestVersion: '5.3.0',
        documentationUrl: 'https://getbootstrap.com/docs/5.3/getting-started/introduction/',
        upgradeGuideUrl: 'https://getbootstrap.com/docs/5.3/migration/'
      },
      'angular.js': {
        latestVersion: '1.8.2',
        documentationUrl: 'https://docs.angularjs.org/guide',
        upgradeGuideUrl: 'https://docs.angularjs.org/guide/migration',
        isDeprecated: true,
        endOfLifeDate: new Date('2022-01-01'),
        endOfLifeDetails: {
          announcementDate: new Date('2021-01-01'),
          endOfLifeUrl: 'https://blog.angular.io/discontinued-long-term-support-for-angularjs-1-6970aa08e0f6',
          recommendedAlternatives: ['Angular (2+)'],
          migrationPath: 'Migrate to Angular 2+ using the ngUpgrade module'
        }
      },
      'ember.js': {
        latestVersion: '4.2.0',
        documentationUrl: 'https://guides.emberjs.com/release/',
        upgradeGuideUrl: 'https://guides.emberjs.com/release/upgrading/'
      },
      'backbone.js': {
        latestVersion: '1.5.0',
        documentationUrl: 'https://backbonejs.org/',
        isDeprecated: false, // Not officially deprecated but usage is declining
        endOfLifeDetails: {
          migrationPath: 'Consider migrating to modern frameworks like React/Vue/Angular'
        }
      },
      'tensorflow': {
        latestVersion: '2.12.0',
        documentationUrl: 'https://www.tensorflow.org/api_docs',
        upgradeGuideUrl: 'https://www.tensorflow.org/guide/migrate'
      },
      'pytorch': {
        latestVersion: '2.0.1',
        documentationUrl: 'https://pytorch.org/docs/stable/index.html',
        upgradeGuideUrl: 'https://pytorch.org/blog/pytorch-2.0-release/'
      },
      'kubernetes': {
        latestVersion: '1.27.2',
        documentationUrl: 'https://kubernetes.io/docs/home/',
        upgradeGuideUrl: 'https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade/'
      },
      'docker': {
        latestVersion: '24.0.2',
        documentationUrl: 'https://docs.docker.com/',
        upgradeGuideUrl: 'https://docs.docker.com/engine/install/'
      },
      'python': {
        latestVersion: '3.11.3',
        documentationUrl: 'https://docs.python.org/3/',
        upgradeGuideUrl: 'https://docs.python.org/3/whatsnew/3.11.html',
        endOfLifeDetails: {
          endOfLifeUrl: 'https://devguide.python.org/versions/'
        }
      },
      'node.js': {
        latestVersion: '20.2.0',
        documentationUrl: 'https://nodejs.org/en/docs/',
        upgradeGuideUrl: 'https://nodejs.org/en/blog/release/v20.0.0',
        endOfLifeDetails: {
          endOfLifeUrl: 'https://nodejs.org/en/about/releases/'
        }
      },
      'php': {
        latestVersion: '8.2.6',
        documentationUrl: 'https://www.php.net/docs.php',
        upgradeGuideUrl: 'https://www.php.net/manual/en/migration82.php',
        endOfLifeDetails: {
          endOfLifeUrl: 'https://www.php.net/supported-versions.php'
        }
      },
      'java': {
        latestVersion: '20.0.1',
        documentationUrl: 'https://docs.oracle.com/en/java/',
        upgradeGuideUrl: 'https://www.oracle.com/java/technologies/javase/20-relnote-issues.html',
        endOfLifeDetails: {
          endOfLifeUrl: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html'
        }
      },
      'ruby': {
        latestVersion: '3.2.2',
        documentationUrl: 'https://www.ruby-lang.org/en/documentation/',
        upgradeGuideUrl: 'https://www.ruby-lang.org/en/news/2022/12/25/ruby-3-2-0-released/',
        endOfLifeDetails: {
          endOfLifeUrl: 'https://www.ruby-lang.org/en/downloads/branches/'
        }
      },
      'go': {
        latestVersion: '1.20.4',
        documentationUrl: 'https://go.dev/doc/',
        upgradeGuideUrl: 'https://go.dev/doc/go1.20',
        endOfLifeDetails: {
          endOfLifeUrl: 'https://go.dev/doc/devel/release'
        }
      },
      '.net framework': {
        latestVersion: '4.8.1',
        documentationUrl: 'https://learn.microsoft.com/en-us/dotnet/framework/',
        upgradeGuideUrl: 'https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/',
        isDeprecated: true,
        endOfLifeDate: new Date('2025-01-14'), // Some versions earlier
        endOfLifeDetails: {
          endOfLifeUrl: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework',
          recommendedAlternatives: ['.NET Core', '.NET 5+'],
          migrationPath: 'Migrate to .NET Core or .NET 5+ (unified platform)'
        }
      },
      '.net core': {
        latestVersion: '3.1.32',
        documentationUrl: 'https://learn.microsoft.com/en-us/dotnet/core/',
        upgradeGuideUrl: 'https://learn.microsoft.com/en-us/dotnet/core/compatibility/3.1-5.0',
        isDeprecated: true,
        endOfLifeDate: new Date('2022-12-13'),
        endOfLifeDetails: {
          endOfLifeUrl: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core',
          recommendedAlternatives: ['.NET 5+'],
          migrationPath: 'Migrate to .NET 5+ (unified platform)'
        }
      },
      '.net': {
        latestVersion: '7.0.5',
        documentationUrl: 'https://learn.microsoft.com/en-us/dotnet/',
        upgradeGuideUrl: 'https://learn.microsoft.com/en-us/dotnet/core/compatibility/6.0-7.0',
        endOfLifeDetails: {
          endOfLifeUrl: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core'
        }
      }
    };
    
    // Normalize framework name for lookup (case-insensitive)
    const normalizedName = frameworkName.toLowerCase();
    
    // Try to find exact matches first
    if (hardcodedKnowledgeBase[normalizedName]) {
      return hardcodedKnowledgeBase[normalizedName];
    }
    
    // Then try to find partial matches
    for (const [name, info] of Object.entries(hardcodedKnowledgeBase)) {
      if (normalizedName.includes(name) || name.includes(normalizedName)) {
        return info;
      }
    }
    
    return null;
  } catch (error) {
    log.warn(`Error getting framework info from knowledge base for ${frameworkName}`, { error });
    return null;
  }
}

/**
 * Check for NPM package updates
 */
async function checkNpmUpdates(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Extract the package name (handle scoped packages like @angular/core)
    let packageName = fw.name;
    
    // For some frameworks, we need to map the framework name to the package name
    const frameworkToPackageMap: Record<string, string> = {
      'React': 'react',
      'Vue.js': 'vue',
      'Angular': '@angular/core',
      'Express.js': 'express',
      'Next.js': 'next',
      'Nuxt.js': 'nuxt',
      'jQuery': 'jquery',
      'Svelte': 'svelte'
    };
    
    if (frameworkToPackageMap[fw.name]) {
      packageName = frameworkToPackageMap[fw.name];
    }
    
    // Use npm registry API to check for latest version
    const { stdout } = await execAsync(`npm view ${packageName} version --json`);
    
    try {
      const latestVersion = JSON.parse(stdout.trim());
      fw.latestVersion = latestVersion;
      
      // Compare versions to determine if outdated
      if (fw.version !== undefined && fw.version !== 'unknown' && fw.version !== fw.latestVersion) {
        // Use semver to compare versions if available
        try {
          const semver = require('semver');
          fw.isOutdated = semver.lt(fw.version, fw.latestVersion);
        } catch (semverError) {
          // Basic version comparison if semver is not available
          fw.isOutdated = fw.version !== fw.latestVersion;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing npm view output for ${fw.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking NPM updates for ${fw.name}`, { error });
  }
}

/**
 * Check for PyPI package updates
 */
async function checkPyPIUpdates(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Extract the package name
    let packageName = fw.name.toLowerCase();
    
    // For some frameworks, we need to map the framework name to the package name
    const frameworkToPackageMap: Record<string, string> = {
      'Django': 'django',
      'Flask': 'flask',
      'FastAPI': 'fastapi',
      'SQLAlchemy': 'sqlalchemy',
      'pandas': 'pandas',
      'NumPy': 'numpy',
      'TensorFlow': 'tensorflow',
      'PyTorch': 'torch'
    };
    
    if (frameworkToPackageMap[fw.name]) {
      packageName = frameworkToPackageMap[fw.name];
    }
    
    // Use PyPI API to check for latest version
    const { stdout } = await execAsync(`curl -s https://pypi.org/pypi/${packageName}/json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      fw.latestVersion = packageInfo.info.version;
      
      // Compare versions to determine if outdated
      if (fw.version !== undefined && fw.version !== 'unknown' && fw.version !== fw.latestVersion) {
        // Use semver to compare versions if available
        try {
          const semver = require('semver');
          fw.isOutdated = semver.lt(fw.version, fw.latestVersion);
        } catch (semverError) {
          // Basic version comparison if semver is not available
          fw.isOutdated = fw.version !== fw.latestVersion;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing PyPI API output for ${fw.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking PyPI updates for ${fw.name}`, { error });
  }
}

/**
 * Check for Maven package updates
 */
async function checkMavenUpdates(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Extract groupId and artifactId if available
    let groupId: string;
    let artifactId: string;
    
    if (fw.name.includes(':')) {
      [groupId, artifactId] = fw.name.split(':');
    } else {
      // For known frameworks, map the name to groupId and artifactId
      const frameworkToMavenMap: Record<string, { groupId: string, artifactId: string }> = {
        'Spring Framework': { groupId: 'org.springframework', artifactId: 'spring-core' },
        'Spring Boot': { groupId: 'org.springframework.boot', artifactId: 'spring-boot' },
        'Hibernate': { groupId: 'org.hibernate', artifactId: 'hibernate-core' },
        'JPA': { groupId: 'javax.persistence', artifactId: 'javax.persistence-api' }
      };
      
      if (frameworkToMavenMap[fw.name]) {
        groupId = frameworkToMavenMap[fw.name].groupId;
        artifactId = frameworkToMavenMap[fw.name].artifactId;
      } else {
        // If we can't map, return early
        return;
      }
    }
    
    // Use Maven Central API to check for latest version
    const { stdout } = await execAsync(`curl -s "https://search.maven.org/solrsearch/select?q=g:%22${groupId}%22+AND+a:%22${artifactId}%22&rows=1&wt=json"`);
    
    try {
      const searchResult = JSON.parse(stdout);
      
      if (searchResult.response && searchResult.response.docs && searchResult.response.docs.length > 0) {
        fw.latestVersion = searchResult.response.docs[0].latestVersion;
        
        // Compare versions to determine if outdated
        if (fw.version !== undefined && fw.version !== 'unknown' && fw.version !== fw.latestVersion) {
          // Use semver to compare versions if available
          try {
            const semver = require('semver');
            fw.isOutdated = semver.lt(fw.version, fw.latestVersion);
          } catch (semverError) {
            // Basic version comparison if semver is not available
            fw.isOutdated = fw.version !== fw.latestVersion;
          }
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing Maven Central API output for ${fw.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking Maven updates for ${fw.name}`, { error });
  }
}

/**
 * Check for RubyGems package updates
 */
async function checkRubyGemsUpdates(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Extract the gem name
    let gemName = fw.name.toLowerCase().replace(/\s/g, '-');
    
    // For some frameworks, we need to map the framework name to the gem name
    const frameworkToGemMap: Record<string, string> = {
      'Ruby on Rails': 'rails',
      'Sinatra': 'sinatra',
      'RSpec': 'rspec',
      'Minitest': 'minitest'
    };
    
    if (frameworkToGemMap[fw.name]) {
      gemName = frameworkToGemMap[fw.name];
    }
    
    // Use RubyGems API to check for latest version
    const { stdout } = await execAsync(`curl -s https://rubygems.org/api/v1/gems/${gemName}.json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      fw.latestVersion = packageInfo.version;
      
      // Compare versions to determine if outdated
      if (fw.version !== undefined && fw.version !== 'unknown' && fw.version !== fw.latestVersion) {
        // Use semver to compare versions if available
        try {
          const semver = require('semver');
          fw.isOutdated = semver.lt(fw.version, fw.latestVersion);
        } catch (semverError) {
          // Basic version comparison if semver is not available
          fw.isOutdated = fw.version !== fw.latestVersion;
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing RubyGems API output for ${fw.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking RubyGems updates for ${fw.name}`, { error });
  }
}

/**
 * Check for Packagist package updates
 */
async function checkPackagistUpdates(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Extract the package name
    let packageName = fw.name.toLowerCase().replace(/\s/g, '-');
    
    // For some frameworks, we need to map the framework name to the package name
    const frameworkToPackageMap: Record<string, string> = {
      'Laravel': 'laravel/framework',
      'Symfony': 'symfony/symfony',
      'Slim': 'slim/slim',
      'CodeIgniter': 'codeigniter/framework'
    };
    
    if (frameworkToPackageMap[fw.name]) {
      packageName = frameworkToPackageMap[fw.name];
    }
    
    // Use Packagist API to check for latest version
    const { stdout } = await execAsync(`curl -s https://repo.packagist.org/p2/${packageName}.json`);
    
    try {
      const packageInfo = JSON.parse(stdout);
      
      if (packageInfo.packages && packageInfo.packages[packageName]) {
        // Get the latest stable version
        const versions = packageInfo.packages[packageName];
        const stableVersions = Object.keys(versions).filter(v => !v.includes('-'));
        
        if (stableVersions.length > 0) {
          // Sort versions and get the latest
          stableVersions.sort((a, b) => {
            try {
              const semver = require('semver');
              return semver.gt(a, b) ? -1 : 1;
            } catch (semverError) {
              return a > b ? -1 : 1; // Basic comparison
            }
          });
          
          fw.latestVersion = stableVersions[0];
          
          // Compare versions to determine if outdated
          if (fw.version !== undefined && fw.version !== 'unknown' && fw.version !== fw.latestVersion) {
            // Use semver to compare versions if available
            try {
              const semver = require('semver');
              fw.isOutdated = semver.lt(fw.version, fw.latestVersion);
            } catch (semverError) {
              // Basic version comparison if semver is not available
              fw.isOutdated = fw.version !== fw.latestVersion;
            }
          }
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing Packagist API output for ${fw.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking Packagist updates for ${fw.name}`, { error });
  }
}

/**
 * Check for NuGet package updates
 */
async function checkNuGetUpdates(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Extract the package name
    let packageName = fw.name;
    
    // For some frameworks, we need to map the framework name to the package name
    const frameworkToPackageMap: Record<string, string> = {
      'ASP.NET Core': 'Microsoft.AspNetCore.App',
      'Entity Framework Core': 'Microsoft.EntityFrameworkCore',
      '.NET': 'Microsoft.NETCore.App'
    };
    
    if (frameworkToPackageMap[fw.name]) {
      packageName = frameworkToPackageMap[fw.name];
    }
    
    // Use NuGet API to check for latest version
    const { stdout } = await execAsync(`curl -s "https://api-v2v3search-0.nuget.org/query?q=${packageName}&prerelease=false"`);
    
    try {
      const searchResult = JSON.parse(stdout);
      
      if (searchResult.data && searchResult.data.length > 0) {
        // Find the package that matches exactly
        const exactMatch = searchResult.data.find((pkg: any) => 
          pkg.id.toLowerCase() === packageName.toLowerCase()
        );
        
        if (exactMatch) {
          fw.latestVersion = exactMatch.version;
          
          // Compare versions to determine if outdated
          if (fw.version !== undefined && fw.version !== 'unknown' && fw.version !== fw.latestVersion) {
            // Use semver to compare versions if available
            try {
              const semver = require('semver');
              fw.isOutdated = semver.lt(fw.version, fw.latestVersion);
            } catch (semverError) {
              // Basic version comparison if semver is not available
              fw.isOutdated = fw.version !== fw.latestVersion;
            }
          }
        }
      }
    } catch (jsonError) {
      log.warn(`Error parsing NuGet API output for ${fw.name}`, { error: jsonError });
    }
  } catch (error) {
    log.warn(`Error checking NuGet updates for ${fw.name}`, { error });
  }
}

/**
 * Check for Go package updates
 */
async function checkGoUpdates(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Extract the package name
    const packageName = fw.name;
    
    // For Go modules, we need a more specialized approach
    if (packageName.includes('github.com/') || packageName.includes('golang.org/') || packageName.includes('k8s.io/')) {
      try {
        // Use proxy.golang.org API to check for latest version
        const { stdout } = await execAsync(`curl -s "https://proxy.golang.org/${packageName}/@v/list"`);
        
        if (stdout.trim()) {
          const versions = stdout.trim().split('\n');
          
          if (versions.length > 0) {
            // Sort versions and get the latest stable version
            const stableVersions = versions.filter(v => 
              !v.includes('-beta') && 
              !v.includes('-alpha') && 
              !v.includes('-rc')
            );
            
            if (stableVersions.length > 0) {
              // Sort versions and get the latest
              stableVersions.sort((a, b) => {
                try {
                  const semver = require('semver');
                  return semver.gt(a, b) ? -1 : 1;
                } catch (semverError) {
                  return a > b ? -1 : 1; // Basic comparison
                }
              });
              
              fw.latestVersion = stableVersions[0];
              
              // Compare versions to determine if outdated
              if (fw.version !== undefined && fw.version !== 'unknown' && fw.version !== fw.latestVersion) {
                // Use semver to compare versions if available
                try {
                  const semver = require('semver');
                  fw.isOutdated = semver.lt(fw.version, fw.latestVersion);
                } catch (semverError) {
                  // Basic version comparison if semver is not available
                  fw.isOutdated = fw.version !== fw.latestVersion;
                }
              }
            }
          }
        }
      } catch (proxyError) {
        log.warn(`Error checking Go module updates via proxy for ${fw.name}`, { error: proxyError });
      }
    } else if (packageName === 'Go') {
      // Special case for the Go language itself
      try {
        const { stdout } = await execAsync(`curl -s https://go.dev/dl/?mode=json`);
        
        try {
          const releases = JSON.parse(stdout);
          
          if (releases && releases.length > 0) {
            // Get the latest stable release
            const latestRelease = releases[0];
            const latestVersion = latestRelease.version.replace('go', '');
            
            fw.latestVersion = latestVersion;
            
            // Compare versions to determine if outdated
            if (fw.version !== undefined && fw.version !== 'unknown' && fw.version !== fw.latestVersion) {
              // Use semver to compare versions if available
              try {
                const semver = require('semver');
                fw.isOutdated = semver.lt(fw.version, fw.latestVersion);
              } catch (semverError) {
                // Basic version comparison if semver is not available
                fw.isOutdated = fw.version !== fw.latestVersion;
              }
            }
          }
        } catch (jsonError) {
          log.warn(`Error parsing Go releases API output`, { error: jsonError });
        }
      } catch (dlError) {
        log.warn(`Error checking Go language updates`, { error: dlError });
      }
    }
  } catch (error) {
    log.warn(`Error checking Go updates for ${fw.name}`, { error });
  }
}

/**
 * Check for framework vulnerabilities
 */
async function checkForFrameworkVulnerabilities(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Check custom database first if configured
    if (config.vulnerabilityDbPaths?.frameworks && fs.existsSync(config.vulnerabilityDbPaths.frameworks)) {
      try {
        const vulnDb = JSON.parse(await readFileAsync(config.vulnerabilityDbPaths.frameworks, 'utf8'));
        
        // Normalize framework name for lookup (case-insensitive)
        const normalizedName = fw.name.toLowerCase();
        
        // Check for exact matches first
        if (vulnDb[normalizedName]) {
          processVulnerabilityData(fw, vulnDb[normalizedName]);
          return;
        }
        
        // Then check for partial matches
        for (const [name, vulns] of Object.entries(vulnDb)) {
          if (normalizedName.includes(name) || name.includes(normalizedName)) {
            processVulnerabilityData(fw, vulns as any);
            return;
          }
        }
      } catch (dbError) {
        log.warn(`Error reading framework vulnerability database`, { error: dbError });
      }
    }
    
    // If no custom database or no vulnerabilities found, try to get from knowledge base
    // This would be a simplified approach - a real implementation would use a proper vulnerability database
    await checkForKnownVulnerableFrameworks(fw, config);
  } catch (error) {
    log.warn(`Error checking vulnerabilities for framework ${fw.name}`, { error });
  }
}

/**
 * Process vulnerability data from a database
 */
function processVulnerabilityData(
  fw: FrameworkInfo,
  vulnerabilities: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affected_versions: string;
    fixed_in_version?: string;
    cve_ids?: string[];
    url?: string;
  }>
): void {
  const affectedVulns = vulnerabilities.filter(vuln => 
    isVersionAffected(fw.version || 'unknown', vuln.affected_versions)
  );
  
  if (affectedVulns.length > 0) {
    fw.vulnerabilities = affectedVulns.map(vuln => ({
      severity: vuln.severity,
      description: vuln.description,
      affectedVersions: vuln.affected_versions,
      fixedInVersion: vuln.fixed_in_version,
      url: vuln.url,
      cveIds: vuln.cve_ids
    }));
    
    fw.isVulnerable = true;
  }
}

/**
 * Check for known vulnerable frameworks
 */
async function checkForKnownVulnerableFrameworks(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  // This is a very simplified example - a real implementation would use a proper vulnerability database
  const knownVulnerableFrameworks: Record<string, Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affected_versions: string;
    fixed_in_version?: string;
    cve_ids?: string[];
    url?: string;
  }>> = {
    'spring framework': [
      {
        severity: 'critical',
        description: 'Spring Framework RCE vulnerability (Spring4Shell)',
        affected_versions: '<=5.3.17,<=5.2.19',
        fixed_in_version: '5.3.18,5.2.20',
        cve_ids: ['CVE-2022-22965'],
        url: 'https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement'
      }
    ],
    'log4j': [
      {
        severity: 'critical',
        description: 'Remote code execution vulnerability in Log4j (Log4Shell)',
        affected_versions: '>=2.0.0,<=2.14.1',
        fixed_in_version: '2.15.0',
        cve_ids: ['CVE-2021-44228'],
        url: 'https://logging.apache.org/log4j/2.x/security.html'
      }
    ],
    'angular.js': [
      {
        severity: 'high',
        description: 'AngularJS expression sandbox bypass (deprecated in 1.7+)',
        affected_versions: '<1.8.0',
        fixed_in_version: '1.8.0',
        cve_ids: ['CVE-2019-10768'],
        url: 'https://docs.angularjs.org/guide/security'
      }
    ],
    'django': [
      {
        severity: 'high',
        description: 'SQL injection vulnerability in Django QuerySet.raw()',
        affected_versions: '>=3.0,<3.0.14 || >=3.1,<3.1.12 || >=3.2,<3.2.5',
        fixed_in_version: '3.0.14,3.1.12,3.2.5',
        cve_ids: ['CVE-2021-35042'],
        url: 'https://www.djangoproject.com/weblog/2021/jul/01/security-releases/'
      }
    ],
    'laravel': [
      {
        severity: 'high',
        description: 'Remote code execution vulnerability in Laravel environment configuration',
        affected_versions: '<8.4.3',
        fixed_in_version: '8.4.3',
        cve_ids: ['CVE-2021-3129'],
        url: 'https://github.com/laravel/framework/security/advisories/GHSA-mhm7-gcv9-jwrp'
      }
    ]
  };
  
  // Normalize framework name for lookup (case-insensitive)
  const normalizedName = fw.name.toLowerCase();
  
  // Check for exact matches first
  if (knownVulnerableFrameworks[normalizedName]) {
    processVulnerabilityData(fw, knownVulnerableFrameworks[normalizedName]);
    return;
  }
  
  // Then check for partial matches
  for (const [name, vulns] of Object.entries(knownVulnerableFrameworks)) {
    if (normalizedName.includes(name) || name.includes(normalizedName)) {
      processVulnerabilityData(fw, vulns);
      return;
    }
  }
}

/**
 * Check if a framework is deprecated
 */
async function checkIfFrameworkDeprecated(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Check knowledge base first
    const knowledgeBaseInfo = getFrameworkInfoFromKnowledgeBase(fw.name, config);
    if (knowledgeBaseInfo && knowledgeBaseInfo.isDeprecated !== undefined) {
      fw.isDeprecated = knowledgeBaseInfo.isDeprecated;
      if (knowledgeBaseInfo.endOfLifeDetails) {
        fw.endOfLifeDetails = knowledgeBaseInfo.endOfLifeDetails;
      }
      return;
    }
    
    // Check for known deprecated frameworks
    const knownDeprecatedFrameworks: Record<string, {
      reason?: string;
      endOfLifeDate?: string;
      alternatives?: string[];
    }> = {
      'angular.js': {
        reason: 'No longer actively maintained. Development and support stopped on January 2022.',
        endOfLifeDate: '2022-01-01',
        alternatives: ['Angular 2+', 'React', 'Vue.js']
      },
      'backbone.js': {
        reason: 'No longer in active development and not recommended for new projects.',
        alternatives: ['React', 'Vue.js', 'Angular']
      },
      'ember.js': {
        reason: 'Declining usage and community support compared to React, Vue, and Angular.',
        alternatives: ['React', 'Vue.js', 'Angular']
      },
      'jquery': {
        reason: 'Modern browsers now support most functionality natively that previously required jQuery.',
        alternatives: ['Vanilla JavaScript', 'React', 'Vue.js']
      },
      '.net framework': {
        reason: 'Being replaced by .NET Core and .NET 5+.',
        endOfLifeDate: '2025-01-14', // Some versions earlier
        alternatives: ['.NET Core', '.NET 5+']
      },
      '.net core': {
        reason: 'Replaced by .NET 5+ (unified platform).',
        endOfLifeDate: '2022-12-13',
        alternatives: ['.NET 5+']
      },
      'flask 0.x': {
        reason: 'Flask 0.x is deprecated. Use Flask 1.0 or newer.',
        alternatives: ['Flask 1.0+', 'FastAPI']
      },
      'django 1.x': {
        reason: 'Django 1.x is no longer supported. Use Django 2.0 or newer.',
        alternatives: ['Django 2.0+', 'Django 3.0+']
      }
    };
    
    // Normalize framework name for lookup (case-insensitive)
    const normalizedName = fw.name.toLowerCase();
    
    // Check if the framework is known to be deprecated
    for (const [name, info] of Object.entries(knownDeprecatedFrameworks)) {
      if (normalizedName.includes(name) || normalizedName === name) {
        fw.isDeprecated = true;
        fw.endOfLifeDetails = {
          endOfLifeUrl: 'https://endoflife.date',
          recommendedAlternatives: info.alternatives,
          migrationPath: `Consider migrating to ${info.alternatives?.join(' or ')}`
        };
        
        if (info.endOfLifeDate) {
          fw.endOfLifeDate = new Date(info.endOfLifeDate);
        }
        
        return;
      }
    }
    
    // If framework has version, check if the major version is deprecated
    if (fw.version && fw.latestVersion) {
      try {
        const currentMajor = parseInt(fw.version.split('.')[0], 10);
        const latestMajor = parseInt(fw.latestVersion.split('.')[0], 10);
        
        // If the framework is more than 2 major versions behind, it might be deprecated
        if (latestMajor - currentMajor >= 2) {
          fw.isDeprecated = true;
          fw.endOfLifeDetails = {
            migrationPath: `Consider upgrading to the latest major version (${fw.latestVersion})`
          };
        }
      } catch (parseError) {
        // Ignore version parsing errors
      }
    }
  } catch (error) {
    log.warn(`Error checking if framework ${fw.name} is deprecated`, { error });
  }
}

/**
 * Check framework lifecycle status (EOL)
 */
async function checkFrameworkLifecycle(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    // Check knowledge base first
    const knowledgeBaseInfo = getFrameworkInfoFromKnowledgeBase(fw.name, config);
    if (knowledgeBaseInfo && knowledgeBaseInfo.endOfLifeDate) {
      fw.endOfLifeDate = knowledgeBaseInfo.endOfLifeDate;
      fw.isEndOfLife = knowledgeBaseInfo.endOfLifeDate < new Date();
      if (knowledgeBaseInfo.endOfLifeDetails) {
        fw.endOfLifeDetails = knowledgeBaseInfo.endOfLifeDetails;
      }
      return;
    }
    
    // Check for known EOL dates for frameworks and versions
    // This is a very simplified example - a real implementation would use a proper database
    const knownEolFrameworks: Record<string, Record<string, {
      eolDate: string;
      url?: string;
      recommendedVersion?: string;
    }>> = {
      'node.js': {
        '10': { eolDate: '2021-04-30', url: 'https://nodejs.org/en/about/releases/', recommendedVersion: '18.x' },
        '12': { eolDate: '2022-04-30', url: 'https://nodejs.org/en/about/releases/', recommendedVersion: '18.x' },
        '14': { eolDate: '2023-04-30', url: 'https://nodejs.org/en/about/releases/', recommendedVersion: '18.x' },
        '16': { eolDate: '2023-09-11', url: 'https://nodejs.org/en/about/releases/', recommendedVersion: '18.x' }
      },
      'python': {
        '2.7': { eolDate: '2020-01-01', url: 'https://www.python.org/doc/sunset-python-2/', recommendedVersion: '3.11' },
        '3.5': { eolDate: '2020-09-13', url: 'https://devguide.python.org/versions/', recommendedVersion: '3.11' },
        '3.6': { eolDate: '2021-12-23', url: 'https://devguide.python.org/versions/', recommendedVersion: '3.11' },
        '3.7': { eolDate: '2023-06-27', url: 'https://devguide.python.org/versions/', recommendedVersion: '3.11' }
      },
      'php': {
        '5.6': { eolDate: '2018-12-31', url: 'https://www.php.net/supported-versions.php', recommendedVersion: '8.2' },
        '7.0': { eolDate: '2018-12-03', url: 'https://www.php.net/supported-versions.php', recommendedVersion: '8.2' },
        '7.1': { eolDate: '2019-12-01', url: 'https://www.php.net/supported-versions.php', recommendedVersion: '8.2' },
        '7.2': { eolDate: '2020-11-30', url: 'https://www.php.net/supported-versions.php', recommendedVersion: '8.2' },
        '7.3': { eolDate: '2021-12-06', url: 'https://www.php.net/supported-versions.php', recommendedVersion: '8.2' },
        '7.4': { eolDate: '2022-11-28', url: 'https://www.php.net/supported-versions.php', recommendedVersion: '8.2' },
        '8.0': { eolDate: '2023-11-26', url: 'https://www.php.net/supported-versions.php', recommendedVersion: '8.2' }
      },
      'ruby': {
        '2.4': { eolDate: '2020-03-31', url: 'https://www.ruby-lang.org/en/downloads/branches/', recommendedVersion: '3.2' },
        '2.5': { eolDate: '2021-03-31', url: 'https://www.ruby-lang.org/en/downloads/branches/', recommendedVersion: '3.2' },
        '2.6': { eolDate: '2022-03-31', url: 'https://www.ruby-lang.org/en/downloads/branches/', recommendedVersion: '3.2' },
        '2.7': { eolDate: '2023-03-31', url: 'https://www.ruby-lang.org/en/downloads/branches/', recommendedVersion: '3.2' }
      },
      'java': {
        '8': { eolDate: '2026-12-31', url: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html', recommendedVersion: '17' },
        '9': { eolDate: '2018-03-31', url: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html', recommendedVersion: '17' },
        '10': { eolDate: '2018-09-30', url: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html', recommendedVersion: '17' },
        '11': { eolDate: '2026-09-30', url: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html', recommendedVersion: '17' },
        '12': { eolDate: '2019-09-30', url: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html', recommendedVersion: '17' },
        '13': { eolDate: '2020-03-31', url: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html', recommendedVersion: '17' },
        '14': { eolDate: '2020-09-30', url: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html', recommendedVersion: '17' },
        '15': { eolDate: '2021-03-31', url: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html', recommendedVersion: '17' },
        '16': { eolDate: '2021-09-30', url: 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html', recommendedVersion: '17' }
      },
      '.net framework': {
        '4.5': { eolDate: '2016-01-12', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework', recommendedVersion: '.NET 5+' },
        '4.5.1': { eolDate: '2016-01-12', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework', recommendedVersion: '.NET 5+' },
        '4.5.2': { eolDate: '2022-04-26', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework', recommendedVersion: '.NET 5+' },
        '4.6': { eolDate: '2022-04-26', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework', recommendedVersion: '.NET 5+' },
        '4.6.1': { eolDate: '2022-04-26', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework', recommendedVersion: '.NET 5+' }
      },
      '.net core': {
        '1.0': { eolDate: '2019-06-27', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core', recommendedVersion: '.NET 7' },
        '1.1': { eolDate: '2019-06-27', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core', recommendedVersion: '.NET 7' },
        '2.0': { eolDate: '2018-10-01', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core', recommendedVersion: '.NET 7' },
        '2.1': { eolDate: '2021-08-21', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core', recommendedVersion: '.NET 7' },
        '2.2': { eolDate: '2019-12-23', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core', recommendedVersion: '.NET 7' },
        '3.0': { eolDate: '2020-03-03', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core', recommendedVersion: '.NET 7' },
        '3.1': { eolDate: '2022-12-13', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core', recommendedVersion: '.NET 7' }
      },
      '.net': {
        '5.0': { eolDate: '2022-05-10', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core', recommendedVersion: '.NET 7' },
        '6.0': { eolDate: '2024-11-12', url: 'https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core', recommendedVersion: '.NET 7' }
      }
    };
    
    // Find matching framework and check if version is EOL
    if (fw.version) {
      // Normalize framework name for lookup (case-insensitive)
      const normalizedName = fw.name.toLowerCase();
      
      for (const [frameworkName, versions] of Object.entries(knownEolFrameworks)) {
        if (normalizedName.includes(frameworkName) || frameworkName.includes(normalizedName)) {
          // Check major version
          try {
            const majorVersion = fw.version.split('.')[0];
            
            if (versions[majorVersion]) {
              const eolInfo = versions[majorVersion];
              const eolDate = new Date(eolInfo.eolDate);
              
              fw.endOfLifeDate = eolDate;
              fw.isEndOfLife = eolDate < new Date();
              
              if (fw.isEndOfLife) {
                fw.endOfLifeDetails = {
                  endOfLifeUrl: eolInfo.url,
                  recommendedAlternatives: [eolInfo.recommendedVersion || `Latest version of ${fw.name}`],
                  migrationPath: `Upgrade to ${eolInfo.recommendedVersion || 'the latest version'}`
                };
              }
              
              return;
            }
            
            // Check full version
            for (const [versionPattern, eolInfo] of Object.entries(versions)) {
              if (fw.version.startsWith(versionPattern)) {
                const eolDate = new Date(eolInfo.eolDate);
                
                fw.endOfLifeDate = eolDate;
                fw.isEndOfLife = eolDate < new Date();
                
                if (fw.isEndOfLife) {
                  fw.endOfLifeDetails = {
                    endOfLifeUrl: eolInfo.url,
                    recommendedAlternatives: [eolInfo.recommendedVersion || `Latest version of ${fw.name}`],
                    migrationPath: `Upgrade to ${eolInfo.recommendedVersion || 'the latest version'}`
                  };
                }
                
                return;
              }
            }
          } catch (versionError) {
            // Ignore version parsing errors
          }
        }
      }
    }
  } catch (error) {
    log.warn(`Error checking framework lifecycle for ${fw.name}`, { error });
  }
}

/**
 * Assess migration complexity if framework needs upgrading
 */
async function assessMigrationComplexity(
  fw: FrameworkInfo,
  config: FrameworkScannerConfig
): Promise<void> {
  try {
    if (!fw.isOutdated && !fw.isVulnerable && !fw.isDeprecated && !fw.isEndOfLife) {
      // No need to assess migration complexity if no issues
      return;
    }
    
    // Default migration complexity level
    let complexityLevel: 'low' | 'medium' | 'high' | 'very-high' = 'medium';
    const factors: string[] = [];
    const potentialIssues: string[] = [];
    const requiredSkills: string[] = [];
    let estimatedEffortDays: number | undefined = undefined;
    
    // Factors that can affect migration complexity
    if (fw.isDeprecated || fw.isEndOfLife) {
      complexityLevel = 'high';
      factors.push('Framework is deprecated or at end-of-life');
      potentialIssues.push('May require complete rewrite or platform change');
    } else if (fw.latestVersion && fw.version) {
      // Check major version differences
      try {
        const currentMajor = parseInt(fw.version.split('.')[0], 10);
        const latestMajor = parseInt(fw.latestVersion.split('.')[0], 10);
        
        if (latestMajor - currentMajor >= 2) {
          complexityLevel = 'high';
          factors.push(`Major version jump (${currentMajor} to ${latestMajor})`);
          potentialIssues.push('Breaking API changes are likely');
        } else if (latestMajor > currentMajor) {
          complexityLevel = 'medium';
          factors.push(`Major version upgrade (${currentMajor} to ${latestMajor})`);
          potentialIssues.push('Some API changes may be required');
        } else {
          complexityLevel = 'low';
          factors.push('Minor version upgrade');
        }
      } catch (versionError) {
        // If can't parse version, assume medium complexity
        complexityLevel = 'medium';
        factors.push('Unknown version difference');
      }
    }
    
    // Framework-specific migration complexity assessment
    switch (fw.name.toLowerCase()) {
      case 'angular.js':
        complexityLevel = 'very-high';
        factors.push('Complete rewrite needed to migrate to Angular 2+');
        potentialIssues.push('Completely different architecture', 'Different language (TypeScript)');
        requiredSkills.push('Angular 2+', 'TypeScript', 'RxJS');
        estimatedEffortDays = 90; // Substantial project
        break;
      
      case 'react':
        if (fw.version && fw.version.startsWith('15')) {
          complexityLevel = 'high';
          factors.push('Major API changes since React 15');
          potentialIssues.push('Class component to hooks migration', 'Context API changes');
          requiredSkills.push('React Hooks', 'Modern React patterns');
          estimatedEffortDays = 30;
        } else if (fw.version && fw.version.startsWith('16')) {
          complexityLevel = 'medium';
          factors.push('Some API changes since React 16');
          potentialIssues.push('Concurrent features adoption');
          requiredSkills.push('React Hooks', 'Concurrent Mode understanding');
          estimatedEffortDays = 14;
        } else {
          complexityLevel = 'low';
          factors.push('Minor changes required');
          estimatedEffortDays = 5;
        }
        break;
      
      case 'vue.js':
        if (fw.version && fw.version.startsWith('2') && fw.latestVersion && fw.latestVersion.startsWith('3')) {
          complexityLevel = 'high';
          factors.push('Major API changes from Vue 2 to Vue 3');
          potentialIssues.push('Global API changes', 'Composition API learning curve');
          requiredSkills.push('Vue 3', 'Composition API');
          estimatedEffortDays = 21;
        } else {
          complexityLevel = 'low';
          factors.push('Minor changes required');
          estimatedEffortDays = 5;
        }
        break;
      
      case 'spring framework':
      case 'spring boot':
        if (fw.version && fw.version.startsWith('1') && fw.latestVersion && fw.latestVersion.startsWith('3')) {
          complexityLevel = 'very-high';
          factors.push('Major version jump from Spring Boot 1.x to 3.x');
          potentialIssues.push('Java 17 requirement', 'Deprecated APIs removed', 'Configuration changes');
          requiredSkills.push('Java 17', 'Spring Boot 3.x');
          estimatedEffortDays = 45;
        } else if (fw.version && fw.version.startsWith('2') && fw.latestVersion && fw.latestVersion.startsWith('3')) {
          complexityLevel = 'high';
          factors.push('Major version upgrade from Spring Boot 2.x to 3.x');
          potentialIssues.push('Java 17 requirement', 'Some API changes');
          requiredSkills.push('Java 17', 'Spring Boot 3.x');
          estimatedEffortDays = 21;
        } else {
          complexityLevel = 'medium';
          factors.push('Minor Spring version upgrade');
          estimatedEffortDays = 10;
        }
        break;
      
      case 'django':
        if (fw.version && parseInt(fw.version.split('.')[0], 10) < 3) {
          complexityLevel = 'high';
          factors.push('Major version upgrade to Django 3+');
          potentialIssues.push('Python 3.6+ requirement', 'Deprecated features removed');
          requiredSkills.push('Python 3.6+', 'Modern Django practices');
          estimatedEffortDays = 20;
        } else {
          complexityLevel = 'medium';
          factors.push('Minor Django version upgrade');
          estimatedEffortDays = 7;
        }
        break;
      
      case '.net framework':
        complexityLevel = 'very-high';
        factors.push('Migration from .NET Framework to modern .NET');
        potentialIssues.push('Windows-specific dependencies', 'Removed APIs', 'Configuration differences');
        requiredSkills.push('.NET Core/.NET 5+', 'Modern C# features');
        estimatedEffortDays = 60;
        break;
      
      case 'php':
        if (fw.version && parseInt(fw.version.split('.')[0], 10) < 7) {
          complexityLevel = 'high';
          factors.push('Major PHP version upgrade (< 7.x to modern)');
          potentialIssues.push('Breaking syntax changes', 'Deprecated functions');
          requiredSkills.push('Modern PHP 7+/8+', 'Composer');
          estimatedEffortDays = 30;
        } else if (fw.version && parseInt(fw.version.split('.')[0], 10) < 8) {
          complexityLevel = 'medium';
          factors.push('PHP 7.x to 8.x upgrade');
          potentialIssues.push('Some syntax changes', 'New features to adopt');
          requiredSkills.push('PHP 8');
          estimatedEffortDays = 14;
        } else {
          complexityLevel = 'low';
          factors.push('Minor PHP version update');
          estimatedEffortDays = 5;
        }
        break;
    }
    
    // Consider framework popularity and available resources
    if (isNicheFramework(fw.name)) {
      complexityLevel = elevateComplexity(complexityLevel);
      factors.push('Niche framework with limited community resources');
      potentialIssues.push('Limited documentation and examples for migration');
    }
    
    // Consider dependency extent
    if (fw.usageExtent && fw.usageExtent > 0.7) {
      complexityLevel = elevateComplexity(complexityLevel);
      factors.push('Framework is extensively used throughout the codebase');
      potentialIssues.push('Wide-ranging impact of changes');
    }
    
    // Consider if framework is used in critical components
    if (fw.usageFiles && fw.usageFiles.some(file => file.includes('core') || file.includes('main'))) {
      complexityLevel = elevateComplexity(complexityLevel);
      factors.push('Framework is used in core/critical components');
      potentialIssues.push('High business risk during migration');
    }
    
    // Set the migration complexity on the framework
    fw.migrationComplexity = {
      level: complexityLevel,
      factors,
      potentialIssues,
      requiredSkills,
      estimatedEffortDays
    };
    
    // If we don't have an estimate yet, calculate a rough one based on complexity
    if (!fw.migrationComplexity.estimatedEffortDays) {
      switch (complexityLevel) {
        case 'low':
          fw.migrationComplexity.estimatedEffortDays = 3;
          break;
        case 'medium':
          fw.migrationComplexity.estimatedEffortDays = 10;
          break;
        case 'high':
          fw.migrationComplexity.estimatedEffortDays = 25;
          break;
        case 'very-high':
          fw.migrationComplexity.estimatedEffortDays = 60;
          break;
      }
    }
  } catch (error) {
    log.warn(`Error assessing migration complexity for ${fw.name}`, { error });
  }
}

/**
 * Elevate complexity level by one step
 */
function elevateComplexity(
  level: 'low' | 'medium' | 'high' | 'very-high'
): 'low' | 'medium' | 'high' | 'very-high' {
  switch (level) {
    case 'low': return 'medium';
    case 'medium': return 'high';
    case 'high': return 'very-high';
    case 'very-high': return 'very-high';
  }
}

/**
 * Determine if a framework is niche/less popular
 */
function isNicheFramework(frameworkName: string): boolean {
  const nicheCandidates = [
    'backbone', 'ember', 'aurelia', 'meteor', 'polymer',
    'knockout', 'dojo', 'mootools', 'prototype', 'extjs',
    'yii', 'codeigniter', 'cakephp', 'slim', 'silex',
    'play framework', 'dropwizard', 'wicket', 'vaadin',
    'pyramid', 'turbogears', 'cherrypy', 'bottle',
    'lift', 'scalatra', 'finatra', 'akka-http'
  ];
  
  const normalizedName = frameworkName.toLowerCase();
  return nicheCandidates.some(candidate => normalizedName.includes(candidate));
}

/**
 * Calculate risk level for a framework issue
 */
function calculateRiskLevel(
  fw: FrameworkInfo
): 'low' | 'medium' | 'high' | 'critical' {
  // Start with low risk
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  // Prioritize vulnerabilities
  if (fw.vulnerabilities && fw.vulnerabilities.length > 0) {
    // Use the highest vulnerability severity
    for (const vuln of fw.vulnerabilities) {
      if (vuln.severity === 'critical') {
        return 'critical';
      } else if (vuln.severity === 'high' && riskLevel !== 'critical') {
        riskLevel = 'high';
      } else if (vuln.severity === 'medium' && riskLevel !== 'critical' && riskLevel !== 'high') {
        riskLevel = 'medium';
      }
    }
  }
  
  // Then consider end-of-life status
  if (fw.isEndOfLife) {
    // End-of-life frameworks are at least high risk
    if (riskLevel !== 'critical') riskLevel = 'high';
    
    // If the framework is both EOL and has vulnerabilities, it's critical
    if (fw.vulnerabilities && fw.vulnerabilities.length > 0) {
      return 'critical';
    }
  }
  
  // Then consider deprecation
  if (fw.isDeprecated) {
    // Deprecated frameworks are at least medium risk
    if (riskLevel === 'low') riskLevel = 'medium';
    
    // If already has vulnerabilities and is deprecated, raise to high
    if (fw.vulnerabilities && fw.vulnerabilities.length > 0 && riskLevel === 'medium') {
      riskLevel = 'high';
    }
  }
  
  // Consider how outdated the framework is
  if (fw.isOutdated && fw.version && fw.latestVersion) {
    try {
      // Check if it's a major version behind
      if (isMajorVersionUpdate(fw.version, fw.latestVersion)) {
        // Being a major version behind is at least medium risk
        if (riskLevel === 'low') riskLevel = 'medium';
        
        // Multiple major versions behind is high risk
        const currentMajor = parseInt(fw.version.split('.')[0], 10);
        const latestMajor = parseInt(fw.latestVersion.split('.')[0], 10);
        
        if (latestMajor - currentMajor >= 2) {
          if (riskLevel === 'medium') riskLevel = 'high';
        }
      }
    } catch (parseError) {
      // If can't parse, default to medium for outdated frameworks
      if (riskLevel === 'low') riskLevel = 'medium';
    }
  }
  
  // Consider criticality based on usage
  if (fw.usageExtent && fw.usageExtent > 0.7) {
    // If framework is used extensively, increase risk
    if (riskLevel === 'low') riskLevel = 'medium';
    if (riskLevel === 'medium') riskLevel = 'high';
  }
  
  return riskLevel;
}

/**
 * Generate tags for a framework issue
 */
function generateTags(fw: FrameworkInfo): string[] {
  const tags: string[] = [fw.type];
  
  // Add language tag if available
  if (fw.language) {
    tags.push(fw.language);
  }
  
  // Add tags based on issue type
  if (fw.isOutdated) {
    tags.push('outdated');
    
    // Check if it's a major version outdated
    if (fw.version && fw.latestVersion) {
      try {
        const currentMajor = parseInt(fw.version.split('.')[0], 10);
        const latestMajor = parseInt(fw.latestVersion.split('.')[0], 10);
        
        if (latestMajor - currentMajor >= 2) {
          tags.push('multiple-major-versions-behind');
        } else if (latestMajor > currentMajor) {
          tags.push('major-version-behind');
        } else {
          tags.push('minor-update-available');
        }
      } catch (parseError) {
        // Ignore version parsing errors
      }
    }
  }
  
  if (fw.isVulnerable) {
    tags.push('vulnerable');
    
    // Add highest severity level
    if (fw.vulnerabilities && fw.vulnerabilities.length > 0) {
      let highestSeverity = 'low';
      for (const vuln of fw.vulnerabilities) {
        if (vuln.severity === 'critical') {
          highestSeverity = 'critical';
          break;
        } else if (vuln.severity === 'high' && highestSeverity !== 'critical') {
          highestSeverity = 'high';
        } else if (vuln.severity === 'medium' && highestSeverity !== 'critical' && highestSeverity !== 'high') {
          highestSeverity = 'medium';
        }
      }
      tags.push(`vulnerability:${highestSeverity}`);
    }
  }
  
  if (fw.isDeprecated) {
    tags.push('deprecated');
  }
  
  if (fw.isEndOfLife) {
    tags.push('end-of-life');
  } else if (fw.endOfLifeDate && fw.endOfLifeDate > new Date()) {
    // Calculate months until EOL
    const monthsUntilEol = (fw.endOfLifeDate.getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24 * 30);
    
    if (monthsUntilEol < 3) {
      tags.push('eol-imminent');
    } else if (monthsUntilEol < 12) {
      tags.push('eol-approaching');
    }
  }
  
  // Add tags for migration complexity if available
  if (fw.migrationComplexity) {
    tags.push(`migration:${fw.migrationComplexity.level}`);
  }
  
  // Add framework-specific tags
  if (fw.name.toLowerCase().includes('spring')) {
    tags.push('spring-ecosystem');
  } else if (fw.name.toLowerCase().includes('react')) {
    tags.push('react-ecosystem');
  } else if (fw.name.toLowerCase().includes('angular')) {
    tags.push('angular-ecosystem');
  } else if (fw.name.toLowerCase().includes('vue')) {
    tags.push('vue-ecosystem');
  } else if (fw.name.toLowerCase().includes('django')) {
    tags.push('django-ecosystem');
  } else if (fw.name.toLowerCase().includes('laravel')) {
    tags.push('laravel-ecosystem');
  } else if (fw.name.toLowerCase().includes('.net')) {
    tags.push('dotnet-ecosystem');
  }
  
  return tags;
}

/**
 * Generate a recommendation for a framework issue
 */
function generateRecommendation(fw: FrameworkInfo): string {
  const recommendations: string[] = [];
  
  // Handle vulnerable frameworks with highest priority
  if (fw.isVulnerable && fw.vulnerabilities && fw.vulnerabilities.length > 0) {
    recommendations.push(
      `Found ${fw.vulnerabilities.length} ${fw.vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'} in ${fw.name}${fw.version ? ` ${fw.version}` : ''}.`
    );
    
    // Group vulnerabilities by severity for better readability
    const bySeverity: Record<string, any[]> = {};
    for (const vuln of fw.vulnerabilities) {
      if (!bySeverity[vuln.severity]) {
        bySeverity[vuln.severity] = [];
      }
      bySeverity[vuln.severity].push(vuln);
    }
    
    // Report vulnerabilities from highest to lowest severity
    for (const severity of ['critical', 'high', 'medium', 'low']) {
      if (bySeverity[severity] && bySeverity[severity].length > 0) {
        recommendations.push(
          `${bySeverity[severity].length} ${severity} severity ${bySeverity[severity].length === 1 ? 'issue' : 'issues'} found:`
        );
        
        // List the vulnerabilities at this severity
        for (const vuln of bySeverity[severity]) {
          let vulnDesc = `- ${vuln.description}`;
          
          if (vuln.cveIds && vuln.cveIds.length > 0) {
            vulnDesc += ` (${vuln.cveIds.join(', ')})`;
          }
          
          if (vuln.fixedInVersion) {
            vulnDesc += ` - Fixed in version ${vuln.fixedInVersion}`;
          }
          
          recommendations.push(vulnDesc);
        }
      }
    }
    
    // Recommend updating
    if (fw.latestVersion) {
      recommendations.push(
        `Update to the latest version (${fw.latestVersion}) to resolve these security issues.`
      );
    } else {
      recommendations.push(
        `Update to the latest version to resolve these security issues.`
      );
    }
  }
  
  // Handle end-of-life frameworks
  if (fw.isEndOfLife) {
    // Only add this header if not already covered by vulnerabilities
    if (recommendations.length === 0) {
      recommendations.push(
        `${fw.name}${fw.version ? ` ${fw.version}` : ''} has reached end-of-life and is no longer supported.`
      );
    } else {
      recommendations.push(
        `Additionally, ${fw.name}${fw.version ? ` ${fw.version}` : ''} has reached end-of-life.`
      );
    }
    
    if (fw.endOfLifeDate) {
      recommendations.push(`End-of-life date: ${fw.endOfLifeDate.toISOString().split('T')[0]}`);
    }
    
    if (fw.endOfLifeDetails) {
      if (fw.endOfLifeDetails.endOfLifeUrl) {
        recommendations.push(`More information: ${fw.endOfLifeDetails.endOfLifeUrl}`);
      }
      
      if (fw.endOfLifeDetails.recommendedAlternatives && fw.endOfLifeDetails.recommendedAlternatives.length > 0) {
        recommendations.push(`Recommended alternatives: ${fw.endOfLifeDetails.recommendedAlternatives.join(', ')}`);
      }
      
      if (fw.endOfLifeDetails.migrationPath) {
        recommendations.push(`Migration path: ${fw.endOfLifeDetails.migrationPath}`);
      }
    }
    
    recommendations.push(
      `Urgent action required: Migrate away from this end-of-life technology to maintain security and supportability.`
    );
  }
  
  // Handle deprecated frameworks
  if (fw.isDeprecated && !fw.isEndOfLife) { // Skip if already covered by EOL
    // Only add this header if not already covered by vulnerabilities
    if (recommendations.length === 0) {
      recommendations.push(
        `${fw.name}${fw.version ? ` ${fw.version}` : ''} is deprecated.`
      );
    } else {
      recommendations.push(
        `Additionally, ${fw.name}${fw.version ? ` ${fw.version}` : ''} is deprecated.`
      );
    }
    
    if (fw.endOfLifeDetails) {
      if (fw.endOfLifeDetails.recommendedAlternatives && fw.endOfLifeDetails.recommendedAlternatives.length > 0) {
        recommendations.push(`Recommended alternatives: ${fw.endOfLifeDetails.recommendedAlternatives.join(', ')}`);
      }
      
      if (fw.endOfLifeDetails.migrationPath) {
        recommendations.push(`Migration path: ${fw.endOfLifeDetails.migrationPath}`);
      }
    }
    
    recommendations.push(
      `Action required: Plan migration away from this deprecated technology.`
    );
  }
  
  // Handle outdated frameworks
  if (fw.isOutdated && fw.latestVersion) {
    // Only add this if not already covered by vulnerabilities, EOL, or deprecation
    if (recommendations.length === 0) {
      recommendations.push(
        `${fw.name}${fw.version ? ` ${fw.version}` : ''} is outdated. Latest version is ${fw.latestVersion}.`
      );
      
      // Check if it's a major version update
      try {
        if (fw.version && isMajorVersionUpdate(fw.version, fw.latestVersion)) {
          const currentMajor = parseInt(fw.version.split('.')[0], 10);
          const latestMajor = parseInt(fw.latestVersion.split('.')[0], 10);
          
          if (latestMajor - currentMajor >= 2) {
            recommendations.push(
              `This is a multi-major version jump (${currentMajor} to ${latestMajor}) which likely includes breaking changes. Review the changelog and migration guides before updating.`
            );
          } else {
            recommendations.push(
              `This is a major version update which may include breaking changes. Review the changelog before updating.`
            );
          }
        } else {
          recommendations.push(
            `Update to the latest version to receive bug fixes, performance improvements, and new features.`
          );
        }
      } catch (versionError) {
        recommendations.push(
          `Update to the latest version to receive bug fixes, performance improvements, and new features.`
        );
      }
    } else if (!recommendations.some(r => r.includes('Update to the latest version'))) {
      // Add update recommendation if not already present
      recommendations.push(
        `Update to ${fw.latestVersion} to receive the latest improvements and fixes.`
      );
    }
  }
  
  // Add assessment of update/migration complexity if available
  if (fw.migrationComplexity) {
    recommendations.push('\nMigration complexity assessment:');
    
    // Complexity level with description
    const complexityDescriptions: Record<string, string> = {
      'low': 'minimal effort required, straightforward update',
      'medium': 'moderate effort required, some code changes expected',
      'high': 'significant effort required, breaking changes likely',
      'very-high': 'extensive effort required, major architectural changes expected'
    };
    
    recommendations.push(`- Complexity: ${fw.migrationComplexity.level.toUpperCase()} (${complexityDescriptions[fw.migrationComplexity.level]})`);
    
    // Estimated effort
    if (fw.migrationComplexity.estimatedEffortDays) {
      recommendations.push(`- Estimated effort: ${fw.migrationComplexity.estimatedEffortDays} person-days`);
    }
    
    // Contributing factors
    if (fw.migrationComplexity.factors.length > 0) {
      recommendations.push(`- Factors affecting complexity: ${fw.migrationComplexity.factors.join(', ')}`);
    }
    
    // Potential issues
    if (fw.migrationComplexity.potentialIssues && fw.migrationComplexity.potentialIssues.length > 0) {
      recommendations.push(`- Potential issues: ${fw.migrationComplexity.potentialIssues.join(', ')}`);
    }
    
    // Required skills
    if (fw.migrationComplexity.requiredSkills && fw.migrationComplexity.requiredSkills.length > 0) {
      recommendations.push(`- Required skills: ${fw.migrationComplexity.requiredSkills.join(', ')}`);
    }
  }
  
  // Add resources for more information
  recommendations.push('\nResources:');
  
  if (fw.documentationUrl) {
    recommendations.push(`- Documentation: ${fw.documentationUrl}`);
  }
  
  if (fw.upgradeGuideUrl) {
    recommendations.push(`- Upgrade guide: ${fw.upgradeGuideUrl}`);
  }
  
  if (!recommendations.some(r => r.includes('Documentation:')) && !recommendations.some(r => r.includes('Upgrade guide:'))) {
    // Add general resource if specific ones aren't available
    recommendations.push(`- Search for "${fw.name} upgrade guide" or "${fw.name} migration guide" for specific instructions.`);
  }
  
  // If no specific recommendations were made, add generic advice
  if (recommendations.length === 0) {
    recommendations.push(
      `Review ${fw.name}${fw.version ? ` ${fw.version}` : ''} for potential updates or replacements as part of regular technical currency maintenance.`
    );
  }
  
  return recommendations.join('\n');
}

/**
 * Check if a version update is a major version change
 */
function isMajorVersionUpdate(currentVersion: string, latestVersion: string): boolean {
  try {
    const current = currentVersion.split('.');
    const latest = latestVersion.split('.');
    
    // If major version number changed, it's a major update
    if (parseInt(current[0], 10) < parseInt(latest[0], 10)) {
      return true;
    }
    
    return false;
  } catch (error) {
    // If can't parse, assume it's a major update to be safe
    return true;
  }
}

/**
 * Check if a version is affected by a specified range
 */
function isVersionAffected(version: string, affectedVersions: string): boolean {
  if (version === 'unknown') {
    return true; // Assume unknown versions are affected
  }
  
  // Very simplified version check - in a real implementation use semver or similar
  if (affectedVersions === '*') {
    return true;
  }
  
  // Check exact version match
  if (affectedVersions === version) {
    return true;
  }
  
  // Check range using commas
  if (affectedVersions.includes(',')) {
    const versions = affectedVersions.split(',').map(v => v.trim());
    return versions.some(v => isVersionAffected(version, v));
  }
  
  // Check range with operators (very simplified)
  if (affectedVersions.startsWith('<=')) {
    const maxVersion = affectedVersions.substring(2);
    return version <= maxVersion;
  }
  
  if (affectedVersions.startsWith('<')) {
    const maxVersion = affectedVersions.substring(1);
    return version < maxVersion;
  }
  
  if (affectedVersions.startsWith('>=')) {
    const minVersion = affectedVersions.substring(2);
    return version >= minVersion;
  }
  
  if (affectedVersions.startsWith('>')) {
    const minVersion = affectedVersions.substring(1);
    return version > minVersion;
  }
  
  // Version ranges like ">=1.0.0,<2.0.0"
  if (affectedVersions.includes(',')) {
    const parts = affectedVersions.split(',');
    return parts.every(part => isVersionAffected(version, part.trim()));
  }
  
  return false;
}