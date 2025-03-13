import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import axios from 'axios';
import * as semver from 'semver';
import { log } from '../utils/logging';
import { DependencyIssue } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);

/**
 * Configuration for dependency scanning
 */
export interface DependencyScannerConfig {
  // Root directory to scan
  rootDir: string;
  
  // Package manager manifests to scan for (glob patterns)
  manifests: string[];
  
  // Whether to include dev dependencies
  includeDev: boolean;
  
  // Whether to include peer dependencies
  includePeer: boolean;
  
  // Whether to include optional dependencies
  includeOptional: boolean;
  
  // Packages to ignore (exact names)
  ignorePackages?: string[];
  
  // Version difference threshold to consider outdated (major.minor.patch)
  outdatedThreshold: {
    major: number;
    minor: number;
    patch: number;
  };
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
  
  // Custom vulnerability database file
  customVulnerabilityDb?: string;
  
  // Registry URLs by package manager
  registryUrls?: {
    npm?: string;
    composer?: string;
    pypi?: string;
    maven?: string;
    gradle?: string;
    cargo?: string;
    gem?: string;
    nuget?: string;
  };
}

/**
 * Interface for dependency metadata from registries
 */
interface DependencyMetadata {
  name: string;
  latestVersion: string;
  isDeprecated: boolean;
  hasSecurityIssues: boolean;
  license?: string;
  repo?: string;
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
    cve?: string;
  }>;
  deprecationReason?: string;
  alternatives?: string[];
  downloadCount?: number;
  lastPublishedAt?: Date;
  maintainedBy?: string[];
}

/**
 * Dependency information parsed from a manifest file
 */
interface ParsedDependency {
  name: string;
  version: string;
  type: 'production' | 'development' | 'peer' | 'optional';
  packageManager: string;
  manifestFile: string;
}

/**
 * Map of package manager to file patterns
 */
const PACKAGE_MANAGER_PATTERNS: Record<string, string[]> = {
  npm: ['package.json'],
  yarn: ['package.json', 'yarn.lock'],
  pnpm: ['package.json', 'pnpm-lock.yaml'],
  bun: ['package.json', 'bun.lockb'],
  composer: ['composer.json'],
  pip: ['requirements.txt', 'pyproject.toml', 'setup.py'],
  poetry: ['pyproject.toml'],
  maven: ['pom.xml'],
  gradle: ['build.gradle', 'build.gradle.kts'],
  cargo: ['Cargo.toml'],
  bundler: ['Gemfile'],
  nuget: ['*.csproj', '*.fsproj', 'packages.config']
};

/**
 * Scanner for detecting outdated or vulnerable dependencies
 */
export async function scanDependencies(
  config: DependencyScannerConfig
): Promise<DependencyIssue[]> {
  try {
    log.info('Starting dependency scanner');
    const issues: DependencyIssue[] = [];
    
    // Find manifest files to scan
    const manifestFiles = await findManifestFiles(config);
    log.info(`Found ${manifestFiles.length} manifest files to scan`);
    
    // Process each manifest file
    for (const manifestFile of manifestFiles) {
      try {
        // Read the manifest file
        const content = await readFileAsync(manifestFile, 'utf8');
        
        // Determine package manager from file name
        const packageManager = determinePackageManager(manifestFile);
        
        if (!packageManager) {
          log.warn(`Could not determine package manager for ${manifestFile}, skipping`);
          continue;
        }
        
        // Parse dependencies from the manifest
        const dependencies = await parseDependencies(
          manifestFile,
          content,
          packageManager,
          config
        );
        
        log.info(`Found ${dependencies.length} dependencies in ${manifestFile}`);
        
        // Check each dependency
        for (const dep of dependencies) {
          // Skip ignored packages
          if (config.ignorePackages?.includes(dep.name)) {
            log.info(`Skipping ignored package: ${dep.name}`);
            continue;
          }
          
          try {
            // Get metadata from registry
            const metadata = await getDependencyMetadata(
              dep.name,
              dep.version,
              dep.packageManager,
              config
            );
            
            // Check if dependency has issues
            const isOutdated = isOutdatedVersion(
              dep.version,
              metadata.latestVersion,
              config.outdatedThreshold
            );
            
            if (isOutdated || metadata.isDeprecated || metadata.hasSecurityIssues) {
              // Create dependency issue
              const issue: DependencyIssue = {
                detectedAt: new Date(),
                name: dep.name,
                currentVersion: dep.version,
                latestVersion: metadata.latestVersion,
                packageManager: dep.packageManager,
                type: dep.type,
                manifestFile: dep.manifestFile,
                isOutdated,
                isDeprecated: metadata.isDeprecated,
                hasSecurityIssues: metadata.hasSecurityIssues,
                license: metadata.license,
                repo: metadata.repo,
                tags: generateTags(dep, metadata, isOutdated),
                recommendation: generateRecommendation(dep, metadata, isOutdated)
              };
              
              // Add security issues if any
              if (metadata.securityIssues?.length) {
                issue.securityIssues = metadata.securityIssues;
              }
              
              // Add business impact and update effort scores
              issue.businessImpact = calculateBusinessImpact(dep, metadata);
              issue.updateEffort = calculateUpdateEffort(dep, metadata);
              
              issues.push(issue);
              log.info(`Added issue for dependency ${dep.name} ${dep.version}`);
            }
          } catch (depError) {
            log.warn(`Error checking dependency ${dep.name}`, { error: depError });
          }
        }
      } catch (manifestError) {
        log.warn(`Error processing manifest file: ${manifestFile}`, { error: manifestError });
      }
    }
    
    log.info(`Completed dependency scanning. Found ${issues.length} total issues`);
    return issues;
  } catch (error) {
    log.error('Error during dependency scanning', { error });
    return [];
  }
}

/**
 * Find manifest files to scan based on configuration
 */
async function findManifestFiles(
  config: DependencyScannerConfig
): Promise<string[]> {
  try {
    const allFiles: string[] = [];
    
    for (const pattern of config.manifests) {
      const matchedFiles = await glob(
        pattern, 
        { 
          cwd: config.rootDir,
          absolute: true
        }
      );
      
      allFiles.push(...matchedFiles);
    }
    
    return [...new Set(allFiles)]; // Remove duplicates
  } catch (error) {
    log.error('Error finding manifest files', { error });
    return [];
  }
}

/**
 * Determine package manager from manifest file name
 */
function determinePackageManager(manifestFile: string): string | null {
  const fileName = path.basename(manifestFile).toLowerCase();
  
  for (const [manager, patterns] of Object.entries(PACKAGE_MANAGER_PATTERNS)) {
    if (patterns.some(pattern => {
      if (pattern.includes('*')) {
        return new RegExp('^' + pattern.replace(/\*/g, '.*') + '$').test(fileName);
      }
      return fileName === pattern.toLowerCase();
    })) {
      return manager;
    }
  }
  
  return null;
}

/**
 * Parse dependencies from a manifest file
 */
async function parseDependencies(
  manifestFile: string,
  content: string,
  packageManager: string,
  config: DependencyScannerConfig
): Promise<ParsedDependency[]> {
  const fileName = path.basename(manifestFile).toLowerCase();
  const dependencies: ParsedDependency[] = [];
  
  try {
    // Handle different manifest formats
    if (fileName === 'package.json') {
      // Parse npm/yarn/pnpm package.json
      const packageJson = JSON.parse(content);
      
      // Production dependencies
      if (packageJson.dependencies) {
        for (const [name, version] of Object.entries(packageJson.dependencies)) {
          dependencies.push({
            name,
            version: version.toString().replace(/[^0-9.]/g, ''),
            type: 'production',
            packageManager,
            manifestFile
          });
        }
      }
      
      // Development dependencies
      if (config.includeDev && packageJson.devDependencies) {
        for (const [name, version] of Object.entries(packageJson.devDependencies)) {
          dependencies.push({
            name,
            version: version.toString().replace(/[^0-9.]/g, ''),
            type: 'development',
            packageManager,
            manifestFile
          });
        }
      }
      
      // Peer dependencies
      if (config.includePeer && packageJson.peerDependencies) {
        for (const [name, version] of Object.entries(packageJson.peerDependencies)) {
          dependencies.push({
            name,
            version: version.toString().replace(/[^0-9.]/g, ''),
            type: 'peer',
            packageManager,
            manifestFile
          });
        }
      }
      
      // Optional dependencies
      if (config.includeOptional && packageJson.optionalDependencies) {
        for (const [name, version] of Object.entries(packageJson.optionalDependencies)) {
          dependencies.push({
            name,
            version: version.toString().replace(/[^0-9.]/g, ''),
            type: 'optional',
            packageManager,
            manifestFile
          });
        }
      }
    } else if (fileName === 'composer.json') {
      // Parse PHP composer.json
      const composerJson = JSON.parse(content);
      
      // Production dependencies
      if (composerJson.require) {
        for (const [name, version] of Object.entries(composerJson.require)) {
          if (name !== 'php') { // Skip PHP itself
            dependencies.push({
              name,
              version: version.toString().replace(/[^0-9.]/g, ''),
              type: 'production',
              packageManager,
              manifestFile
            });
          }
        }
      }
      
      // Development dependencies
      if (config.includeDev && composerJson['require-dev']) {
        for (const [name, version] of Object.entries(composerJson['require-dev'])) {
          dependencies.push({
            name,
            version: version.toString().replace(/[^0-9.]/g, ''),
            type: 'development',
            packageManager,
            manifestFile
          });
        }
      }
    } else if (fileName === 'requirements.txt') {
      // Parse Python requirements.txt
      const lines = content.split('\n').map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
      
      for (const line of lines) {
        // Basic format: package==version or package>=version
        const match = line.match(/^([a-zA-Z0-9_.-]+)\s*([=><~!]+)\s*([0-9a-zA-Z.-]+)/);
        if (match) {
          const [_, name, operator, version] = match;
          dependencies.push({
            name,
            version,
            type: 'production',
            packageManager,
            manifestFile
          });
        } else if (!line.includes('=')) {
          // Handle package with no version specified
          dependencies.push({
            name: line,
            version: 'latest',
            type: 'production',
            packageManager,
            manifestFile
          });
        }
      }
    } else if (fileName === 'pyproject.toml') {
      // Very basic TOML parsing for Python projects
      const lines = content.split('\n');
      let currentSection = '';
      
      for (const line of lines) {
        // Section headers are in [brackets]
        const sectionMatch = line.match(/^\[([^\]]+)\]/);
        if (sectionMatch) {
          currentSection = sectionMatch[1];
          continue;
        }
        
        // Look for dependencies in various sections
        const isDevSection = currentSection.includes('dev-dependencies') ||
                             currentSection.includes('development-dependencies');
        
        if (['project', 'tool.poetry.dependencies', 'dependencies', 'build-system.requires'].some(s => currentSection.includes(s))) {
          const depMatch = line.match(/([a-zA-Z0-9_.-]+)\s*=\s*["']?([0-9a-zA-Z.-]+)["']?/);
          if (depMatch) {
            const [_, name, version] = depMatch;
            dependencies.push({
              name,
              version,
              type: isDevSection && config.includeDev ? 'development' : 'production',
              packageManager,
              manifestFile
            });
          }
        }
      }
    } else if (fileName === 'cargo.toml') {
      // Very basic TOML parsing for Rust projects
      const lines = content.split('\n');
      let currentSection = '';
      
      for (const line of lines) {
        // Section headers
        const sectionMatch = line.match(/^\[([^\]]+)\]/);
        if (sectionMatch) {
          currentSection = sectionMatch[1];
          continue;
        }
        
        const isDevSection = currentSection === 'dev-dependencies';
        if (currentSection === 'dependencies' || isDevSection) {
          // Simple key = "version"
          const simpleDepMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*["']([^"']+)["']/);
          if (simpleDepMatch) {
            dependencies.push({
              name: simpleDepMatch[1],
              version: simpleDepMatch[2],
              type: isDevSection && config.includeDev ? 'development' : 'production',
              packageManager,
              manifestFile
            });
          }
          
          // Table format with version
          const tableDepMatch = line.match(/^([a-zA-Z0-9_-]+)\s*\.version\s*=\s*["']([^"']+)["']/);
          if (tableDepMatch) {
            dependencies.push({
              name: tableDepMatch[1],
              version: tableDepMatch[2],
              type: isDevSection && config.includeDev ? 'development' : 'production',
              packageManager,
              manifestFile
            });
          }
        }
      }
    } else if (fileName === 'gemfile') {
      // Parse Ruby Gemfile
      const lines = content.split('\n').map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
      
      for (const line of lines) {
        // Match gem 'name', '~> version'
        const gemMatch = line.match(/gem\s+['"]([^'"]*)['"](,\s*['"]([^'"]*)['"])?/);
        if (gemMatch) {
          const name = gemMatch[1];
          const version = gemMatch[3] ? gemMatch[3].replace(/[^0-9.]/g, '') : 'latest';
          
          dependencies.push({
            name,
            version,
            type: 'production',
            packageManager,
            manifestFile
          });
        }
      }
    } else if (fileName.endsWith('.csproj') || fileName.endsWith('.fsproj')) {
      // Very simplistic handling of .NET project files
      // For a real scanner, you'd use an XML parser
      const packageRefRegex = /<PackageReference\s+Include=["']([^"']+)["']\s+Version=["']([^"']+)["']\s*\/>/g;
      let match;
      
      while ((match = packageRefRegex.exec(content)) !== null) {
        dependencies.push({
          name: match[1],
          version: match[2],
          type: 'production',
          packageManager,
          manifestFile
        });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.warn(`Error parsing dependencies from ${manifestFile}`, { error });
    return [];
  }
}

/**
 * Get dependency metadata from appropriate registry
 */
async function getDependencyMetadata(
  name: string,
  version: string,
  packageManager: string,
  config: DependencyScannerConfig
): Promise<DependencyMetadata> {
  // Check cache first
  if (config.cacheDir) {
    const cacheFile = path.join(
      config.cacheDir, 
      `${packageManager}-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`
    );
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as DependencyMetadata;
        log.info(`Loaded ${name} dependency info from cache`);
        return cachedInfo;
      } catch (cacheError) {
        log.warn(`Error reading dependency cache for ${name}`, { error: cacheError });
      }
    }
  }
  
  // In a real implementation, we would query package registries
  // For this example, we'll use mock data to simulate API responses
  try {
    log.info(`Querying info for dependency: ${name} ${version} (${packageManager})`);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 100));
    
    // Construct metadata based on the package manager and name
    // This is mock data for demonstration purposes
    const metadata: DependencyMetadata = {
      name,
      latestVersion: incrementVersion(version),
      isDeprecated: Math.random() < 0.1, // 10% chance of being deprecated
      hasSecurityIssues: Math.random() < 0.15, // 15% chance of having security issues
      license: getRandomLicense(),
      repo: `https://github.com/org/${name.toLowerCase()}`,
      lastPublishedAt: new Date(Date.now() - Math.random() * 180 * 24 * 60 * 60 * 1000), // Up to 180 days ago
      downloadCount: Math.floor(Math.random() * 10000000), // Random download count
      maintainedBy: ['developer1', 'developer2']
    };
    
    // Set deprecation reason if deprecated
    if (metadata.isDeprecated) {
      metadata.deprecationReason = getRandomDeprecationReason();
      metadata.alternatives = getRandomAlternatives(name, packageManager);
    }
    
    // Add security issues if flagged
    if (metadata.hasSecurityIssues) {
      metadata.securityIssues = [
        {
          severity: getRandomSeverity(),
          description: `${getRandomVulnerabilityType()} vulnerability in ${name}`,
          fixedInVersion: metadata.latestVersion,
          cve: `CVE-${new Date().getFullYear()}-${Math.floor(Math.random() * 10000)}`
        }
      ];
      
      // Sometimes add a second vulnerability
      if (Math.random() < 0.3) {
        metadata.securityIssues.push({
          severity: getRandomSeverity(),
          description: `${getRandomVulnerabilityType()} vulnerability in ${name}`,
          fixedInVersion: metadata.latestVersion,
          cve: `CVE-${new Date().getFullYear()}-${Math.floor(Math.random() * 10000)}`
        });
      }
    }
    
    // Customize based on some known package names for more realistic examples
    customizeMockMetadata(metadata, name, version, packageManager);
    
    // Save to cache if cacheDir is provided
    if (config.cacheDir) {
      try {
        if (!fs.existsSync(config.cacheDir)) {
          fs.mkdirSync(config.cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(
          config.cacheDir, 
          `${packageManager}-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`
        );
        
        await fs.promises.writeFile(
          cacheFile, 
          JSON.stringify(metadata, null, 2), 
          'utf8'
        );
        
        log.info(`Cached ${name} dependency info`);
      } catch (cacheError) {
        log.warn(`Error writing dependency cache for ${name}`, { error: cacheError });
      }
    }
    
    return metadata;
  } catch (error) {
    log.error(`Error querying info for dependency ${name}`, { error });
    
    // Return default info if query fails
    return {
      name,
      latestVersion: version,
      isDeprecated: false,
      hasSecurityIssues: false
    };
  }
}

/**
 * Customize mock metadata for more realistic examples
 */
function customizeMockMetadata(
  metadata: DependencyMetadata,
  name: string,
  version: string,
  packageManager: string
): void {
  // Well-known vulnerable packages
  const knownVulnerablePackages: Record<string, {
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    fixedInVersion: string;
    affectedVersions: string;
    cve?: string;
  }[]> = {
    'log4j-core': [{
      description: 'Remote code execution vulnerability in log4j',
      severity: 'critical',
      fixedInVersion: '2.15.0',
      affectedVersions: '<2.15.0',
      cve: 'CVE-2021-44228'
    }],
    'lodash': [{
      description: 'Prototype pollution vulnerability in lodash',
      severity: 'high',
      fixedInVersion: '4.17.21',
      affectedVersions: '<4.17.21',
      cve: 'CVE-2021-23337'
    }],
    'express': [{
      description: 'Open redirect vulnerability in express',
      severity: 'medium',
      fixedInVersion: '4.17.3',
      affectedVersions: '<4.17.3',
      cve: 'CVE-2022-24999'
    }],
    'moment': [{
      description: 'Regular expression denial of service',
      severity: 'medium',
      fixedInVersion: '2.29.2',
      affectedVersions: '<2.29.2',
      cve: 'CVE-2022-24785'
    }]
  };
  
  // Known deprecated packages
  const knownDeprecatedPackages: Record<string, {
    reason: string;
    alternatives: string[];
  }> = {
    'request': {
      reason: 'Package is no longer maintained',
      alternatives: ['node-fetch', 'axios', 'got', 'superagent']
    },
    'moment': {
      reason: 'Project is now in maintenance mode',
      alternatives: ['date-fns', 'dayjs', 'luxon']
    },
    'gulp': {
      reason: 'Modern JavaScript build tools have superseded this package',
      alternatives: ['webpack', 'parcel', 'vite', 'esbuild']
    },
    'coffeescript': {
      reason: 'No longer actively developed',
      alternatives: ['TypeScript', 'modern JavaScript']
    }
  };
  
  // Apply known vulnerabilities
  if (name.toLowerCase() in knownVulnerablePackages) {
    const vulns = knownVulnerablePackages[name.toLowerCase()];
    metadata.hasSecurityIssues = true;
    metadata.securityIssues = vulns.map(v => ({
      severity: v.severity,
      description: v.description,
      fixedInVersion: v.fixedInVersion,
      cve: v.cve
    }));
    metadata.latestVersion = vulns[0].fixedInVersion;
  }
  
  // Apply known deprecations
  if (name.toLowerCase() in knownDeprecatedPackages) {
    const depInfo = knownDeprecatedPackages[name.toLowerCase()];
    metadata.isDeprecated = true;
    metadata.deprecationReason = depInfo.reason;
    metadata.alternatives = depInfo.alternatives;
  }
  
  // Update other metadata fields for specific packages
  if (name.toLowerCase() === 'jquery') {
    metadata.latestVersion = '3.6.4';
    metadata.isDeprecated = true;
    metadata.deprecationReason = 'Modern browsers have native APIs that make jQuery unnecessary';
    metadata.alternatives = ['Vanilla JavaScript', 'Alpine.js'];
    metadata.downloadCount = 100000000; // Very popular
  } else if (name.toLowerCase() === 'react') {
    metadata.latestVersion = '18.2.0';
    metadata.isDeprecated = false;
    metadata.downloadCount = 80000000; // Very popular
    metadata.license = 'MIT';
  } else if (name.toLowerCase() === 'vue') {
    metadata.latestVersion = '3.3.4';
    metadata.isDeprecated = false;
    metadata.downloadCount = 45000000; // Very popular
    metadata.license = 'MIT';
  } else if (name.toLowerCase() === 'express') {
    metadata.latestVersion = '4.18.2';
    metadata.isDeprecated = false;
    metadata.downloadCount = 50000000; // Very popular
    metadata.license = 'MIT';
  } else if (name.toLowerCase() === 'webpack') {
    metadata.latestVersion = '5.88.2';
    metadata.isDeprecated = false;
    metadata.downloadCount = 40000000; // Very popular
    metadata.license = 'MIT';
  }
}

/**
 * Check if a version is outdated based on threshold
 */
function isOutdatedVersion(
  currentVersion: string,
  latestVersion: string,
  threshold: { major: number; minor: number; patch: number }
): boolean {
  try {
    // Parse versions
    const current = parseVersion(currentVersion);
    const latest = parseVersion(latestVersion);
    
    // Compare based on threshold
    if (latest.major - current.major > threshold.major) return true;
    if (latest.major === current.major && latest.minor - current.minor > threshold.minor) return true;
    if (latest.major === current.major && latest.minor === current.minor && 
        latest.patch - current.patch > threshold.patch) return true;
    
    return false;
  } catch (error) {
    log.warn(`Error comparing versions: ${currentVersion} vs ${latestVersion}`, { error });
    return false;
  }
}

/**
 * Parse version string into components
 */
function parseVersion(version: string): { major: number; minor: number; patch: number } {
  // Try using semver first
  try {
    const parsed = semver.coerce(version);
    if (parsed) {
      return {
        major: parsed.major,
        minor: parsed.minor,
        patch: parsed.patch
      };
    }
  } catch (error) {
    // Proceed to fallback parsing
  }
  
  // Fallback version parsing
  const parts = version.split('.').map(p => parseInt(p, 10) || 0);
  
  return {
    major: parts[0] || 0,
    minor: parts[1] || 0,
    patch: parts[2] || 0
  };
}

/**
 * Calculate business impact score for a dependency
 */
function calculateBusinessImpact(dep: ParsedDependency, metadata: DependencyMetadata): number {
  let score = 3; // Default medium impact
  
  // Higher impact for production dependencies
  if (dep.type === 'production') score += 1;
  
  // Security issues raise impact significantly
  if (metadata.hasSecurityIssues) {
    // Find the highest severity
    const highestSeverity = metadata.securityIssues?.reduce(
      (highest, current) => {
        const severityRank = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
        const currentRank = severityRank[current.severity] || 0;
        const highestRank = severityRank[highest] || 0;
        return currentRank > highestRank ? current.severity : highest;
      },
      'low' as 'low' | 'medium' | 'high' | 'critical'
    );
    
    if (highestSeverity === 'critical') score += 2;
    else if (highestSeverity === 'high') score += 1.5;
    else if (highestSeverity === 'medium') score += 1;
    else score += 0.5;
  }
  
  // Very popular packages may have higher impact
  if (metadata.downloadCount && metadata.downloadCount > 10000000) score += 0.5;
  
  // Deprecated packages without alternatives are concerning
  if (metadata.isDeprecated && !metadata.alternatives?.length) score += 0.5;
  
  // Bound the score between 1 and 5
  return Math.max(1, Math.min(5, score));
}

/**
 * Calculate update effort score for a dependency
 */
function calculateUpdateEffort(dep: ParsedDependency, metadata: DependencyMetadata): number {
  let score = 2; // Default somewhat easy to update
  
  // Version jump size
  if (dep.version && metadata.latestVersion) {
    const current = parseVersion(dep.version);
    const latest = parseVersion(metadata.latestVersion);
    
    if (latest.major !== current.major) {
      // Major version changes are harder
      score += latest.major - current.major;
    } else if (latest.minor - current.minor > 5) {
      // Many minor versions behind
      score += 0.5;
    }
  }
  
  // Deprecated packages without clear alternatives are harder to update
  if (metadata.isDeprecated) {
    score += metadata.alternatives?.length ? 1 : 2;
  }
  
  // Dependencies used in production code are generally harder to update
  if (dep.type === 'production') score += 0.5;
  
  // Bound the score between 1 and 5
  return Math.max(1, Math.min(5, score));
}

/**
 * Generate tags for a dependency issue
 */
function generateTags(
  dep: ParsedDependency, 
  metadata: DependencyMetadata, 
  isOutdated: boolean
): string[] {
  const tags: string[] = [dep.packageManager, dep.type];
  
  if (isOutdated) tags.push('outdated');
  if (metadata.isDeprecated) tags.push('deprecated');
  if (metadata.hasSecurityIssues) tags.push('security-issue');
  
  // Add severity tag for security issues
  if (metadata.securityIssues?.length) {
    const severities = metadata.securityIssues.map(issue => issue.severity);
    if (severities.includes('critical')) tags.push('critical-severity');
    else if (severities.includes('high')) tags.push('high-severity');
    else if (severities.includes('medium')) tags.push('medium-severity');
    else if (severities.includes('low')) tags.push('low-severity');
  }
  
  // Add license tag if available
  if (metadata.license) {
    tags.push(`license-${metadata.license.toLowerCase().replace(/[^a-z0-9]/g, '-')}`);
  }
  
  // Add popularity tag
  if (metadata.downloadCount) {
    if (metadata.downloadCount > 10000000) tags.push('very-popular');
    else if (metadata.downloadCount > 1000000) tags.push('popular');
    else if (metadata.downloadCount > 100000) tags.push('moderately-popular');
    else tags.push('niche');
  }
  
  return tags;
}

/**
 * Generate a recommendation for the dependency issue
 */
function generateRecommendation(
  dep: ParsedDependency, 
  metadata: DependencyMetadata, 
  isOutdated: boolean
): string {
  const recommendations: string[] = [];
  
  if (metadata.hasSecurityIssues) {
    // Find the highest severity
    const highestSeverity = metadata.securityIssues?.reduce(
      (highest, current) => {
        const severityRank = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
        const currentRank = severityRank[current.severity] || 0;
        const highestRank = severityRank[highest] || 0;
        return currentRank > highestRank ? current.severity : highest;
      },
      'low' as 'low' | 'medium' | 'high' | 'critical'
    );
    
    const issueCount = metadata.securityIssues?.length || 0;
    
    recommendations.push(
      `Update ${dep.name} immediately from ${dep.version} to ${metadata.latestVersion} to fix ${issueCount} ${highestSeverity} severity security ${issueCount === 1 ? 'issue' : 'issues'}`
    );
  } else if (metadata.isDeprecated) {
    recommendations.push(
      `Replace deprecated dependency ${dep.name} ${dep.version}`
    );
    
    if (metadata.deprecationReason) {
      recommendations.push(`Reason: ${metadata.deprecationReason}`);
    }
    
    if (metadata.alternatives?.length) {
      recommendations.push(
        `Consider these alternatives: ${metadata.alternatives.join(', ')}`
      );
    }
  } else if (isOutdated) {
    recommendations.push(
      `Update ${dep.name} from ${dep.version} to ${metadata.latestVersion}`
    );
  }
  
  // If we have no recommendations yet, add a general one
  if (recommendations.length === 0) {
    recommendations.push(
      `No immediate actions needed for ${dep.name} ${dep.version}`
    );
  }
  
  return recommendations.join('. ');
}

/* ---- Helper Functions ---- */

/**
 * Increment a version for demonstration purposes
 */
function incrementVersion(version: string): string {
  try {
    // Clean up version string to ensure it's parseable
    const cleanVersion = version.replace(/[^0-9.]/g, '');
    
    // Handle 'latest' or empty versions
    if (!cleanVersion || cleanVersion === 'latest') {
      return '1.0.0';
    }
    
    const parts = cleanVersion.split('.');
    
    if (parts.length < 3) {
      // Ensure we have at least 3 parts
      while (parts.length < 3) {
        parts.push('0');
      }
    }
    
    // Randomly decide which part to increment
    const random = Math.random();
    let incrementIndex = 2; // Default to patch increment
    
    if (random < 0.1) {
      // 10% chance of major version increment
      incrementIndex = 0;
    } else if (random < 0.3) {
      // 20% chance of minor version increment
      incrementIndex = 1;
    }
    
    // Increment the selected part
    parts[incrementIndex] = String(parseInt(parts[incrementIndex], 10) + 1);
    
    // Reset subsequent parts to 0
    for (let i = incrementIndex + 1; i < parts.length; i++) {
      parts[i] = '0';
    }
    
    return parts.join('.');
  } catch (error) {
    return `${version || '1.0.0'}.1`; // Fallback
  }
}

/**
 * Get a random severity level
 */
function getRandomSeverity(): 'low' | 'medium' | 'high' | 'critical' {
  const severities: Array<'low' | 'medium' | 'high' | 'critical'> = [
    'low', 'medium', 'high', 'critical'
  ];
  const weights = [0.3, 0.4, 0.2, 0.1]; // More medium and low than high and critical
  
  const random = Math.random();
  let sum = 0;
  
  for (let i = 0; i < weights.length; i++) {
    sum += weights[i];
    if (random < sum) {
      return severities[i];
    }
  }
  
  return 'medium'; // Default fallback
}

/**
 * Get a random vulnerability type
 */
function getRandomVulnerabilityType(): string {
  const types = [
    'SQL injection',
    'cross-site scripting',
    'remote code execution',
    'denial of service',
    'buffer overflow',
    'path traversal',
    'privilege escalation',
    'open redirect',
    'insecure deserialization',
    'information disclosure',
    'authentication bypass',
    'memory corruption',
    'prototype pollution',
    'regular expression denial of service',
    'stack overflow',
    'injection',
    'race condition'
  ];
  return types[Math.floor(Math.random() * types.length)];
}

/**
 * Get random deprecation reason
 */
function getRandomDeprecationReason(): string {
  const reasons = [
    'Package is no longer maintained',
    'Package has been superseded by newer alternatives',
    'Security concerns that cannot be fixed',
    'Functionality now included in the language/framework',
    'API fundamentally flawed',
    'Project merged into another package',
    'Author has discontinued development',
    'Performance issues that cannot be resolved',
    'Deprecated by the platform/language',
    'Unmaintained and contains security issues'
  ];
  return reasons[Math.floor(Math.random() * reasons.length)];
}

/**
 * Get random alternatives based on package manager
 */
function getRandomAlternatives(name: string, packageManager: string): string[] {
  // Default alternatives by package manager
  const defaultAlternatives: Record<string, string[]> = {
    npm: ['newer-lib', 'modern-package', 'maintained-tool'],
    composer: ['better-php-lib', 'modern-php-package'],
    pip: ['better-python-lib', 'modern-python-tool'],
    maven: ['better-java-lib', 'modern-java-tool'],
    cargo: ['better-rust-lib', 'modern-rust-tool'],
    bundler: ['better-ruby-gem', 'modern-ruby-tool']
  };
  
  // Use defaults or generate random count of alternatives
  const count = 1 + Math.floor(Math.random() * 3);
  const alternatives = defaultAlternatives[packageManager] || ['alternative-lib'];
  
  // Return a subset of alternatives
  return alternatives.slice(0, count);
}

/**
 * Get a random license
 */
function getRandomLicense(): string {
  const licenses = [
    'MIT',
    'Apache-2.0',
    'GPL-3.0',
    'BSD-3-Clause',
    'ISC',
    'LGPL-2.1',
    'MPL-2.0',
    'AGPL-3.0',
    'Proprietary'
  ];
  return licenses[Math.floor(Math.random() * licenses.length)];
}
