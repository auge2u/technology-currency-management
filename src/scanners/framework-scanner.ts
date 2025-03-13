import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import * as semver from 'semver';
import { log } from '../utils/logging';
import { FrameworkIssue } from '../types/scanning';
import { detectTechnology } from '../utils/technology-detection';

const readFileAsync = promisify(fs.readFile);

/**
 * Configuration for framework scanning
 */
export interface FrameworkScannerConfig {
  // Root directory to scan
  rootDir: string;
  
  // File patterns to include
  includePatterns: string[];
  
  // File patterns to exclude
  excludePatterns: string[];
  
  // Specific frameworks to scan for, empty means all
  frameworks?: string[];
  
  // Whether to include language scanning
  includeLanguages: boolean;
  
  // Whether to include runtime scanning
  includeRuntimes: boolean;
  
  // Whether to include database technology scanning
  includeDatabases: boolean;
  
  // Whether to include infrastructure scanning
  includeInfrastructure: boolean;
  
  // Minimum version age in days to consider outdated
  minAgeForOutdated: number;
  
  // API timeout in milliseconds
  apiTimeoutMs: number;
  
  // Directory to store cached data
  cacheDir?: string;
  
  // Custom technology signatures file path
  customSignaturesPath?: string;
  
  // Ignore certain technologies
  ignoreTechnologies?: string[];
}

/**
 * Technology detection result
 */
interface DetectedTechnology {
  name: string;
  version?: string;
  type: 'framework' | 'language' | 'runtime' | 'database' | 'infrastructure' | 'other';
  file: string;
  signature: string;
  confidence: number;
  matcher?: 'regex' | 'ast' | 'content' | 'filename' | 'manifest';
  lineNumber?: number;
}

/**
 * Technology information from repository
 */
interface TechnologyInfo {
  latestVersion: string;
  isOutdated: boolean;
  isDeprecated: boolean;
  hasSecurityIssues: boolean;
  endOfLifeDate?: Date;
  endOfSupportDate?: Date;
  securityIssues?: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedInVersion?: string;
    cve?: string;
  }>;
  repo?: string;
  license?: string;
  lastRelease?: Date;
  releaseFrequency?: number; // average days between releases
  popularityMetric?: number; // a relative popularity score
  migrationPath?: string;
  migrationDifficulty?: 'easy' | 'medium' | 'hard' | 'very-hard';
  alternatives?: string[];
  businessImpact?: number; // 1-5 where 5 is highest
}

/**
 * Scanner for detecting frameworks and technologies
 */
export async function scanFrameworks(
  config: FrameworkScannerConfig
): Promise<FrameworkIssue[]> {
  try {
    log.info('Starting framework scanner');
    const issues: FrameworkIssue[] = [];
    
    // Find files to scan
    const filePaths = await findFilesToScan(config);
    log.info(`Found ${filePaths.length} files to scan`);
    
    // Track all detected technologies to consolidate later
    const detectedTechnologies: DetectedTechnology[] = [];
    
    // Process each file
    for (const filePath of filePaths) {
      try {
        // Read the file content
        const content = await readFileAsync(filePath, 'utf8');
        
        // Detect technologies in this file
        const technologies = await detectTechnologiesInFile(
          filePath,
          content,
          config
        );
        
        detectedTechnologies.push(...technologies);
      } catch (fileError) {
        log.warn(`Error processing file: ${filePath}`, { error: fileError });
      }
    }
    
    // Consolidate technologies (merge duplicates, keeping track of files)
    const consolidatedTechs = consolidateTechnologies(detectedTechnologies);
    log.info(`Found ${consolidatedTechs.length} unique technologies in codebase`);
    
    // Get technology information and create issues
    for (const tech of consolidatedTechs) {
      try {
        // Skip ignored technologies
        if (config.ignoreTechnologies && config.ignoreTechnologies.includes(tech.name)) {
          log.info(`Skipping ignored technology: ${tech.name}`);
          continue;
        }
        
        // Get technology information
        const techInfo = await getTechnologyInfo(
          tech.name,
          tech.version,
          tech.type,
          config.apiTimeoutMs,
          config.cacheDir
        );
        
        // Create issue if needed
        if (techInfo.isOutdated || techInfo.isDeprecated || techInfo.hasSecurityIssues ||
            (techInfo.endOfLifeDate && techInfo.endOfLifeDate < new Date()) ||
            (techInfo.endOfSupportDate && techInfo.endOfSupportDate < new Date())) {
          
          // Create the issue
          const issue: FrameworkIssue = {
            detectedAt: new Date(),
            name: tech.name,
            currentVersion: tech.version || 'unknown',
            latestVersion: techInfo.latestVersion,
            type: tech.type,
            files: tech.files,
            isOutdated: techInfo.isOutdated,
            isDeprecated: techInfo.isDeprecated,
            hasSecurityIssues: techInfo.hasSecurityIssues,
            endOfLifeDate: techInfo.endOfLifeDate,
            endOfSupportDate: techInfo.endOfSupportDate,
            usageCount: tech.files.length,
            license: techInfo.license,
            repo: techInfo.repo,
            businessImpact: techInfo.businessImpact,
            migrationPath: techInfo.migrationPath,
            tags: generateTags(tech, techInfo),
            recommendation: generateRecommendation(tech, techInfo)
          };
          
          // Add security issues if any
          if (techInfo.securityIssues?.length) {
            issue.securityIssues = techInfo.securityIssues;
          }
          
          // Calculate update effort score
          issue.updateEffort = calculateUpdateEffort(
            tech, 
            techInfo
          );
          
          issues.push(issue);
          log.info(`Added issue for technology ${tech.name} ${tech.version || 'unknown'}`);
        }
      } catch (techError) {
        log.warn(`Error processing technology: ${tech.name}`, { error: techError });
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
 * Find files to scan based on configuration
 */
async function findFilesToScan(
  config: FrameworkScannerConfig
): Promise<string[]> {
  try {
    const allFiles: string[] = [];
    
    for (const pattern of config.includePatterns) {
      const matchedFiles = await glob(
        pattern, 
        { 
          cwd: config.rootDir,
          ignore: config.excludePatterns,
          absolute: true
        }
      );
      
      allFiles.push(...matchedFiles);
    }
    
    return [...new Set(allFiles)]; // Remove duplicates
  } catch (error) {
    log.error('Error finding files to scan', { error });
    return [];
  }
}

/**
 * Detect technologies in a single file
 */
async function detectTechnologiesInFile(
  filePath: string,
  content: string,
  config: FrameworkScannerConfig
): Promise<DetectedTechnology[]> {
  try {
    const fileExt = path.extname(filePath).toLowerCase();
    const fileName = path.basename(filePath);
    const detected: DetectedTechnology[] = [];
    
    // Skip binary files or very large files
    if (content.length > 5 * 1024 * 1024 || isBinaryFile(content)) {
      return [];
    }
    
    // Check for special manifest files
    if (isManifestFile(filePath)) {
      const manifestTechs = await detectFromManifest(filePath, content);
      detected.push(...manifestTechs);
    }
    
    // Detect via technology detection utility
    // This uses file extension, content patterns, and AST parsing
    const detectedTechs = await detectTechnology(filePath, content, {
      customSignaturesPath: config.customSignaturesPath,
      includeFrameworks: true,
      includeLanguages: config.includeLanguages,
      includeRuntimes: config.includeRuntimes,
      includeDatabases: config.includeDatabases,
      includeInfrastructure: config.includeInfrastructure
    });
    
    detected.push(...detectedTechs.map(dt => ({
      name: dt.name,
      version: dt.version,
      type: mapTypeToCategory(dt.type),
      file: filePath,
      signature: dt.signature,
      confidence: dt.confidence,
      matcher: dt.matchType,
      lineNumber: dt.lineNumber
    })));
    
    return detected;
  } catch (error) {
    log.warn(`Error detecting technologies in ${filePath}`, { error });
    return [];
  }
}

/**
 * Check if a file is likely a binary file
 * Very simple check that looks for null bytes in the first chunk
 */
function isBinaryFile(content: string): boolean {
  // Check if the first 1000 characters contain a null byte
  const sample = content.slice(0, 1000);
  return sample.includes('\0');
}

/**
 * Check if a file is a package manifest
 */
function isManifestFile(filePath: string): boolean {
  const fileName = path.basename(filePath).toLowerCase();
  
  return [
    'package.json',
    'composer.json',
    'pom.xml',
    'build.gradle',
    'build.gradle.kts',
    'requirements.txt',
    'pyproject.toml',
    'gemfile',
    'cargo.toml',
    'go.mod',
    'project.clj',
    'mix.exs',
    'yarn.lock',
    'package-lock.json',
    'bun.lockb',
    'pubspec.yaml',
    '.csproj',
    '.fsproj'
  ].some(manifest => fileName.includes(manifest.toLowerCase()));
}

/**
 * Detect technologies from manifest files
 */
async function detectFromManifest(
  filePath: string,
  content: string
): Promise<DetectedTechnology[]> {
  try {
    const fileName = path.basename(filePath).toLowerCase();
    const detected: DetectedTechnology[] = [];
    
    if (fileName === 'package.json') {
      // Parse JavaScript/Node.js package.json
      const packageJson = JSON.parse(content);
      
      // Add the project framework/library itself
      if (packageJson.name && packageJson.version) {
        detected.push({
          name: packageJson.name,
          version: packageJson.version,
          type: 'framework',
          file: filePath,
          signature: 'package.json name+version',
          confidence: 1.0,
          matcher: 'manifest'
        });
      }
      
      // Detect dependencies
      for (const [depType, deps] of Object.entries({
        dependencies: packageJson.dependencies || {},
        devDependencies: packageJson.devDependencies || {},
        peerDependencies: packageJson.peerDependencies || {},
        optionalDependencies: packageJson.optionalDependencies || {}
      })) {
        for (const [name, version] of Object.entries(deps as Record<string, string>)) {
          detected.push({
            name,
            version: version.toString().replace(/[^0-9.]/g, ''),
            type: 'framework',
            file: filePath,
            signature: `package.json ${depType}`,
            confidence: 1.0,
            matcher: 'manifest'
          });
        }
      }
      
      // Add React if jsx or tsx is in the package.json config
      if ((packageJson.babel?.presets?.includes('react') || 
          packageJson.dependencies?.react ||
          content.includes('"jsx"')) && 
          !detected.some(d => d.name === 'react')) {
        
        const reactVersion = packageJson.dependencies?.react ||
                            packageJson.peerDependencies?.react ||
                            'unknown';
        
        detected.push({
          name: 'react',
          version: reactVersion.toString().replace(/[^0-9.]/g, ''),
          type: 'framework',
          file: filePath,
          signature: 'package.json inferred',
          confidence: 0.9,
          matcher: 'manifest'
        });
      }
    } else if (fileName === 'composer.json') {
      // Parse PHP Composer.json
      const composerJson = JSON.parse(content);
      
      // Add the project itself
      if (composerJson.name && composerJson.version) {
        detected.push({
          name: composerJson.name,
          version: composerJson.version,
          type: 'framework',
          file: filePath,
          signature: 'composer.json name+version',
          confidence: 1.0,
          matcher: 'manifest'
        });
      }
      
      // Add PHP framework/version if specified
      if (composerJson.require?.php) {
        detected.push({
          name: 'php',
          version: composerJson.require.php.toString().replace(/[^0-9.]/g, ''),
          type: 'language',
          file: filePath,
          signature: 'composer.json require.php',
          confidence: 1.0,
          matcher: 'manifest'
        });
      }
      
      // Detect dependencies
      for (const [name, version] of Object.entries(composerJson.require || {})) {
        if (name !== 'php') { // Skip PHP itself, already added
          detected.push({
            name,
            version: version.toString().replace(/[^0-9.]/g, ''),
            type: 'framework',
            file: filePath,
            signature: 'composer.json require',
            confidence: 1.0,
            matcher: 'manifest'
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
          detected.push({
            name,
            version,
            type: 'framework',
            file: filePath,
            signature: 'requirements.txt dependency',
            confidence: 1.0,
            matcher: 'manifest'
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
        if (['project', 'tool.poetry.dependencies', 'dependencies', 'build-system.requires'].some(s => currentSection.includes(s))) {
          const depMatch = line.match(/([a-zA-Z0-9_.-]+)\s*=\s*["']?([0-9a-zA-Z.-]+)["']?/);
          if (depMatch) {
            const [_, name, version] = depMatch;
            detected.push({
              name,
              version,
              type: 'framework',
              file: filePath,
              signature: `pyproject.toml ${currentSection}`,
              confidence: 1.0,
              matcher: 'manifest'
            });
          }
        }
      }
    } else if (fileName === 'go.mod') {
      // Parse Go modules
      const lines = content.split('\n');
      
      // Extract module name
      const moduleMatch = lines.find(line => line.startsWith('module '));
      if (moduleMatch) {
        const moduleName = moduleMatch.split(' ')[1].trim();
        detected.push({
          name: moduleName,
          type: 'framework',
          file: filePath,
          signature: 'go.mod module',
          confidence: 1.0,
          matcher: 'manifest'
        });
      }
      
      // Extract Go version
      const goMatch = lines.find(line => line.startsWith('go '));
      if (goMatch) {
        const goVersion = goMatch.split(' ')[1].trim();
        detected.push({
          name: 'go',
          version: goVersion,
          type: 'language',
          file: filePath,
          signature: 'go.mod go version',
          confidence: 1.0,
          matcher: 'manifest'
        });
      }
      
      // Extract dependencies
      let inRequireBlock = false;
      for (const line of lines) {
        if (line.startsWith('require (')) {
          inRequireBlock = true;
          continue;
        }
        
        if (inRequireBlock && line.startsWith(')')) {
          inRequireBlock = false;
          continue;
        }
        
        // Check for single-line require
        const singleRequireMatch = line.match(/^require\s+([^\s]+)\s+v([0-9.]+)/);
        if (singleRequireMatch) {
          detected.push({
            name: singleRequireMatch[1],
            version: singleRequireMatch[2],
            type: 'framework',
            file: filePath,
            signature: 'go.mod require single',
            confidence: 1.0,
            matcher: 'manifest'
          });
          continue;
        }
        
        // Check for require block entries
        if (inRequireBlock) {
          const blockRequireMatch = line.match(/\s+([^\s]+)\s+v([0-9.]+)/);
          if (blockRequireMatch) {
            detected.push({
              name: blockRequireMatch[1],
              version: blockRequireMatch[2],
              type: 'framework',
              file: filePath,
              signature: 'go.mod require block',
              confidence: 1.0,
              matcher: 'manifest'
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
        
        // Package info
        if (currentSection === 'package') {
          const nameMatch = line.match(/^name\s*=\s*["']([^"']+)["']/);
          const versionMatch = line.match(/^version\s*=\s*["']([^"']+)["']/);
          
          if (nameMatch) {
            detected.push({
              name: nameMatch[1],
              version: versionMatch ? versionMatch[1] : undefined,
              type: 'framework',
              file: filePath,
              signature: 'cargo.toml package',
              confidence: 1.0,
              matcher: 'manifest'
            });
          }
        }
        
        // Dependencies
        if (currentSection === 'dependencies' || currentSection.startsWith('dependencies.')) {
          // Simple key = "version"
          const simpleDepMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*["']([^"']+)["']/);
          if (simpleDepMatch) {
            detected.push({
              name: simpleDepMatch[1],
              version: simpleDepMatch[2],
              type: 'framework',
              file: filePath,
              signature: `cargo.toml ${currentSection}`,
              confidence: 1.0,
              matcher: 'manifest'
            });
          }
          
          // Table format with version
          const tableDepMatch = line.match(/^([a-zA-Z0-9_-]+)\s*\.version\s*=\s*["']([^"']+)["']/);
          if (tableDepMatch) {
            detected.push({
              name: tableDepMatch[1],
              version: tableDepMatch[2],
              type: 'framework',
              file: filePath,
              signature: `cargo.toml ${currentSection} table`,
              confidence: 1.0,
              matcher: 'manifest'
            });
          }
        }
      }
    }
    
    return detected;
  } catch (error) {
    log.warn(`Error parsing manifest file: ${filePath}`, { error });
    return [];
  }
}

/**
 * Map general type to category
 */
function mapTypeToCategory(type: string): 'framework' | 'language' | 'runtime' | 'database' | 'infrastructure' | 'other' {
  const typeMap: Record<string, 'framework' | 'language' | 'runtime' | 'database' | 'infrastructure' | 'other'> = {
    'framework': 'framework',
    'library': 'framework',
    'language': 'language',
    'runtime': 'runtime',
    'database': 'database',
    'infrastructure': 'infrastructure',
    'tool': 'other',
    'platform': 'infrastructure'
  };
  
  return typeMap[type.toLowerCase()] || 'other';
}

/**
 * Consolidate detected technologies from multiple files
 */
function consolidateTechnologies(
  detectedTechnologies: DetectedTechnology[]
): Array<DetectedTechnology & { files: string[] }> {
  const techMap = new Map<string, DetectedTechnology & { files: string[] }>();
  
  // Group by name and type
  for (const tech of detectedTechnologies) {
    const key = `${tech.name}|${tech.type}`;
    
    if (!techMap.has(key)) {
      techMap.set(key, {
        ...tech,
        files: [tech.file]
      });
    } else {
      const existing = techMap.get(key)!;
      
      // Add file if not already included
      if (!existing.files.includes(tech.file)) {
        existing.files.push(tech.file);
      }
      
      // Use the more specific version if available
      if (tech.version && (!existing.version || 
          (tech.confidence > existing.confidence) ||
          (tech.matcher === 'manifest' && existing.matcher !== 'manifest'))) {
        existing.version = tech.version;
        existing.confidence = tech.confidence;
        existing.matcher = tech.matcher;
      }
    }
  }
  
  return Array.from(techMap.values());
}

/**
 * Get technology information from repository or cache
 */
async function getTechnologyInfo(
  name: string,
  version: string | undefined,
  type: 'framework' | 'language' | 'runtime' | 'database' | 'infrastructure' | 'other',
  timeoutMs: number,
  cacheDir?: string
): Promise<TechnologyInfo> {
  // Check cache first
  if (cacheDir) {
    const cacheFile = path.join(cacheDir, `tech-${type}-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
    
    if (fs.existsSync(cacheFile)) {
      try {
        const cacheContent = await readFileAsync(cacheFile, 'utf8');
        const cachedInfo = JSON.parse(cacheContent) as TechnologyInfo;
        log.info(`Loaded ${name} technology info from cache`);
        return cachedInfo;
      } catch (cacheError) {
        log.warn(`Error reading technology cache for ${name}`, { error: cacheError });
      }
    }
  }
  
  // In a real implementation, we would query technology repositories
  // For this example, we'll use mock data
  try {
    log.info(`Querying info for technology: ${name} ${version || 'unknown'} (${type})`);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 200));
    
    // Generate latest version
    let latestVersion = version ? incrementVersion(version) : '1.0.0';
    
    // Set technology-specific values
    let isDeprecated = false;
    let releaseFrequency = 30 + Math.floor(Math.random() * 60); // days
    let endOfLifeDate: Date | undefined = undefined;
    let endOfSupportDate: Date | undefined = undefined;
    let migrationPath: string | undefined = undefined;
    let migrationDifficulty: 'easy' | 'medium' | 'hard' | 'very-hard' | undefined = undefined;
    let alternatives: string[] | undefined = undefined;
    
    // Customize based on some known technology names
    if (name.toLowerCase() === 'jquery') {
      isDeprecated = true;
      latestVersion = '3.6.4';
      migrationPath = 'Migrate to native JavaScript or modern frameworks';
      migrationDifficulty = 'medium';
      alternatives = ['Vanilla JavaScript', 'React', 'Vue.js', 'Alpine.js'];
    } else if (name.toLowerCase() === 'php' && version && semver.lt(version, '7.4.0')) {
      isDeprecated = true;
      latestVersion = '8.2.0';
      endOfLifeDate = new Date('2022-11-28');
      endOfSupportDate = new Date('2023-11-28');
      migrationPath = 'Upgrade to PHP 8.x';
      migrationDifficulty = 'medium';
    } else if (name.toLowerCase() === 'python' && version && semver.lt(version, '3.7.0')) {
      isDeprecated = true;
      latestVersion = '3.11.0';
      endOfLifeDate = new Date('2023-06-27');
      endOfSupportDate = new Date('2023-06-27');
      migrationPath = 'Upgrade to Python 3.10+';
      migrationDifficulty = 'medium';
    } else if (name.toLowerCase() === 'react' && version && semver.lt(version, '16.0.0')) {
      isDeprecated = false;
      latestVersion = '18.2.0';
      migrationPath = 'Upgrade to React 18';
      migrationDifficulty = 'medium';
    } else if (name.toLowerCase() === 'angular.js') {
      isDeprecated = true;
      latestVersion = '1.8.3';
      endOfLifeDate = new Date('2022-01-01');
      endOfSupportDate = new Date('2022-01-01');
      migrationPath = 'Migrate to Angular 2+';
      migrationDifficulty = 'hard';
      alternatives = ['Angular', 'React', 'Vue.js'];
    } else if (name.toLowerCase() === 'node' && version && semver.lt(version, '16.0.0')) {
      isDeprecated = version.startsWith('15') || version.startsWith('13');
      latestVersion = '20.0.0';
      if (semver.lt(version, '14.0.0')) {
        endOfLifeDate = new Date('2023-04-30');
        endOfSupportDate = new Date('2023-04-30');
      }
      migrationPath = 'Upgrade to Node.js 20 LTS';
      migrationDifficulty = 'easy';
    }
    
    // Calculate if outdated based on version difference
    const isOutdated = version && latestVersion ?
      compareVersions(latestVersion, version) > 0 : false;
    
    // Generate mock security issues for some percentage of technologies
    const hasSecurityIssues = Math.random() < 0.15; // 15% chance
    
    // Calculate business impact based on usage, criticality of the technology
    const businessImpact = Math.min(5, Math.ceil(Math.random() * 5));
    
    // Create the technology info
    const info: TechnologyInfo = {
      latestVersion,
      isOutdated,
      isDeprecated,
      hasSecurityIssues,
      endOfLifeDate,
      endOfSupportDate,
      license: getRandomLicense(),
      repo: `https://github.com/org/${name.toLowerCase()}`,
      lastRelease: new Date(Date.now() - Math.random() * 180 * 24 * 60 * 60 * 1000), // Up to 180 days ago
      releaseFrequency,
      popularityMetric: Math.random() * 100,
      migrationPath,
      migrationDifficulty,
      alternatives,
      businessImpact
    };
    
    // Add security issues if flagged
    if (info.hasSecurityIssues) {
      info.securityIssues = [
        {
          severity: getRandomSeverity(),
          description: `${getRandomVulnerabilityType()} vulnerability in ${name}`,
          fixedInVersion: latestVersion,
          cve: `CVE-${new Date().getFullYear()}-${Math.floor(Math.random() * 10000)}`
        }
      ];
      
      // Sometimes add a second vulnerability
      if (Math.random() < 0.3) {
        info.securityIssues.push({
          severity: getRandomSeverity(),
          description: `${getRandomVulnerabilityType()} vulnerability in ${name}`,
          fixedInVersion: latestVersion,
          cve: `CVE-${new Date().getFullYear()}-${Math.floor(Math.random() * 10000)}`
        });
      }
    }
    
    // Save to cache if cacheDir is provided
    if (cacheDir) {
      try {
        if (!fs.existsSync(cacheDir)) {
          fs.mkdirSync(cacheDir, { recursive: true });
        }
        
        const cacheFile = path.join(cacheDir, `tech-${type}-${name.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.json`);
        await fs.promises.writeFile(cacheFile, JSON.stringify(info, null, 2), 'utf8');
        log.info(`Cached ${name} technology info`);
      } catch (cacheError) {
        log.warn(`Error writing technology cache for ${name}`, { error: cacheError });
      }
    }
    
    return info;
  } catch (error) {
    log.error(`Error querying info for technology ${name}`, { error });
    
    // Return basic info if query fails
    return {
      latestVersion: version || '1.0.0',
      isOutdated: false,
      isDeprecated: false,
      hasSecurityIssues: false
    };
  }
}

/**
 * Calculate update effort score for a technology
 */
function calculateUpdateEffort(
  tech: DetectedTechnology & { files: string[] },
  info: TechnologyInfo
): number {
  let score = 3; // Default medium effort
  
  // More files using this technology means higher effort
  if (tech.files.length > 100) score += 2;
  else if (tech.files.length > 30) score += 1;
  
  // Migration difficulty if specified
  if (info.migrationDifficulty) {
    switch (info.migrationDifficulty) {
      case 'easy': score -= 1; break;
      case 'medium': break; // No change
      case 'hard': score += 1; break;
      case 'very-hard': score += 2; break;
    }
  }
  
  // Major version changes are harder
  if (tech.version && info.latestVersion) {
    const versionDiff = calculateVersionDifference(tech.version, info.latestVersion);
    if (versionDiff.major >= 2) score += 1;
    if (versionDiff.major >= 5) score += 1;
  }
  
  // Types of technology affect difficulty
  if (tech.type === 'framework') score += 1;
  if (tech.type === 'language') score += 2;
  if (tech.type === 'database') score += 2;
  
  // Deprecated technologies often have poor upgrade paths
  if (info.isDeprecated) score += 1;
  
  // Bound the score between 1 and 5
  return Math.max(1, Math.min(5, score));
}

/**
 * Generate tags for a technology issue
 */
function generateTags(
  tech: DetectedTechnology & { files: string[] },
  info: TechnologyInfo
): string[] {
  const tags: string[] = [tech.type];
  
  if (info.isOutdated) tags.push('outdated');
  if (info.isDeprecated) tags.push('deprecated');
  if (info.hasSecurityIssues) tags.push('security-issue');
  
  if (info.endOfLifeDate) {
    const now = new Date();
    if (info.endOfLifeDate < now) {
      tags.push('end-of-life');
    } else if (info.endOfLifeDate.getTime() - now.getTime() < 180 * 24 * 60 * 60 * 1000) {
      tags.push('approaching-eol'); // Within 180 days of EOL
    }
  }
  
  // Add severity tag for security issues
  if (info.securityIssues?.length) {
    const severities = info.securityIssues.map(issue => issue.severity);
    if (severities.includes('critical')) tags.push('critical-severity');
    else if (severities.includes('high')) tags.push('high-severity');
    else if (severities.includes('medium')) tags.push('medium-severity');
    else if (severities.includes('low')) tags.push('low-severity');
  }
  
  // Add usage extent
  if (tech.files.length > 100) tags.push('widespread-usage');
  else if (tech.files.length > 30) tags.push('moderate-usage');
  else tags.push('limited-usage');
  
  // Add migration difficulty if available
  if (info.migrationDifficulty) {
    tags.push(`migration-${info.migrationDifficulty}`);
  }
  
  // Add license tag if available
  if (info.license) {
    tags.push(`license-${info.license.toLowerCase().replace(/[^a-z0-9]/g, '-')}`);
  }
  
  return tags;
}

/**
 * Generate a recommendation for the technology issue
 */
function generateRecommendation(
  tech: DetectedTechnology & { files: string[] },
  info: TechnologyInfo
): string {
  const recommendations: string[] = [];
  
  if (info.hasSecurityIssues) {
    // Find the highest severity
    const highestSeverity = info.securityIssues?.reduce(
      (highest, current) => {
        const severityRank = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
        const currentRank = severityRank[current.severity] || 0;
        const highestRank = severityRank[highest] || 0;
        return currentRank > highestRank ? current.severity : highest;
      },
      'low' as 'low' | 'medium' | 'high' | 'critical'
    );
    
    recommendations.push(
      `Update ${tech.name} immediately to fix ${highestSeverity} severity security ${info.securityIssues?.length === 1 ? 'issue' : 'issues'}`
    );
  } else if (info.endOfLifeDate && info.endOfLifeDate < new Date()) {
    recommendations.push(
      `Replace end-of-life technology ${tech.name} ${tech.version || ''}`
    );
    
    if (info.migrationPath) {
      recommendations.push(info.migrationPath);
    }
    
    if (info.alternatives?.length) {
      recommendations.push(
        `Consider these alternatives: ${info.alternatives.join(', ')}`
      );
    }
  } else if (info.isDeprecated) {
    recommendations.push(
      `Plan migration away from deprecated technology ${tech.name} ${tech.version || ''}`
    );
    
    if (info.migrationPath) {
      recommendations.push(info.migrationPath);
    }
    
    if (info.alternatives?.length) {
      recommendations.push(
        `Consider these alternatives: ${info.alternatives.join(', ')}`
      );
    }
  } else if (info.endOfSupportDate && info.endOfSupportDate.getTime() - new Date().getTime() < 180 * 24 * 60 * 60 * 1000) {
    // Within 180 days of end of support
    const daysToEOS = Math.ceil((info.endOfSupportDate.getTime() - new Date().getTime()) / (24 * 60 * 60 * 1000));
    
    recommendations.push(
      `Update ${tech.name} ${tech.version || ''} within ${daysToEOS} days before end of support`
    );
    
    if (info.migrationPath) {
      recommendations.push(info.migrationPath);
    }
  } else if (info.isOutdated) {
    recommendations.push(
      `Update ${tech.name} from ${tech.version || 'unknown'} to ${info.latestVersion}`
    );
    
    if (info.migrationPath) {
      recommendations.push(info.migrationPath);
    }
  }
  
  // If we have no recommendations yet, add a general one
  if (recommendations.length === 0) {
    recommendations.push(
      `No immediate actions needed for ${tech.name} ${tech.version || ''}`
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
    return `${version}.1`; // Fallback
  }
}

/**
 * Compare two version strings
 * Returns > 0 if version1 is greater, < 0 if version2 is greater, 0 if equal
 */
function compareVersions(version1: string, version2: string): number {
  try {
    return semver.compare(
      semver.coerce(version1)?.version || version1,
      semver.coerce(version2)?.version || version2
    );
  } catch (error) {
    // Fallback manual comparison if semver fails
    const v1parts = version1.split('.').map(p => parseInt(p, 10) || 0);
    const v2parts = version2.split('.').map(p => parseInt(p, 10) || 0);
    
    // Ensure both arrays have the same length
    while (v1parts.length < v2parts.length) v1parts.push(0);
    while (v2parts.length < v1parts.length) v2parts.push(0);
    
    // Compare each part
    for (let i = 0; i < v1parts.length; i++) {
      if (v1parts[i] > v2parts[i]) return 1;
      if (v1parts[i] < v2parts[i]) return -1;
    }
    
    return 0;
  }
}

/**
 * Calculate the difference between two versions
 */
function calculateVersionDifference(
  currentVersion: string,
  latestVersion: string
): { major: number, minor: number, patch: number } {
  try {
    const current = semver.coerce(currentVersion);
    const latest = semver.coerce(latestVersion);
    
    if (current && latest) {
      return {
        major: Math.max(0, latest.major - current.major),
        minor: Math.max(0, latest.minor - current.minor),
        patch: Math.max(0, latest.patch - current.patch)
      };
    }
  } catch (error) {
    // Proceed to fallback
  }
  
  // Fallback manual calculation
  const current = currentVersion.split('.').map(p => parseInt(p, 10) || 0);
  const latest = latestVersion.split('.').map(p => parseInt(p, 10) || 0);
  
  // Ensure both arrays have at least 3 elements
  while (current.length < 3) current.push(0);
  while (latest.length < 3) latest.push(0);
  
  return {
    major: Math.max(0, latest[0] - current[0]),
    minor: Math.max(0, latest[1] - current[1]),
    patch: Math.max(0, latest[2] - current[2])
  };
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
    'memory corruption'
  ];
  return types[Math.floor(Math.random() * types.length)];
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
