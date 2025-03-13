import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { glob } from 'glob';
import { exec } from 'child_process';
import { log } from '../utils/logging';
import { DependencyIssue, ScannerConfig } from '../types/scanning';

const readFileAsync = promisify(fs.readFile);
const execAsync = promisify(exec);

/**
 * Dependency scanner configuration
 */
export interface DependencyScannerConfig extends ScannerConfig {
  // Package managers to include in the scan
  packageManagers?: Array<'npm' | 'pip' | 'maven' | 'gradle' | 'nuget'>;
  
  // Whether to scan direct dependencies only
  directDependenciesOnly?: boolean;
  
  // Whether to use vulnerability databases
  checkVulnerabilities?: boolean;
  
  // Custom vulnerability database paths
  vulnerabilityDbPaths?: {
    npm?: string;
    pip?: string;
    maven?: string;
    gradle?: string;
    nuget?: string;
  };
  
  // Maximum depth for transitive dependencies
  maxTransitiveDepth?: number;
  
  // Whether to extract update impact information
  assessUpdateImpact?: boolean;
  
  // Custom registry URLs
  registryUrls?: {
    npm?: string;
    pip?: string;
    maven?: string;
    gradle?: string;
    nuget?: string;
  };
}

/**
 * Vulnerability information from various sources
 */
interface VulnerabilityInfo {
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  cveIds?: string[];
  fixedInVersion?: string;
  url?: string;
}

/**
 * Package information extracted from manifest files
 */
interface PackageInfo {
  name: string;
  version: string;
  isDirect: boolean;
  dependencyType?: 'regular' | 'dev' | 'peer' | 'optional';
  packageManager: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget';
  sourcePath: string;
  parent?: string; // For transitive dependencies
  depth?: number;  // Depth in dependency tree
}

/**
 * Result of checking a package against registry
 */
interface PackageCheckResult {
  isOutdated: boolean;
  latestVersion?: string;
  isVulnerable: boolean;
  vulnerabilities: VulnerabilityInfo[];
  updateImpact: {
    breakingChanges: boolean;
    affectedComponents?: string[];
    estimatedEffort: 'low' | 'medium' | 'high';
  };
}

/**
 * Main function to scan dependencies
 */
export async function scanDependencies(
  config: DependencyScannerConfig
): Promise<DependencyIssue[]> {
  try {
    log.info('Starting dependency scanner');
    const issues: DependencyIssue[] = [];
    
    // Determine which package managers to scan
    const packageManagers = config.packageManagers || ['npm', 'pip', 'maven', 'gradle', 'nuget'];
    log.info(`Scanning for package managers: ${packageManagers.join(', ')}`);
    
    // Extract packages from manifest files
    const extractedPackages = await extractAllPackages(config, packageManagers);
    log.info(`Found ${extractedPackages.length} packages across all manifests`);
    
    // Process each package
    for (const pkg of extractedPackages) {
      try {
        log.info(`Checking package: ${pkg.name}@${pkg.version} (${pkg.packageManager})`);
        
        // Skip if config specifies direct dependencies only and this is transitive
        if (config.directDependenciesOnly && !pkg.isDirect) {
          continue;
        }
        
        // Skip if beyond max transitive depth
        if (config.maxTransitiveDepth !== undefined && 
            pkg.depth !== undefined && 
            pkg.depth > config.maxTransitiveDepth) {
          continue;
        }
        
        // Check package against registry and vulnerability databases
        const checkResult = await checkPackage(pkg, config);
        
        // Create issues for outdated or vulnerable packages
        if (checkResult.isOutdated || checkResult.isVulnerable) {
          const issue: DependencyIssue = {
            detectedAt: new Date(),
            packageName: pkg.name,
            currentVersion: pkg.version,
            latestVersion: checkResult.latestVersion,
            packageManager: pkg.packageManager,
            isDirect: pkg.isDirect,
            isOutdated: checkResult.isOutdated,
            isVulnerable: checkResult.isVulnerable,
            vulnerabilities: checkResult.vulnerabilities,
            dependentFiles: [pkg.sourcePath],
            updateImpact: checkResult.updateImpact,
            riskLevel: calculateRiskLevel(checkResult),
            tags: generateTags(pkg, checkResult),
            recommendation: generateRecommendation(pkg, checkResult)
          };
          
          issues.push(issue);
          log.info(`Added issue for ${pkg.name}@${pkg.version}`);
        }
      } catch (pkgError) {
        log.error(`Error checking package ${pkg.name}@${pkg.version}`, { error: pkgError });
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
 * Extract packages from all manifest files for specified package managers
 */
async function extractAllPackages(
  config: DependencyScannerConfig,
  packageManagers: Array<'npm' | 'pip' | 'maven' | 'gradle' | 'nuget'>
): Promise<PackageInfo[]> {
  const allPackages: PackageInfo[] = [];
  
  // Define file patterns for each package manager
  const filePatterns: Record<string, string[]> = {
    npm: ['**/package.json', '!**/node_modules/**'],
    pip: ['**/requirements.txt', '**/Pipfile', '**/setup.py', '!**/.venv/**', '!**/env/**'],
    maven: ['**/pom.xml'],
    gradle: ['**/build.gradle', '**/build.gradle.kts'],
    nuget: ['**/*.csproj', '**/packages.config']
  };
  
  // Process each package manager
  for (const manager of packageManagers) {
    try {
      log.info(`Looking for ${manager} manifest files`);
      
      // Find all manifest files for this package manager
      let manifests: string[] = [];
      for (const pattern of filePatterns[manager]) {
        const files = await glob(pattern, {
          cwd: config.rootDir,
          absolute: true,
          ignore: [...(config.excludePaths || []), '**/.git/**']
        });
        manifests.push(...files);
      }
      
      log.info(`Found ${manifests.length} ${manager} manifest files`);
      
      // Extract packages from each manifest
      for (const manifestPath of manifests) {
        try {
          const packages = await extractPackagesFromManifest(manifestPath, manager);
          allPackages.push(...packages);
        } catch (manifestError) {
          log.warn(`Error extracting packages from ${manifestPath}`, { error: manifestError });
        }
      }
    } catch (managerError) {
      log.error(`Error processing ${manager} dependencies`, { error: managerError });
    }
  }
  
  return allPackages;
}

/**
 * Extract packages from a single manifest file
 */
async function extractPackagesFromManifest(
  manifestPath: string,
  packageManager: 'npm' | 'pip' | 'maven' | 'gradle' | 'nuget'
): Promise<PackageInfo[]> {
  try {
    const content = await readFileAsync(manifestPath, 'utf8');
    const packages: PackageInfo[] = [];
    
    switch (packageManager) {
      case 'npm':
        return extractNpmPackages(content, manifestPath);
      case 'pip':
        return extractPipPackages(content, manifestPath);
      case 'maven':
        return extractMavenPackages(content, manifestPath);
      case 'gradle':
        return extractGradlePackages(content, manifestPath);
      case 'nuget':
        return extractNugetPackages(content, manifestPath);
      default:
        return [];
    }
  } catch (error) {
    log.warn(`Error reading manifest file ${manifestPath}`, { error });
    return [];
  }
}

/**
 * Extract packages from npm package.json
 */
function extractNpmPackages(content: string, manifestPath: string): PackageInfo[] {
  try {
    const packages: PackageInfo[] = [];
    const parsed = JSON.parse(content);
    
    // Process regular dependencies
    if (parsed.dependencies) {
      for (const [name, version] of Object.entries(parsed.dependencies)) {
        packages.push({
          name,
          // Handle different version formats (e.g., "^1.2.3", "~1.2.3", "1.2.3")
          version: typeof version === 'string' ? version.replace(/[^0-9.]/g, '') : 'unknown',
          isDirect: true,
          dependencyType: 'regular',
          packageManager: 'npm',
          sourcePath: manifestPath,
          depth: 0
        });
      }
    }
    
    // Process dev dependencies
    if (parsed.devDependencies) {
      for (const [name, version] of Object.entries(parsed.devDependencies)) {
        packages.push({
          name,
          version: typeof version === 'string' ? version.replace(/[^0-9.]/g, '') : 'unknown',
          isDirect: true,
          dependencyType: 'dev',
          packageManager: 'npm',
          sourcePath: manifestPath,
          depth: 0
        });
      }
    }
    
    // Process peer dependencies
    if (parsed.peerDependencies) {
      for (const [name, version] of Object.entries(parsed.peerDependencies)) {
        packages.push({
          name,
          version: typeof version === 'string' ? version.replace(/[^0-9.]/g, '') : 'unknown',
          isDirect: true,
          dependencyType: 'peer',
          packageManager: 'npm',
          sourcePath: manifestPath,
          depth: 0
        });
      }
    }
    
    // Process optional dependencies
    if (parsed.optionalDependencies) {
      for (const [name, version] of Object.entries(parsed.optionalDependencies)) {
        packages.push({
          name,
          version: typeof version === 'string' ? version.replace(/[^0-9.]/g, '') : 'unknown',
          isDirect: true,
          dependencyType: 'optional',
          packageManager: 'npm',
          sourcePath: manifestPath,
          depth: 0
        });
      }
    }
    
    return packages;
  } catch (error) {
    log.warn(`Error parsing npm manifest ${manifestPath}`, { error });
    return [];
  }
}

/**
 * Extract packages from pip requirements.txt, Pipfile, or setup.py
 */
function extractPipPackages(content: string, manifestPath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  const filename = path.basename(manifestPath).toLowerCase();
  
  try {
    if (filename === 'requirements.txt') {
      // Process requirements.txt
      const lines = content.split('\n');
      
      for (const line of lines) {
        // Skip comments and empty lines
        if (line.trim().startsWith('#') || line.trim() === '') {
          continue;
        }
        
        // Extract package name and version
        // Handle various formats: package==1.2.3, package>=1.2.3, package~=1.2.3
        const match = line.match(/^([a-zA-Z0-9_.-]+)\s*([=<>~!]+)\s*([0-9a-zA-Z.]+)/);
        
        if (match) {
          packages.push({
            name: match[1],
            version: match[3],
            isDirect: true,
            packageManager: 'pip',
            sourcePath: manifestPath,
            depth: 0
          });
        } else if (!line.includes('-r ')) { // Skip include directives
          // Just package name without version
          const pkgName = line.trim().split(' ')[0].split('#')[0].trim();
          if (pkgName) {
            packages.push({
              name: pkgName,
              version: 'latest',
              isDirect: true,
              packageManager: 'pip',
              sourcePath: manifestPath,
              depth: 0
            });
          }
        }
      }
    } else if (filename === 'pipfile') {
      // Process Pipfile (simplified, would need proper TOML parsing for production)
      let inPackages = false;
      let inDevPackages = false;
      const lines = content.split('\n');
      
      for (const line of lines) {
        if (line.trim() === '[packages]') {
          inPackages = true;
          inDevPackages = false;
          continue;
        } else if (line.trim() === '[dev-packages]') {
          inPackages = false;
          inDevPackages = true;
          continue;
        } else if (line.trim().startsWith('[')) {
          inPackages = false;
          inDevPackages = false;
          continue;
        }
        
        if (inPackages || inDevPackages) {
          // Match package specifications
          const match = line.match(/^([a-zA-Z0-9_.-]+)\s*=\s*"([^"]+)"/i);
          if (match) {
            packages.push({
              name: match[1],
              version: match[2].replace(/[^0-9.]/g, ''),
              isDirect: true,
              dependencyType: inDevPackages ? 'dev' : 'regular',
              packageManager: 'pip',
              sourcePath: manifestPath,
              depth: 0
            });
          }
        }
      }
    } else if (filename === 'setup.py') {
      // Process setup.py (simplified, would need AST parsing for production)
      const installRequiresMatch = content.match(/install_requires\s*=\s*\[([^\]]+)\]/s);
      if (installRequiresMatch) {
        const requiresStr = installRequiresMatch[1];
        // Extract quoted strings
        const requiresList = requiresStr.match(/['"]([^'"]+)['"],?/g);
        
        if (requiresList) {
          for (const item of requiresList) {
            const pkgSpec = item.replace(/['",]/g, '').trim();
            // Parse similar to requirements.txt format
            const match = pkgSpec.match(/^([a-zA-Z0-9_.-]+)\s*([=<>~!]+)\s*([0-9a-zA-Z.]+)/);
            
            if (match) {
              packages.push({
                name: match[1],
                version: match[3],
                isDirect: true,
                packageManager: 'pip',
                sourcePath: manifestPath,
                depth: 0
              });
            } else {
              // Just package name
              const pkgName = pkgSpec.split(' ')[0].split('#')[0].trim();
              if (pkgName) {
                packages.push({
                  name: pkgName,
                  version: 'latest',
                  isDirect: true,
                  packageManager: 'pip',
                  sourcePath: manifestPath,
                  depth: 0
                });
              }
            }
          }
        }
      }
    }
    
    return packages;
  } catch (error) {
    log.warn(`Error parsing pip manifest ${manifestPath}`, { error });
    return [];
  }
}

/**
 * Extract packages from Maven pom.xml
 */
function extractMavenPackages(content: string, manifestPath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  
  try {
    // Very simplified XML parsing - in a real implementation, use a proper XML parser
    // Extract dependencies
    const dependencyMatches = content.matchAll(/<dependency>[\s\S]*?<\/dependency>/g);
    
    for (const match of dependencyMatches) {
      const depContent = match[0];
      const groupIdMatch = depContent.match(/<groupId>([^<]+)<\/groupId>/);
      const artifactIdMatch = depContent.match(/<artifactId>([^<]+)<\/artifactId>/);
      const versionMatch = depContent.match(/<version>([^<]+)<\/version>/);
      const scopeMatch = depContent.match(/<scope>([^<]+)<\/scope>/);
      
      if (groupIdMatch && artifactIdMatch) {
        const groupId = groupIdMatch[1];
        const artifactId = artifactIdMatch[1];
        const version = versionMatch ? versionMatch[1] : 'latest';
        const scope = scopeMatch ? scopeMatch[1] : 'compile';
        
        packages.push({
          name: `${groupId}:${artifactId}`,
          version,
          isDirect: true,
          dependencyType: scope === 'test' ? 'dev' : 'regular',
          packageManager: 'maven',
          sourcePath: manifestPath,
          depth: 0
        });
      }
    }
    
    return packages;
  } catch (error) {
    log.warn(`Error parsing maven manifest ${manifestPath}`, { error });
    return [];
  }
}

/**
 * Extract packages from Gradle build files
 */
function extractGradlePackages(content: string, manifestPath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  
  try {
    // This is a very simplified approach - in a real implementation, use AST parsing
    // Look for common dependency patterns in Gradle files
    
    // Pattern: implementation 'group:artifact:version'
    const singleQuoteDeps = content.matchAll(/\b(implementation|api|testImplementation|compileOnly|runtimeOnly)\s*['"](([^:'"
]+):([^:'"
]+):([^'"
]+))['"] ?/g);
    for (const match of singleQuoteDeps) {
      const scope = match[1];
      const name = `${match[3]}:${match[4]}`;
      const version = match[5];
      
      packages.push({
        name,
        version,
        isDirect: true,
        dependencyType: scope.includes('test') ? 'dev' : 'regular',
        packageManager: 'gradle',
        sourcePath: manifestPath,
        depth: 0
      });
    }
    
    // Pattern: implementation(group: "group", name: "artifact", version: "version")
    const methodDeps = content.matchAll(/\b(implementation|api|testImplementation|compileOnly|runtimeOnly)\s*\(\s*(?:group|project):\s*['"]([^'"
]+)['"]\s*,\s*(?:name|module):\s*['"]([^'"
]+)['"]\s*(?:,\s*version:\s*['"]([^'"
]+)['"])?\s*\)/g);
    for (const match of methodDeps) {
      const scope = match[1];
      const groupId = match[2];
      const artifactId = match[3];
      const version = match[4] || 'latest';
      
      packages.push({
        name: `${groupId}:${artifactId}`,
        version,
        isDirect: true,
        dependencyType: scope.includes('test') ? 'dev' : 'regular',
        packageManager: 'gradle',
        sourcePath: manifestPath,
        depth: 0
      });
    }
    
    return packages;
  } catch (error) {
    log.warn(`Error parsing gradle manifest ${manifestPath}`, { error });
    return [];
  }
}

/**
 * Extract packages from NuGet configuration
 */
function extractNugetPackages(content: string, manifestPath: string): PackageInfo[] {
  const packages: PackageInfo[] = [];
  const filename = path.basename(manifestPath).toLowerCase();
  
  try {
    if (filename === 'packages.config') {
      // Extract packages from packages.config
      const packageMatches = content.matchAll(/<package\s+id="([^"]+)"\s+version="([^"]+)"[^>]*\/>/g);
      
      for (const match of packageMatches) {
        const id = match[1];
        const version = match[2];
        
        packages.push({
          name: id,
          version,
          isDirect: true,
          packageManager: 'nuget',
          sourcePath: manifestPath,
          depth: 0
        });
      }
    } else if (filename.endsWith('.csproj')) {
      // Extract packages from .csproj file
      const packageRefMatches = content.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"[^>]*\/>/g);
      
      for (const match of packageRefMatches) {
        const id = match[1];
        const version = match[2];
        
        packages.push({
          name: id,
          version,
          isDirect: true,
          packageManager: 'nuget',
          sourcePath: manifestPath,
          depth: 0
        });
      }
    }
    
    return packages;
  } catch (error) {
    log.warn(`Error parsing nuget manifest ${manifestPath}`, { error });
    return [];
  }
}

/**
 * Check a package against registries and vulnerability databases
 */
async function checkPackage(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<PackageCheckResult> {
  try {
    // Default result
    const result: PackageCheckResult = {
      isOutdated: false,
      isVulnerable: false,
      vulnerabilities: [],
      updateImpact: {
        breakingChanges: false,
        estimatedEffort: 'low'
      }
    };
    
    // Check if package is outdated
    const latestVersionInfo = await getLatestVersion(pkg, config);
    if (latestVersionInfo.isOutdated) {
      result.isOutdated = true;
      result.latestVersion = latestVersionInfo.latestVersion;
    }
    
    // Check for vulnerabilities if configured
    if (config.checkVulnerabilities) {
      const vulnerabilityInfo = await checkVulnerabilities(pkg, config);
      
      if (vulnerabilityInfo.length > 0) {
        result.isVulnerable = true;
        result.vulnerabilities = vulnerabilityInfo;
      }
    }
    
    // Assess update impact if needed and outdated
    if ((result.isOutdated || result.isVulnerable) && config.assessUpdateImpact) {
      result.updateImpact = await assessUpdateImpact(pkg, result.latestVersion, result.vulnerabilities);
    }
    
    return result;
  } catch (checkError) {
    log.warn(`Error checking package ${pkg.name}@${pkg.version}`, { error: checkError });
    
    return {
      isOutdated: false,
      isVulnerable: false,
      vulnerabilities: [],
      updateImpact: {
        breakingChanges: false,
        estimatedEffort: 'low'
      }
    };
  }
}

/**
 * Get the latest version of a package
 */
async function getLatestVersion(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  try {
    switch (pkg.packageManager) {
      case 'npm':
        return await getNpmLatestVersion(pkg, config);
      case 'pip':
        return await getPipLatestVersion(pkg, config);
      case 'maven':
        return await getMavenLatestVersion(pkg, config);
      case 'gradle':
        return await getGradleLatestVersion(pkg, config);
      case 'nuget':
        return await getNugetLatestVersion(pkg, config);
      default:
        return { isOutdated: false };
    }
  } catch (error) {
    log.warn(`Error fetching latest version for ${pkg.name}`, { error });
    return { isOutdated: false };
  }
}

/**
 * Get the latest version of an npm package
 */
async function getNpmLatestVersion(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  try {
    // Use registry URL from config if provided
    const registryUrl = config.registryUrls?.npm || 'https://registry.npmjs.org';
    
    // Use npm view to get package info
    const cmd = `npm view ${pkg.name} version --json --registry=${registryUrl}`;
    const { stdout } = await execAsync(cmd);
    
    let latestVersion;
    try {
      // Handle possible array or string response
      const versionData = JSON.parse(stdout.trim());
      latestVersion = Array.isArray(versionData) ? versionData[versionData.length - 1] : versionData;
    } catch {
      // If parsing fails, use the raw output
      latestVersion = stdout.trim();
    }
    
    // Compare versions (simplified version comparison)
    if (latestVersion && pkg.version !== 'unknown' && pkg.version !== latestVersion) {
      return { isOutdated: true, latestVersion };
    }
    
    return { isOutdated: false, latestVersion };
  } catch (error) {
    log.warn(`Error fetching npm version for ${pkg.name}`, { error });
    return { isOutdated: false };
  }
}

/**
 * Get the latest version of a pip package
 */
async function getPipLatestVersion(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  try {
    // Use pip index to get package info
    const cmd = `pip index versions ${pkg.name} --json`;
    const { stdout } = await execAsync(cmd);
    
    try {
      const result = JSON.parse(stdout.trim());
      
      if (result.versions && result.versions.length > 0) {
        const latestVersion = result.versions[0];
        
        if (pkg.version !== 'unknown' && pkg.version !== 'latest' && pkg.version !== latestVersion) {
          return { isOutdated: true, latestVersion };
        }
        
        return { isOutdated: false, latestVersion };
      }
    } catch (parseError) {
      // If JSON parsing fails, try alternative approach with pip search
      log.warn(`Error parsing pip JSON output for ${pkg.name}`, { error: parseError });
    }
    
    // Fallback method: try to extract from PyPI API
    try {
      const apiUrl = config.registryUrls?.pip || 'https://pypi.org/pypi';
      const cmd = `curl -s ${apiUrl}/${pkg.name}/json`;
      const { stdout } = await execAsync(cmd);
      const result = JSON.parse(stdout.trim());
      
      if (result.info && result.info.version) {
        const latestVersion = result.info.version;
        
        if (pkg.version !== 'unknown' && pkg.version !== 'latest' && pkg.version !== latestVersion) {
          return { isOutdated: true, latestVersion };
        }
        
        return { isOutdated: false, latestVersion };
      }
    } catch (apiError) {
      log.warn(`Error using PyPI API for ${pkg.name}`, { error: apiError });
    }
    
    return { isOutdated: false };
  } catch (error) {
    log.warn(`Error fetching pip version for ${pkg.name}`, { error });
    return { isOutdated: false };
  }
}

/**
 * Get the latest version of a Maven package
 */
async function getMavenLatestVersion(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  try {
    // Split the name into groupId and artifactId
    const [groupId, artifactId] = pkg.name.split(':');
    
    if (!groupId || !artifactId) {
      return { isOutdated: false };
    }
    
    // Use Maven Central API or configured registry
    const mavenRepo = config.registryUrls?.maven || 'https://search.maven.org/solrsearch/select';
    const query = `g:"${groupId}" AND a:"${artifactId}"`;
    const cmd = `curl -s "${mavenRepo}?q=${encodeURIComponent(query)}&rows=1&wt=json"`;
    
    const { stdout } = await execAsync(cmd);
    const result = JSON.parse(stdout.trim());
    
    if (result.response && result.response.docs && result.response.docs.length > 0) {
      const latestVersion = result.response.docs[0].latestVersion;
      
      if (pkg.version !== 'unknown' && pkg.version !== 'latest' && pkg.version !== latestVersion) {
        return { isOutdated: true, latestVersion };
      }
      
      return { isOutdated: false, latestVersion };
    }
    
    return { isOutdated: false };
  } catch (error) {
    log.warn(`Error fetching maven version for ${pkg.name}`, { error });
    return { isOutdated: false };
  }
}

/**
 * Get the latest version of a Gradle package
 * (Typically uses the same Maven repositories as Maven)
 */
async function getGradleLatestVersion(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  // Gradle uses Maven repositories, so we can reuse the Maven approach
  return getMavenLatestVersion(pkg, config);
}

/**
 * Get the latest version of a NuGet package
 */
async function getNugetLatestVersion(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<{ isOutdated: boolean; latestVersion?: string }> {
  try {
    // Use NuGet API
    const nugetRepo = config.registryUrls?.nuget || 'https://api.nuget.org/v3';
    const cmd = `curl -s "${nugetRepo}/registration5-semver1/${pkg.name.toLowerCase()}/index.json"`;
    
    const { stdout } = await execAsync(cmd);
    const result = JSON.parse(stdout.trim());
    
    if (result.items && result.items.length > 0) {
      // Find the latest stable version
      let latestVersion = null;
      
      // Look for the latest non-prerelease version
      for (const item of result.items) {
        if (item.items && item.items.length > 0) {
          for (const version of item.items) {
            if (version.catalogEntry && !version.catalogEntry.version.includes('-')) {
              // Found a stable version (no hyphen indicating prerelease)
              if (!latestVersion || version.catalogEntry.version > latestVersion) {
                latestVersion = version.catalogEntry.version;
              }
            }
          }
        }
      }
      
      if (latestVersion && pkg.version !== 'unknown' && pkg.version !== latestVersion) {
        return { isOutdated: true, latestVersion };
      }
      
      return { isOutdated: false, latestVersion: latestVersion || undefined };
    }
    
    return { isOutdated: false };
  } catch (error) {
    log.warn(`Error fetching nuget version for ${pkg.name}`, { error });
    return { isOutdated: false };
  }
}

/**
 * Check for vulnerabilities in a package
 */
async function checkVulnerabilities(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<VulnerabilityInfo[]> {
  try {
    switch (pkg.packageManager) {
      case 'npm':
        return await checkNpmVulnerabilities(pkg, config);
      case 'pip':
        return await checkPipVulnerabilities(pkg, config);
      case 'maven':
      case 'gradle':
        return await checkMavenVulnerabilities(pkg, config);
      case 'nuget':
        return await checkNugetVulnerabilities(pkg, config);
      default:
        return [];
    }
  } catch (error) {
    log.warn(`Error checking vulnerabilities for ${pkg.name}`, { error });
    return [];
  }
}

/**
 * Check for vulnerabilities in an npm package
 */
async function checkNpmVulnerabilities(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<VulnerabilityInfo[]> {
  try {
    // Use npm audit to check for vulnerabilities
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dependency-scanner-'));
    const packageJsonPath = path.join(tempDir, 'package.json');
    
    // Create a minimal package.json with the dependency
    const packageJson = {
      name: 'vulnerability-check',
      version: '1.0.0',
      dependencies: {
        [pkg.name]: pkg.version
      }
    };
    
    fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));
    
    // Run npm audit
    const cmd = `cd ${tempDir} && npm audit --json`;
    const { stdout } = await execAsync(cmd);
    
    // Clean up temp directory
    fs.rmSync(tempDir, { recursive: true, force: true });
    
    // Parse audit results
    const auditResult = JSON.parse(stdout);
    const vulnerabilities: VulnerabilityInfo[] = [];
    
    if (auditResult.vulnerabilities && auditResult.vulnerabilities[pkg.name]) {
      const vulnInfo = auditResult.vulnerabilities[pkg.name];
      
      // Map npm severity levels to our severity levels
      const severityMap: Record<string, 'low' | 'medium' | 'high' | 'critical'> = {
        'low': 'low',
        'moderate': 'medium',
        'high': 'high',
        'critical': 'critical',
        'info': 'low'
      };
      
      for (const vuln of vulnInfo.via) {
        if (typeof vuln === 'object') {
          const vulnerability: VulnerabilityInfo = {
            severity: severityMap[vuln.severity] || 'medium',
            description: vuln.title || 'Vulnerability found by npm audit',
            fixedInVersion: vuln.range ? vuln.range.replace(/[<>=~^]/g, '') : undefined,
            url: vuln.url,
            cveIds: vuln.cve ? [vuln.cve] : undefined
          };
          
          vulnerabilities.push(vulnerability);
        }
      }
    }
    
    return vulnerabilities;
  } catch (error) {
    // Log but don't fail the process
    log.warn(`Error checking npm vulnerabilities for ${pkg.name}`, { error });
    return [];
  }
}

/**
 * Check for vulnerabilities in a pip package
 */
async function checkPipVulnerabilities(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<VulnerabilityInfo[]> {
  try {
    // Use Safety DB (https://github.com/pyupio/safety-db) or similar source
    // For this example, we'll use a simplified approach with the safety tool if available
    
    // Create a temporary file with the package and version
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dependency-scanner-'));
    const requirementsPath = path.join(tempDir, 'requirements.txt');
    
    fs.writeFileSync(requirementsPath, `${pkg.name}==${pkg.version}\n`);
    
    // Check if safety is installed
    try {
      await execAsync('safety --version');
      
      // Run safety check
      const cmd = `safety check -r ${requirementsPath} --json`;
      const { stdout } = await execAsync(cmd);
      
      // Parse safety results
      const safetyResult = JSON.parse(stdout);
      const vulnerabilities: VulnerabilityInfo[] = [];
      
      for (const vuln of safetyResult.vulnerabilities) {
        if (vuln.package_name.toLowerCase() === pkg.name.toLowerCase()) {
          // Map PIP severity levels (if available) to our severity levels
          let severity: 'low' | 'medium' | 'high' | 'critical' = 'medium';
          
          // Some safety DB entries have severity info
          if (vuln.severity) {
            if (vuln.severity >= 8) severity = 'critical';
            else if (vuln.severity >= 6) severity = 'high';
            else if (vuln.severity >= 4) severity = 'medium';
            else severity = 'low';
          }
          
          const vulnerability: VulnerabilityInfo = {
            severity,
            description: vuln.advisory || 'Vulnerability found by safety check',
            fixedInVersion: vuln.fixed_version || undefined,
            url: vuln.more_info_url || undefined,
            cveIds: vuln.cve ? [vuln.cve] : undefined
          };
          
          vulnerabilities.push(vulnerability);
        }
      }
      
      // Clean up temp directory
      fs.rmSync(tempDir, { recursive: true, force: true });
      
      return vulnerabilities;
    } catch (safetyError) {
      // Safety not installed or failed, try using custom vulnerability DB if available
      if (config.vulnerabilityDbPaths?.pip) {
        try {
          const vulnDb = JSON.parse(fs.readFileSync(config.vulnerabilityDbPaths.pip, 'utf8'));
          
          // Format will depend on your custom DB structure
          // This is just an example assuming a simple format
          const vulnerabilities: VulnerabilityInfo[] = [];
          
          if (vulnDb[pkg.name]) {
            const pkgVulns = vulnDb[pkg.name];
            
            for (const vuln of pkgVulns) {
              if (isVersionAffected(pkg.version, vuln.affected_versions)) {
                vulnerabilities.push({
                  severity: vuln.severity || 'medium',
                  description: vuln.description || 'Vulnerability in package',
                  fixedInVersion: vuln.fixed_version,
                  url: vuln.url,
                  cveIds: vuln.cve_ids
                });
              }
            }
          }
          
          return vulnerabilities;
        } catch (dbError) {
          log.warn(`Error reading custom vulnerability DB for pip`, { error: dbError });
        }
      }
      
      // If all else fails, return empty array
      return [];
    }
  } catch (error) {
    log.warn(`Error checking pip vulnerabilities for ${pkg.name}`, { error });
    return [];
  }
}

/**
 * Check for vulnerabilities in a Maven or Gradle package
 */
async function checkMavenVulnerabilities(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<VulnerabilityInfo[]> {
  try {
    // Split the name into groupId and artifactId
    const [groupId, artifactId] = pkg.name.split(':');
    
    if (!groupId || !artifactId) {
      return [];
    }
    
    // Use OSS Index API for vulnerability information
    const ossIndexUrl = 'https://ossindex.sonatype.org/api/v3/component-report';
    const coordinates = `pkg:maven/${groupId}/${artifactId}@${pkg.version}`;
    
    const cmd = `curl -s -X POST ${ossIndexUrl} -H "Content-Type: application/json" -d '{"coordinates":["${coordinates}"]}'`;
    const { stdout } = await execAsync(cmd);
    
    const ossResult = JSON.parse(stdout);
    const vulnerabilities: VulnerabilityInfo[] = [];
    
    if (ossResult && Array.isArray(ossResult)) {
      for (const component of ossResult) {
        if (component.coordinates === coordinates && component.vulnerabilities) {
          for (const vuln of component.vulnerabilities) {
            // Map OSS Index severity to our levels
            let severity: 'low' | 'medium' | 'high' | 'critical' = 'medium';
            
            if (vuln.cvssScore !== undefined) {
              const score = parseFloat(vuln.cvssScore);
              if (score >= 9.0) severity = 'critical';
              else if (score >= 7.0) severity = 'high';
              else if (score >= 4.0) severity = 'medium';
              else severity = 'low';
            }
            
            const vulnerability: VulnerabilityInfo = {
              severity,
              description: vuln.title || vuln.description || 'Vulnerability found in package',
              url: vuln.reference,
              cveIds: vuln.cve ? [vuln.cve] : undefined
            };
            
            vulnerabilities.push(vulnerability);
          }
        }
      }
    }
    
    return vulnerabilities;
  } catch (error) {
    log.warn(`Error checking Maven/Gradle vulnerabilities for ${pkg.name}`, { error });
    return [];
  }
}

/**
 * Check for vulnerabilities in a NuGet package
 */
async function checkNugetVulnerabilities(
  pkg: PackageInfo,
  config: DependencyScannerConfig
): Promise<VulnerabilityInfo[]> {
  try {
    // Use the OSV API to check for vulnerabilities
    const osvUrl = 'https://api.osv.dev/v1/query';
    const postData = {
      package: {
        name: pkg.name,
        ecosystem: 'NuGet',
        version: pkg.version
      }
    };
    
    const cmd = `curl -s -X POST ${osvUrl} -H "Content-Type: application/json" -d '${JSON.stringify(postData)}'`;
    const { stdout } = await execAsync(cmd);
    
    const osvResult = JSON.parse(stdout);
    const vulnerabilities: VulnerabilityInfo[] = [];
    
    if (osvResult.vulns && Array.isArray(osvResult.vulns)) {
      for (const vuln of osvResult.vulns) {
        // OSV doesn't provide severity, so we'll estimate based on how it's described
        let severity: 'low' | 'medium' | 'high' | 'critical' = 'medium';
        
        // Heuristic based on keywords in the description
        const desc = vuln.summary || '';
        if (desc.toLowerCase().includes('critical') || desc.toLowerCase().includes('remote code execution')) {
          severity = 'critical';
        } else if (desc.toLowerCase().includes('high impact') || desc.toLowerCase().includes('arbitrary code')) {
          severity = 'high';
        } else if (desc.toLowerCase().includes('low impact') || desc.toLowerCase().includes('minor')) {
          severity = 'low';
        }
        
        const vulnerability: VulnerabilityInfo = {
          severity,
          description: vuln.summary || 'Vulnerability found in package',
          url: vuln.references && vuln.references.length > 0 ? vuln.references[0].url : undefined,
          cveIds: vuln.aliases?.filter((alias: string) => alias.startsWith('CVE-'))
        };
        
        // If fixed versions are specified
        if (vuln.affected && vuln.affected.ranges) {
          const fixedVersions = [];
          
          for (const range of vuln.affected.ranges) {
            if (range.type === 'SEMVER' && range.events) {
              for (const event of range.events) {
                if (event.fixed) {
                  fixedVersions.push(event.fixed);
                }
              }
            }
          }
          
          if (fixedVersions.length > 0) {
            vulnerability.fixedInVersion = fixedVersions.join(', ');
          }
        }
        
        vulnerabilities.push(vulnerability);
      }
    }
    
    return vulnerabilities;
  } catch (error) {
    log.warn(`Error checking NuGet vulnerabilities for ${pkg.name}`, { error });
    return [];
  }
}

/**
 * Assess the impact of updating a package
 */
async function assessUpdateImpact(
  pkg: PackageInfo,
  latestVersion?: string,
  vulnerabilities: VulnerabilityInfo[] = []
): Promise<{
  breakingChanges: boolean;
  affectedComponents?: string[];
  estimatedEffort: 'low' | 'medium' | 'high';
}> {
  // Default assessment
  const assessment = {
    breakingChanges: false,
    estimatedEffort: 'low' as 'low' | 'medium' | 'high'
  };
  
  try {
    if (latestVersion && pkg.version !== 'unknown') {
      // Major version changes often indicate breaking changes
      const currentParts = pkg.version.split('.');
      const latestParts = latestVersion.split('.');
      
      if (currentParts[0] !== latestParts[0]) {
        // Major version bump
        assessment.breakingChanges = true;
        
        // Multiple major versions behind is higher effort
        const majorDiff = parseInt(latestParts[0]) - parseInt(currentParts[0]);
        if (majorDiff >= 2) {
          assessment.estimatedEffort = 'high';
        } else {
          assessment.estimatedEffort = 'medium';
        }
      } else if (currentParts[1] !== latestParts[1]) {
        // Minor version changes might have some breaking changes
        const minorDiff = parseInt(latestParts[1]) - parseInt(currentParts[1]);
        
        if (minorDiff > 5) {
          assessment.estimatedEffort = 'medium';
          assessment.breakingChanges = true;
        }
      }
      
      // If it's a critical library, upgrading may be higher effort
      if (isLikelyCriticalPackage(pkg.name)) {
        if (assessment.estimatedEffort === 'low') {
          assessment.estimatedEffort = 'medium';
        } else if (assessment.estimatedEffort === 'medium') {
          assessment.estimatedEffort = 'high';
        }
      }
      
      // Add affected components if available
      // This would typically require a deeper analysis of the codebase
      // Here we just use a placeholder
      if (assessment.breakingChanges) {
        assessment.affectedComponents = await findAffectedComponents(pkg);
      }
    }
    
    // If there are critical vulnerabilities, that increases the urgency regardless of effort
    if (vulnerabilities.some(v => v.severity === 'critical')) {
      // Don't reduce effort level, but update breaking changes if needed
      assessment.breakingChanges = true;
    }
    
    return assessment;
  } catch (error) {
    log.warn(`Error assessing update impact for ${pkg.name}`, { error });
    return assessment;
  }
}

/**
 * Heuristic to determine if a package is likely critical to the project
 */
function isLikelyCriticalPackage(packageName: string): boolean {
  // Lower-case for case-insensitive comparison
  const name = packageName.toLowerCase();
  
  // Check against a list of common critical packages
  const criticalPatterns = [
    // Core frameworks
    'react', 'angular', 'vue', 'express', 'next', 'nest', 'django', 'spring', 'flask',
    
    // Core libraries
    'redux', 'rxjs', 'axios', 'lodash', 'jquery', 'moment', 'graphql',
    
    // Database
    'mongoose', 'sequelize', 'typeorm', 'prisma', 'knex', 'mongodb', 'mysql', 'postgres', 'sqlite',
    
    // Build & tooling
    'webpack', 'babel', 'typescript', 'eslint', 'jest', 'mocha', 'chai',
    
    // Security
    'auth', 'oauth', 'passport', 'jwt', 'bcrypt', 'crypto'
  ];
  
  // Check if the package name contains any of the critical patterns
  return criticalPatterns.some(pattern => {
    // Match the pattern as a word boundary or with hyphens/dots
    const regex = new RegExp(`(^|[-./])(${pattern})([-./]|$)`, 'i');
    return regex.test(name);
  });
}

/**
 * Find components affected by a package update
 * This would typically involve deeper code analysis
 */
async function findAffectedComponents(pkg: PackageInfo): Promise<string[]> {
  // In a real implementation, this would involve code analysis to find imports
  // of this package and trace usage through the codebase
  
  // For this example, we return the directory containing the manifest file
  const manifestDir = path.dirname(pkg.sourcePath);
  const relativeDir = path.relative(process.cwd(), manifestDir);
  
  return [relativeDir || 'root'];
}

/**
 * Calculate the risk level for a dependency issue
 */
function calculateRiskLevel(
  result: PackageCheckResult
): 'low' | 'medium' | 'high' | 'critical' {
  // Start with low risk
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  // If there are vulnerabilities, base risk on highest severity
  if (result.isVulnerable && result.vulnerabilities.length > 0) {
    for (const vuln of result.vulnerabilities) {
      if (vuln.severity === 'critical') {
        return 'critical'; // Critical vulnerabilities are always critical risk
      } else if (vuln.severity === 'high' && riskLevel !== 'critical') {
        riskLevel = 'high';
      } else if (vuln.severity === 'medium' && riskLevel !== 'critical' && riskLevel !== 'high') {
        riskLevel = 'medium';
      }
    }
  }
  
  // If outdated but no vulnerabilities
  if (result.isOutdated && !result.isVulnerable) {
    // Breaking changes indicate higher risk
    if (result.updateImpact.breakingChanges) {
      if (riskLevel === 'low') riskLevel = 'medium';
    }
  }
  
  // If both outdated and vulnerable, increase risk level
  if (result.isOutdated && result.isVulnerable) {
    if (riskLevel === 'medium') riskLevel = 'high';
    else if (riskLevel === 'low') riskLevel = 'medium';
  }
  
  return riskLevel;
}

/**
 * Generate tags for a dependency issue
 */
function generateTags(
  pkg: PackageInfo,
  result: PackageCheckResult
): string[] {
  const tags: string[] = [pkg.packageManager];
  
  // Add status tags
  if (result.isOutdated) {
    tags.push('outdated');
  }
  
  if (result.isVulnerable) {
    tags.push('vulnerable');
    
    // Add vulnerability severity tags
    const severities = new Set<string>();
    for (const vuln of result.vulnerabilities) {
      severities.add(`${vuln.severity}-severity`);
    }
    tags.push(...severities);
  }
  
  // Add dependency type
  if (pkg.dependencyType) {
    tags.push(`${pkg.dependencyType}-dependency`);
  }
  
  // Direct vs transitive
  tags.push(pkg.isDirect ? 'direct' : 'transitive');
  
  // Add update impact tags
  if (result.updateImpact.breakingChanges) {
    tags.push('breaking-changes');
  }
  
  tags.push(`effort-${result.updateImpact.estimatedEffort}`);
  
  return tags;
}

/**
 * Generate a recommendation for resolving a dependency issue
 */
function generateRecommendation(
  pkg: PackageInfo,
  result: PackageCheckResult
): string {
  const recommendations: string[] = [];
  
  // Handle vulnerable packages with highest priority
  if (result.isVulnerable) {
    recommendations.push(
      `${pkg.name}@${pkg.version} has ${result.vulnerabilities.length} security vulnerabilities.`
    );
    
    // Group vulnerabilities by severity for better readability
    const bySeverity: Record<string, VulnerabilityInfo[]> = {};
    for (const vuln of result.vulnerabilities) {
      if (!bySeverity[vuln.severity]) {
        bySeverity[vuln.severity] = [];
      }
      bySeverity[vuln.severity].push(vuln);
    }
    
    // Report vulnerabilities from highest to lowest severity
    for (const severity of ['critical', 'high', 'medium', 'low']) {
      if (bySeverity[severity] && bySeverity[severity].length > 0) {
        recommendations.push(
          `${bySeverity[severity].length} ${severity} severity issues found:`
        );
        
        // List up to 3 vulnerabilities per severity level
        for (let i = 0; i < Math.min(bySeverity[severity].length, 3); i++) {
          const vuln = bySeverity[severity][i];
          let vulnDesc = `- ${vuln.description}`;
          
          if (vuln.cveIds && vuln.cveIds.length > 0) {
            vulnDesc += ` (${vuln.cveIds.join(', ')})`;
          }
          
          if (vuln.fixedInVersion) {
            vulnDesc += ` - Fixed in version ${vuln.fixedInVersion}`;
          }
          
          recommendations.push(vulnDesc);
        }
        
        // Indicate if there are more
        if (bySeverity[severity].length > 3) {
          recommendations.push(`  ...and ${bySeverity[severity].length - 3} more ${severity} issues`);
        }
      }
    }
    
    // Recommend updating to fix vulnerabilities
    if (result.latestVersion) {
      recommendations.push(
        `Update to version ${result.latestVersion} to resolve these security issues.`
      );
    } else {
      recommendations.push(
        `Update to the latest version to resolve these security issues.`
      );
    }
  }
  // Handle outdated packages
  else if (result.isOutdated && result.latestVersion) {
    recommendations.push(
      `${pkg.name}@${pkg.version} is outdated. Latest version is ${result.latestVersion}.`
    );
    
    // Warn about breaking changes if detected
    if (result.updateImpact.breakingChanges) {
      recommendations.push(
        `⚠️ This update may contain breaking changes. Test thoroughly after updating.`
      );
    }
  }
  
  // Add update complexity information
  if (result.updateImpact.estimatedEffort !== 'low') {
    recommendations.push(
      `Estimated update effort: ${result.updateImpact.estimatedEffort.toUpperCase()}. ` +
      (result.updateImpact.estimatedEffort === 'high' ? 
        'Plan for significant testing and potential refactoring.' : 
        'Allow time for testing and possible code adjustments.')
    );
  }
  
  // If affected components are specified
  if (result.updateImpact.affectedComponents && result.updateImpact.affectedComponents.length > 0) {
    recommendations.push(
      `Components potentially affected by this update: ${result.updateImpact.affectedComponents.join(', ')}`
    );
  }
  
  // If no recommendations were generated
  if (recommendations.length === 0) {
    recommendations.push(
      `Review ${pkg.name}@${pkg.version} for update considerations.`
    );
  }
  
  return recommendations.join('\n');
}

/**
 * Check if a version is affected by a specified range
 * This is a simplified implementation
 */
function isVersionAffected(version: string, affectedVersions: string): boolean {
  // Very simplified version check - in a real implementation use semver or similar
  return affectedVersions.includes(version) || affectedVersions.includes('*');
}

/**
 * Operating system utilities
 */
import * as os from 'os';