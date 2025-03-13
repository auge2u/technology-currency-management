import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as semver from 'semver';
import { DependencyInfo, DependencyNotification, TechnologyEOL } from '../types/monitoring';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Configuration for dependency monitoring
 */
export interface DependencyMonitorConfig {
  // Source repositories to monitor
  repositories: Array<{
    name: string;
    path: string;
    excludedPackages?: string[];
    criticalPackages?: string[];
  }>;
  
  // Technology types to monitor
  monitorTypes: Array<'npm' | 'pip' | 'java' | 'dotnet' | 'ruby' | 'go' | 'rust' | 'php' | 'databases' | 'frameworks' | 'os'>;
  
  // Notification thresholds in days
  notificationThresholds: {
    endOfLife: number; // Days before EOL to start notifying
    majorUpdate: number; // Days after major update available to notify
    minorUpdate: number; // Days after minor update available to notify
    patchUpdate: number; // Days after patch update available to notify
    securityFix: number; // Days to notify about security fixes (priority)
  };
  
  // Notification targets
  notificationTargets: Array<{
    type: 'email' | 'slack' | 'teams' | 'webhook' | 'jira';
    config: Record<string, string>;
  }>;
  
  // Cache settings
  cacheDir: string;
  cacheTtlMinutes: number;
  
  // API keys for version data providers
  apiKeys?: {
    snyk?: string;
    libraries?: string;
    npms?: string;
    packagist?: string;
    endOfLifeDate?: string;
  };
  
  // Custom EOL data sources 
  customEolDataSources?: Array<{
    name: string;
    url: string;
    mapping: Record<string, string>;
  }>;
  
  // Ignored dependencies
  ignoredDependencies: string[];
  
  // Report settings
  reportDir: string;
  reportFrequency: 'daily' | 'weekly' | 'monthly';
}

/**
 * Check for dependency updates and EOL
 */
export async function monitorDependencies(
  config: DependencyMonitorConfig
): Promise<{
  dependencies: DependencyInfo[];
  notifications: DependencyNotification[];
}> {
  try {
    log.info('Starting dependency monitoring');
    
    const allDependencies: DependencyInfo[] = [];
    const notifications: DependencyNotification[] = [];
    
    // Get EOL dates for technologies
    const eolData = await getEndOfLifeDates(config);
    
    // Scan repositories for dependencies
    for (const repo of config.repositories) {
      log.info(`Scanning repository: ${repo.name}`);
      
      const repoPath = repo.path;
      
      if (!fs.existsSync(repoPath)) {
        log.warn(`Repository path does not exist: ${repoPath}`);
        continue;
      }
      
      // Scan for each type of dependency
      if (config.monitorTypes.includes('npm')) {
        const npmDeps = await scanNpmDependencies(repoPath, repo.excludedPackages || []);
        for (const dep of npmDeps) {
          dep.repository = repo.name;
          dep.critical = (repo.criticalPackages || []).includes(dep.name);
          allDependencies.push(dep);
        }
      }
      
      if (config.monitorTypes.includes('pip')) {
        const pipDeps = await scanPipDependencies(repoPath, repo.excludedPackages || []);
        for (const dep of pipDeps) {
          dep.repository = repo.name;
          dep.critical = (repo.criticalPackages || []).includes(dep.name);
          allDependencies.push(dep);
        }
      }
      
      if (config.monitorTypes.includes('java')) {
        const javaDeps = await scanJavaDependencies(repoPath, repo.excludedPackages || []);
        for (const dep of javaDeps) {
          dep.repository = repo.name;
          dep.critical = (repo.criticalPackages || []).includes(dep.name);
          allDependencies.push(dep);
        }
      }
      
      // Add more dependency types as needed
    }
    
    log.info(`Found ${allDependencies.length} dependencies across all repositories`);
    
    // Check for updates and EOL
    for (const dep of allDependencies) {
      if (config.ignoredDependencies.includes(dep.name)) {
        continue;
      }
      
      // Check for latest version
      const latestVersion = await getLatestVersion(dep.name, dep.type);
      
      if (latestVersion) {
        dep.latestVersion = latestVersion.version;
        dep.releaseDate = latestVersion.releaseDate;
        
        // Check if update is available
        if (semver.valid(dep.version) && semver.valid(latestVersion.version)) {
          const currentVersion = semver.clean(dep.version) || dep.version;
          const newVersion = semver.clean(latestVersion.version) || latestVersion.version;
          
          if (semver.lt(currentVersion, newVersion)) {
            const diff = semver.diff(currentVersion, newVersion);
            const behind = getVersionsBehind(currentVersion, newVersion);
            
            dep.updateAvailable = true;
            dep.updateType = diff || 'patch';
            dep.versionsCount = behind.major + behind.minor + behind.patch;
            dep.versionsOutdated = `${behind.major} major, ${behind.minor} minor, ${behind.patch} patch`;
            
            // Create notification based on version difference
            const notification = createUpdateNotification(dep, config.notificationThresholds);
            if (notification) {
              notifications.push(notification);
            }
          }
        }
      }
      
      // Check for EOL
      const eol = findEOLData(dep, eolData);
      if (eol) {
        dep.endOfLife = eol.date;
        dep.endOfLifeInfo = eol.info;
        
        // Create EOL notification if approaching
        if (eol.date) {
          const eolDate = new Date(eol.date);
          const now = new Date();
          const daysToEol = Math.floor((eolDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
          
          if (daysToEol <= config.notificationThresholds.endOfLife) {
            const notification: DependencyNotification = {
              id: `eol-${dep.type}-${dep.name}-${dep.version}`,
              type: 'end-of-life',
              dependencyName: dep.name,
              dependencyType: dep.type,
              currentVersion: dep.version,
              repository: dep.repository,
              message: `${dep.name} ${dep.version} will reach end-of-life in ${daysToEol} days (${eol.date})`,
              details: eol.info || '',
              severity: daysToEol <= 30 ? 'critical' : 'high',
              actionItems: [
                `Upgrade ${dep.name} to a supported version`,
                `Review migration documentation at ${dep.documentationUrl || 'unavailable'}`
              ],
              created: new Date(),
              due: new Date(eol.date)
            };
            
            notifications.push(notification);
          }
        }
      }
    }
    
    // Send notifications
    if (notifications.length > 0) {
      await sendNotifications(notifications, config.notificationTargets);
    }
    
    // Generate report
    await generateDependencyReport(allDependencies, notifications, config.reportDir);
    
    log.info(`Dependency monitoring completed. Created ${notifications.length} notifications`);
    
    return {
      dependencies: allDependencies,
      notifications
    };
  } catch (error) {
    log.error('Error during dependency monitoring', { error });
    return {
      dependencies: [],
      notifications: []
    };
  }
}

/**
 * Scan NPM dependencies in a repository
 */
async function scanNpmDependencies(
  repoPath: string,
  excludedPackages: string[]
): Promise<DependencyInfo[]> {
  try {
    // Find all package.json files in the repository
    const { stdout } = await execAsync(`find ${repoPath} -name "package.json" -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*"`);
    const packageJsonFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (packageJsonFiles.length === 0) {
      return [];
    }
    
    const dependencies: DependencyInfo[] = [];
    
    for (const filePath of packageJsonFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const packageJson = JSON.parse(content);
        
        // Process regular dependencies
        if (packageJson.dependencies) {
          for (const [name, version] of Object.entries(packageJson.dependencies)) {
            if (typeof version === 'string' && !excludedPackages.includes(name)) {
              const cleanVersion = version.replace(/^[\^~><=]/, '');
              
              dependencies.push({
                name,
                version: cleanVersion,
                type: 'npm',
                path: filePath,
                updateAvailable: false,
                installDate: await getInstallDate(filePath),
                documentationUrl: await getNpmDocumentationUrl(name)
              });
            }
          }
        }
        
        // Process dev dependencies
        if (packageJson.devDependencies) {
          for (const [name, version] of Object.entries(packageJson.devDependencies)) {
            if (typeof version === 'string' && !excludedPackages.includes(name)) {
              const cleanVersion = version.replace(/^[\^~><=]/, '');
              
              dependencies.push({
                name,
                version: cleanVersion,
                type: 'npm',
                path: filePath,
                updateAvailable: false,
                installDate: await getInstallDate(filePath),
                documentationUrl: await getNpmDocumentationUrl(name),
                isDev: true
              });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${filePath}`, { error: fileError });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error('Error scanning NPM dependencies', { error });
    return [];
  }
}

/**
 * Scan Python dependencies in a repository
 */
async function scanPipDependencies(
  repoPath: string,
  excludedPackages: string[]
): Promise<DependencyInfo[]> {
  try {
    // Find all requirements.txt files
    const { stdout } = await execAsync(`find ${repoPath} -name "requirements.txt" -not -path "*/venv/*" -not -path "*/.env/*"`);
    const requirementsFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (requirementsFiles.length === 0) {
      return [];
    }
    
    const dependencies: DependencyInfo[] = [];
    
    for (const filePath of requirementsFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        
        for (const line of lines) {
          // Skip comments and empty lines
          if (line.trim().startsWith('#') || !line.trim()) {
            continue;
          }
          
          // Parse package name and version
          const match = line.match(/^([\w-\.]+)(?:[=<>!~]+([\w\.]+))?/);
          
          if (match) {
            const name = match[1];
            const version = match[2] || 'latest';
            
            if (!excludedPackages.includes(name)) {
              dependencies.push({
                name,
                version,
                type: 'pip',
                path: filePath,
                updateAvailable: false,
                installDate: await getInstallDate(filePath),
                documentationUrl: await getPipDocumentationUrl(name)
              });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${filePath}`, { error: fileError });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error('Error scanning Python dependencies', { error });
    return [];
  }
}

/**
 * Scan Java dependencies in a repository
 */
async function scanJavaDependencies(
  repoPath: string,
  excludedPackages: string[]
): Promise<DependencyInfo[]> {
  try {
    // Find all pom.xml and build.gradle files
    const { stdout: pomFiles } = await execAsync(`find ${repoPath} -name "pom.xml"`);
    const { stdout: gradleFiles } = await execAsync(`find ${repoPath} -name "build.gradle" -o -name "build.gradle.kts"`);
    
    const dependencies: DependencyInfo[] = [];
    
    // Process Maven POM files
    for (const filePath of pomFiles.trim().split('\n').filter(Boolean)) {
      try {
        // Real implementation would use XML parsing
        // This is a simplified placeholder
        const content = fs.readFileSync(filePath, 'utf8');
        const depMatches = content.matchAll(/<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g);
        
        for (const match of depMatches) {
          const groupId = match[1].trim();
          const artifactId = match[2].trim();
          const version = match[3].trim();
          const name = `${groupId}:${artifactId}`;
          
          if (!excludedPackages.includes(name)) {
            dependencies.push({
              name,
              version,
              type: 'maven',
              path: filePath,
              updateAvailable: false,
              installDate: await getInstallDate(filePath),
              documentationUrl: await getMavenDocumentationUrl(groupId, artifactId)
            });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${filePath}`, { error: fileError });
      }
    }
    
    // Process Gradle files - simplified placeholder
    // A real implementation would need more robust parsing
    for (const filePath of gradleFiles.trim().split('\n').filter(Boolean)) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const depMatches = content.matchAll(/implementation\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]|api\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]|compile\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]|implementation\(['"]([^'"]+):([^'"]+):([^'"]+)['"]/g);
        
        for (const match of depMatches) {
          let groupId, artifactId, version;
          
          if (match[1] && match[2] && match[3]) {
            groupId = match[1].trim();
            artifactId = match[2].trim();
            version = match[3].trim();
          } else if (match[4] && match[5] && match[6]) {
            groupId = match[4].trim();
            artifactId = match[5].trim();
            version = match[6].trim();
          } else if (match[7] && match[8] && match[9]) {
            groupId = match[7].trim();
            artifactId = match[8].trim();
            version = match[9].trim();
          } else if (match[10] && match[11] && match[12]) {
            groupId = match[10].trim();
            artifactId = match[11].trim();
            version = match[12].trim();
          } else {
            continue;
          }
          
          const name = `${groupId}:${artifactId}`;
          
          if (!excludedPackages.includes(name)) {
            dependencies.push({
              name,
              version,
              type: 'gradle',
              path: filePath,
              updateAvailable: false,
              installDate: await getInstallDate(filePath),
              documentationUrl: await getMavenDocumentationUrl(groupId, artifactId) // Often the same as maven
            });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${filePath}`, { error: fileError });
      }
    }
    
    return dependencies;
  } catch (error) {
    log.error('Error scanning Java dependencies', { error });
    return [];
  }
}

/**
 * Get file modification date as install date approximation
 */
async function getInstallDate(filePath: string): Promise<Date | undefined> {
  try {
    const stats = fs.statSync(filePath);
    return stats.mtime;
  } catch (error) {
    return undefined;
  }
}

/**
 * Get documentation URL for an NPM package
 */
async function getNpmDocumentationUrl(packageName: string): Promise<string | undefined> {
  try {
    const response = await axios.get(`https://registry.npmjs.org/${packageName}`);
    return response.data.homepage || response.data.repository?.url || undefined;
  } catch (error) {
    return undefined;
  }
}

/**
 * Get documentation URL for a Python package
 */
async function getPipDocumentationUrl(packageName: string): Promise<string | undefined> {
  try {
    const response = await axios.get(`https://pypi.org/pypi/${packageName}/json`);
    return response.data.info.project_urls?.Homepage || response.data.info.project_urls?.Documentation || response.data.info.home_page || undefined;
  } catch (error) {
    return undefined;
  }
}

/**
 * Get documentation URL for a Maven package
 */
async function getMavenDocumentationUrl(groupId: string, artifactId: string): Promise<string | undefined> {
  try {
    return `https://mvnrepository.com/artifact/${groupId}/${artifactId}`;
  } catch (error) {
    return undefined;
  }
}

/**
 * Get latest version information for a package
 */
async function getLatestVersion(
  packageName: string,
  packageType: string
): Promise<{ version: string; releaseDate?: Date } | null> {
  try {
    switch (packageType) {
      case 'npm':
        return await getNpmLatestVersion(packageName);
      case 'pip':
        return await getPipLatestVersion(packageName);
      case 'maven':
      case 'gradle':
        const [groupId, artifactId] = packageName.split(':');
        return await getMavenLatestVersion(groupId, artifactId);
      default:
        return null;
    }
  } catch (error) {
    log.warn(`Error getting latest version for ${packageName}`, { error });
    return null;
  }
}

/**
 * Get latest NPM package version
 */
async function getNpmLatestVersion(packageName: string): Promise<{ version: string; releaseDate?: Date } | null> {
  try {
    const response = await axios.get(`https://registry.npmjs.org/${packageName}`);
    const latestVersion = response.data['dist-tags']?.latest;
    
    if (latestVersion) {
      const versionData = response.data.versions[latestVersion];
      const releaseDate = versionData ? new Date(versionData.time) : undefined;
      
      return {
        version: latestVersion,
        releaseDate
      };
    }
    
    return null;
  } catch (error) {
    log.warn(`Error getting NPM version for ${packageName}`, { error });
    return null;
  }
}

/**
 * Get latest Python package version
 */
async function getPipLatestVersion(packageName: string): Promise<{ version: string; releaseDate?: Date } | null> {
  try {
    const response = await axios.get(`https://pypi.org/pypi/${packageName}/json`);
    
    return {
      version: response.data.info.version,
      releaseDate: response.data.releases[response.data.info.version][0]?.upload_time ? 
                   new Date(response.data.releases[response.data.info.version][0].upload_time) : 
                   undefined
    };
  } catch (error) {
    log.warn(`Error getting Python version for ${packageName}`, { error });
    return null;
  }
}

/**
 * Get latest Maven package version
 */
async function getMavenLatestVersion(groupId: string, artifactId: string): Promise<{ version: string; releaseDate?: Date } | null> {
  try {
    // Using Maven Central API
    const response = await axios.get(
      `https://search.maven.org/solrsearch/select?q=g:"${groupId}"+AND+a:"${artifactId}"&core=gav&rows=1&wt=json`
    );
    
    if (response.data.response.numFound > 0) {
      const doc = response.data.response.docs[0];
      
      return {
        version: doc.v,
        releaseDate: doc.timestamp ? new Date(doc.timestamp) : undefined
      };
    }
    
    return null;
  } catch (error) {
    log.warn(`Error getting Maven version for ${groupId}:${artifactId}`, { error });
    return null;
  }
}

/**
 * Get end-of-life dates for various technologies
 */
async function getEndOfLifeDates(config: DependencyMonitorConfig): Promise<TechnologyEOL[]> {
  try {
    // Use the endoflife.date API if available
    const eolList: TechnologyEOL[] = [];
    
    // Fetch from endoflife.date API
    const baseUrl = 'https://endoflife.date/api';
    
    // Get list of products
    const productResponse = await axios.get(`${baseUrl}/all.json`);
    const products = productResponse.data;
    
    // Fetch details for each relevant product
    for (const product of products) {
      try {
        const productDetailsResponse = await axios.get(`${baseUrl}/${product}.json`);
        const productDetails = productDetailsResponse.data;
        
        if (Array.isArray(productDetails)) {
          for (const release of productDetails) {
            if (release.cycle && release.eol) {
              eolList.push({
                name: product,
                version: release.cycle,
                date: release.eol === true ? 'EOL' : release.eol,
                info: `${product} ${release.cycle} ${release.eol === true ? 'has reached EOL' : `reaches EOL on ${release.eol}`}`,
                latestVersion: release.latest || undefined,
                lts: release.lts || undefined,
                support: release.support || undefined
              });
            }
          }
        }
      } catch (productError) {
        log.warn(`Error fetching EOL data for ${product}`, { error: productError });
      }
    }
    
    // Add custom framework and database EOL data
    const frameworkEol = getFrameworkEOLData();
    eolList.push(...frameworkEol);
    
    return eolList;
  } catch (error) {
    log.error('Error getting end-of-life dates', { error });
    return [];
  }
}

/**
 * Get EOL data for major frameworks
 */
function getFrameworkEOLData(): TechnologyEOL[] {
  return [
    {
      name: 'angular',
      version: '11.x',
      date: '2022-05-11',
      info: 'Angular 11.x reached EOL on May 11, 2022',
      latestVersion: '16.x'
    },
    {
      name: 'react',
      version: '16.x',
      date: '2023-06-15', // Placeholder
      info: 'React 16.x is no longer actively maintained',
      latestVersion: '18.x'
    },
    {
      name: 'vue',
      version: '2.x',
      date: '2023-12-31', // Placeholder
      info: 'Vue 2.x support ends December 31, 2023',
      latestVersion: '3.x'
    },
    {
      name: 'laravel',
      version: '8.x',
      date: '2023-01-24',
      info: 'Laravel 8.x reached EOL on January 24, 2023',
      latestVersion: '10.x'
    },
    {
      name: 'django',
      version: '3.2',
      date: '2024-04-01',
      info: 'Django 3.2 LTS support ends April 2024',
      latestVersion: '4.2'
    },
    // Database examples
    {
      name: 'mongodb',
      version: '4.4',
      date: '2024-02-01',
      info: 'MongoDB 4.4 support ends February 2024',
      latestVersion: '6.0'
    },
    {
      name: 'mysql',
      version: '5.7',
      date: '2023-10-31',
      info: 'MySQL 5.7 extended support ends October 2023',
      latestVersion: '8.0'
    },
    // OS examples
    {
      name: 'ubuntu',
      version: '20.04',
      date: '2025-04-30',
      info: 'Ubuntu 20.04 LTS support ends April 2025',
      latestVersion: '22.04'
    },
    {
      name: 'centos',
      version: '8',
      date: '2021-12-31',
      info: 'CentOS 8 reached EOL on December 31, 2021',
      latestVersion: 'Stream 9'
    }
  ];
}

/**
 * Find EOL data for a dependency
 */
function findEOLData(dependency: DependencyInfo, eolData: TechnologyEOL[]): TechnologyEOL | null {
  try {
    let matches: TechnologyEOL[] = [];
    
    // Try exact name match
    matches = eolData.filter(eol => eol.name.toLowerCase() === dependency.name.toLowerCase());
    
    if (matches.length === 0) {
      // Try partial name match for frameworks and databases
      matches = eolData.filter(eol => dependency.name.toLowerCase().includes(eol.name.toLowerCase()));
    }
    
    if (matches.length === 0) {
      return null;
    }
    
    // Find best version match
    for (const match of matches) {
      // If version contains wildcard (e.g., 2.x)
      if (match.version.includes('x') || match.version.includes('*')) {
        const matchPrefix = match.version.replace('.x', '').replace('.*', '');
        const depPrefix = dependency.version.split('.')[0];
        
        if (matchPrefix === depPrefix) {
          return match;
        }
      } else if (match.version === dependency.version) {
        // Exact version match
        return match;
      } else if (semver.valid(dependency.version) && semver.valid(match.version)) {
        // Compare major.minor versions
        const depParts = semver.major(dependency.version) + '.' + semver.minor(dependency.version);
        const matchParts = semver.major(match.version) + '.' + semver.minor(match.version);
        
        if (depParts === matchParts) {
          return match;
        }
      }
    }
    
    // If no version match but we have an entry for the dependency, 
    // return the oldest EOL entry as a warning
    matches.sort((a, b) => {
      if (a.date === 'EOL') return -1;
      if (b.date === 'EOL') return 1;
      return new Date(a.date).getTime() - new Date(b.date).getTime();
    });
    
    return matches[0];
  } catch (error) {
    log.warn(`Error finding EOL data for ${dependency.name}`, { error });
    return null;
  }
}

/**
 * Calculate how many versions behind a dependency is
 */
function getVersionsBehind(current: string, latest: string): { major: number; minor: number; patch: number } {
  try {
    if (!semver.valid(current) || !semver.valid(latest)) {
      return { major: 0, minor: 0, patch: 0 };
    }
    
    const currentParts = {
      major: semver.major(current),
      minor: semver.minor(current),
      patch: semver.patch(current)
    };
    
    const latestParts = {
      major: semver.major(latest),
      minor: semver.minor(latest),
      patch: semver.patch(latest)
    };
    
    return {
      major: Math.max(0, latestParts.major - currentParts.major),
      minor: currentParts.major === latestParts.major ? 
             Math.max(0, latestParts.minor - currentParts.minor) : 0,
      patch: currentParts.major === latestParts.major && 
             currentParts.minor === latestParts.minor ? 
             Math.max(0, latestParts.patch - currentParts.patch) : 0
    };
  } catch (error) {
    return { major: 0, minor: 0, patch: 0 };
  }
}

/**
 * Create notification for outdated dependency
 */
function createUpdateNotification(
  dependency: DependencyInfo,
  thresholds: DependencyMonitorConfig['notificationThresholds']
): DependencyNotification | null {
  try {
    if (!dependency.updateAvailable || !dependency.latestVersion) {
      return null;
    }
    
    let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
    let daysOld = 0;
    
    // Calculate how long the update has been available
    if (dependency.releaseDate) {
      const now = new Date();
      daysOld = Math.floor((now.getTime() - dependency.releaseDate.getTime()) / (1000 * 60 * 60 * 24));
    }
    
    // Determine severity based on update type and time elapsed
    switch (dependency.updateType) {
      case 'major':
        severity = daysOld >= thresholds.majorUpdate ? 'high' : 'medium';
        if (dependency.critical) {
          severity = 'critical';
        }
        break;
      case 'minor':
        severity = daysOld >= thresholds.minorUpdate ? 'medium' : 'low';
        if (dependency.critical) {
          severity = 'high';
        }
        break;
      case 'patch':
        severity = daysOld >= thresholds.patchUpdate ? 'low' : 'low';
        if (dependency.critical) {
          severity = 'medium';
        }
        break;
    }
    
    // Create notification
    const notification: DependencyNotification = {
      id: `update-${dependency.type}-${dependency.name}-${dependency.version}`,
      type: 'update-available',
      dependencyName: dependency.name,
      dependencyType: dependency.type,
      currentVersion: dependency.version,
      newVersion: dependency.latestVersion,
      updateType: dependency.updateType,
      repository: dependency.repository,
      message: `Update available for ${dependency.name}: ${dependency.version} → ${dependency.latestVersion} (${dependency.updateType} update)`,
      details: dependency.versionsOutdated || '',
      severity,
      actionItems: [
        `Update ${dependency.name} to version ${dependency.latestVersion}`,
        `Review changelog at ${dependency.documentationUrl || 'unavailable'}`
      ],
      created: new Date(),
      due: new Date(new Date().getTime() + (30 * 24 * 60 * 60 * 1000)) // 30 days from now
    };
    
    return notification;
  } catch (error) {
    log.warn(`Error creating update notification for ${dependency.name}`, { error });
    return null;
  }
}

/**
 * Send notifications to configured targets
 */
async function sendNotifications(
  notifications: DependencyNotification[],
  targets: DependencyMonitorConfig['notificationTargets']
): Promise<void> {
  try {
    log.info(`Sending ${notifications.length} notifications to ${targets.length} targets`);
    
    for (const target of targets) {
      try {
        switch (target.type) {
          case 'email':
            await sendEmailNotifications(notifications, target.config);
            break;
          case 'slack':
            await sendSlackNotifications(notifications, target.config);
            break;
          case 'teams':
            await sendTeamsNotifications(notifications, target.config);
            break;
          case 'webhook':
            await sendWebhookNotifications(notifications, target.config);
            break;
          case 'jira':
            await createJiraIssues(notifications, target.config);
            break;
        }
      } catch (targetError) {
        log.error(`Error sending notifications to ${target.type}`, { error: targetError });
      }
    }
  } catch (error) {
    log.error('Error sending notifications', { error });
  }
}

/**
 * Send email notifications
 */
async function sendEmailNotifications(
  notifications: DependencyNotification[],
  config: Record<string, string>
): Promise<void> {
  // Implementation would use a library like nodemailer
  log.info(`Would send ${notifications.length} email notifications to ${config.recipients}`);
}

/**
 * Send Slack notifications
 */
async function sendSlackNotifications(
  notifications: DependencyNotification[],
  config: Record<string, string>
): Promise<void> {
  // Implementation would use Slack API
  log.info(`Would send ${notifications.length} Slack notifications to ${config.channel}`);
}

/**
 * Send Microsoft Teams notifications
 */
async function sendTeamsNotifications(
  notifications: DependencyNotification[],
  config: Record<string, string>
): Promise<void> {
  // Implementation would use Microsoft Teams webhook
  log.info(`Would send ${notifications.length} Teams notifications to webhook`);
}

/**
 * Send generic webhook notifications
 */
async function sendWebhookNotifications(
  notifications: DependencyNotification[],
  config: Record<string, string>
): Promise<void> {
  // Implementation would use axios to post to webhook
  log.info(`Would send ${notifications.length} webhook notifications to ${config.url}`);
}

/**
 * Create Jira issues for notifications
 */
async function createJiraIssues(
  notifications: DependencyNotification[],
  config: Record<string, string>
): Promise<void> {
  // Implementation would use Jira API
  log.info(`Would create ${notifications.length} Jira issues in project ${config.project}`);
}

/**
 * Generate dependency report
 */
async function generateDependencyReport(
  dependencies: DependencyInfo[],
  notifications: DependencyNotification[],
  reportDir: string
): Promise<void> {
  try {
    // Ensure report directory exists
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    
    const now = new Date();
    const dateStr = now.toISOString().split('T')[0];
    const reportPath = path.join(reportDir, `dependency-report-${dateStr}.json`);
    
    // Generate summary statistics
    const totalDeps = dependencies.length;
    const outdatedDeps = dependencies.filter(d => d.updateAvailable).length;
    const criticalUpdates = notifications.filter(n => n.severity === 'critical').length;
    const highUpdates = notifications.filter(n => n.severity === 'high').length;
    const eolNotifications = notifications.filter(n => n.type === 'end-of-life').length;
    
    const report = {
      generatedAt: now,
      summary: {
        totalDependencies: totalDeps,
        outdatedDependencies: outdatedDeps,
        outdatedPercentage: totalDeps > 0 ? Math.round((outdatedDeps / totalDeps) * 100) : 0,
        criticalUpdates,
        highUpdates,
        endOfLifeNotifications: eolNotifications
      },
      notifications: notifications.map(n => ({
        ...n,
        created: n.created.toISOString(),
        due: n.due?.toISOString()
      })),
      dependencies: dependencies.map(d => ({
        ...d,
        installDate: d.installDate?.toISOString(),
        releaseDate: d.releaseDate?.toISOString(),
        endOfLife: d.endOfLife
      }))
    };
    
    // Write report to file
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    // Generate HTML report for better readability
    const htmlReportPath = path.join(reportDir, `dependency-report-${dateStr}.html`);
    const htmlReport = generateHtmlReport(report);
    fs.writeFileSync(htmlReportPath, htmlReport);
    
    log.info(`Dependency report generated at ${reportPath} and ${htmlReportPath}`);
  } catch (error) {
    log.error('Error generating dependency report', { error });
  }
}

/**
 * Generate HTML report from report data
 */
function generateHtmlReport(report: any): string {
  // This would be a more elaborate HTML template
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Dependency Report - ${report.generatedAt}</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        h1 { color: #2c3e50; }
        .summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .stat { margin-bottom: 10px; }
        .notifications { margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .critical { background-color: #ffdddd; }
        .high { background-color: #ffffcc; }
        .medium { background-color: #e7f5fe; }
        .low { background-color: #f0fff0; }
      </style>
    </head>
    <body>
      <h1>Dependency Report</h1>
      <p>Generated on ${new Date(report.generatedAt).toLocaleString()}</p>
      
      <div class="summary">
        <h2>Summary</h2>
        <div class="stat">Total Dependencies: ${report.summary.totalDependencies}</div>
        <div class="stat">Outdated Dependencies: ${report.summary.outdatedDependencies} (${report.summary.outdatedPercentage}%)</div>
        <div class="stat">Critical Updates Required: ${report.summary.criticalUpdates}</div>
        <div class="stat">High Priority Updates: ${report.summary.highUpdates}</div>
        <div class="stat">End-of-Life Components: ${report.summary.endOfLifeNotifications}</div>
      </div>
      
      <div class="notifications">
        <h2>Notifications</h2>
        <table>
          <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>Dependency</th>
            <th>Message</th>
            <th>Due Date</th>
          </tr>
          ${report.notifications.map((n: any) => `
            <tr class="${n.severity}">
              <td>${n.severity.toUpperCase()}</td>
              <td>${n.type}</td>
              <td>${n.dependencyName} ${n.currentVersion}</td>
              <td>${n.message}</td>
              <td>${n.due ? new Date(n.due).toLocaleDateString() : 'N/A'}</td>
            </tr>
          `).join('')}
        </table>
      </div>
      
      <div class="dependencies">
        <h2>Dependencies</h2>
        <table>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Current Version</th>
            <th>Latest Version</th>
            <th>Repository</th>
            <th>End of Life</th>
          </tr>
          ${report.dependencies.map((d: any) => `
            <tr>
              <td>${d.name}</td>
              <td>${d.type}</td>
              <td>${d.version}</td>
              <td>${d.latestVersion || 'Unknown'}</td>
              <td>${d.repository || 'N/A'}</td>
              <td>${d.endOfLife || 'N/A'}</td>
            </tr>
          `).join('')}
        </table>
      </div>
    </body>
    </html>
  `;
}
