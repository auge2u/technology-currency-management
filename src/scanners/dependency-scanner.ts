import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import axios from 'axios';
import { log } from '../utils/logging';
import { OutdatedDependency } from '../types/scanning';
import { determineSeverity } from '../utils/severity-calculator';
import { getRemediation } from '../utils/remediation-helper';

const execAsync = promisify(exec);

/**
 * Scans for outdated dependencies in multiple package managers
 */
export async function scanDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Starting dependency scanning');
    
    const results: OutdatedDependency[] = [];
    
    // Scan for all types of dependencies
    const npmDeps = await scanNpmDependencies(rootDir);
    const pythonDeps = await scanPythonDependencies(rootDir);
    const gemDeps = await scanRubyDependencies(rootDir);
    const composerDeps = await scanPhpDependencies(rootDir);
    const javaDeps = await scanJavaDependencies(rootDir);
    
    results.push(...npmDeps, ...pythonDeps, ...gemDeps, ...composerDeps, ...javaDeps);
    
    log.info(`Dependency scanning completed. Found ${results.length} outdated dependencies`);
    
    return results;
  } catch (error) {
    log.error('Error during dependency scanning', { error });
    return [];
  }
}

/**
 * Scan for outdated NPM dependencies
 */
async function scanNpmDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Scanning NPM dependencies');
    const results: OutdatedDependency[] = [];
    
    // Find all package.json files
    const packageFiles = await findFiles(rootDir, 'package.json');
    
    log.debug(`Found ${packageFiles.length} package.json files`);
    
    for (const packageFile of packageFiles) {
      try {
        const packageJson = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
        const packageLockPath = path.join(path.dirname(packageFile), 'package-lock.json');
        const yarnLockPath = path.join(path.dirname(packageFile), 'yarn.lock');
        const pnpmLockPath = path.join(path.dirname(packageFile), 'pnpm-lock.yaml');
        
        // Determine package manager
        let packageManager = 'npm';
        if (fs.existsSync(yarnLockPath)) {
          packageManager = 'yarn';
        } else if (fs.existsSync(pnpmLockPath)) {
          packageManager = 'pnpm';
        }
        
        // Get registry info for all dependencies
        const allDeps = {
          ...packageJson.dependencies || {},
          ...packageJson.devDependencies || {},
        };
        
        for (const [name, versionConstraint] of Object.entries<string>(allDeps)) {
          try {
            // Skip github and file dependencies
            if (
              versionConstraint.includes('github:') ||
              versionConstraint.includes('git+') ||
              versionConstraint.startsWith('file:')
            ) {
              continue;
            }
            
            // Clean up version string
            const cleanVersion = versionConstraint.replace(/^[\^~]/, '');
            
            // Get latest version from npm registry
            const { data } = await axios.get(`https://registry.npmjs.org/${name}`);
            const latestVersion = data['dist-tags']?.latest;
            
            if (latestVersion && cleanVersion !== latestVersion) {
              // Check for deprecation
              const isDeprecated = !!data.versions?.[latestVersion]?.deprecated;
              
              // Determine if it's a direct or dev dependency
              const isDev = !!packageJson.devDependencies?.[name];
              const isDirectDependency = !!packageJson.dependencies?.[name] || isDev;
              
              // Calculate severity based on version difference
              let breakingChanges = false;
              if (cleanVersion && latestVersion) {
                const [currMajor] = cleanVersion.split('.').map(Number);
                const [latestMajor] = latestVersion.split('.').map(Number);
                breakingChanges = currMajor < latestMajor;
              }
              
              const severity = determineSeverity({
                versionDifference: { current: cleanVersion, latest: latestVersion },
                isDeprecated,
                isDirectDependency,
                breakingChanges,
                isDev
              });
              
              const remediationSteps = getRemediation({
                type: 'dependency',
                packageManager,
                name,
                currentVersion: cleanVersion,
                latestVersion,
                isDev
              });
              
              // Parse release date if available
              let releaseDate: Date | undefined;
              if (data.time?.[latestVersion]) {
                releaseDate = new Date(data.time[latestVersion]);
              }
              
              results.push({
                name,
                currentVersion: cleanVersion,
                latestVersion,
                packageManager: packageManager as any,
                filePath: packageFile,
                isDirectDependency,
                isDev,
                isDeprecated,
                severity,
                breakingChanges,
                remediationSteps,
                releaseDate,
                detectedAt: new Date()
              });
            }
          } catch (depError) {
            log.warn(`Error checking dependency ${name}`, { error: depError });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${packageFile}`, { error: fileError });
      }
    }
    
    log.info(`Found ${results.length} outdated NPM dependencies`);
    return results;
  } catch (error) {
    log.error('Error scanning NPM dependencies', { error });
    return [];
  }
}

/**
 * Scan for outdated Python dependencies
 */
async function scanPythonDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Scanning Python dependencies');
    const results: OutdatedDependency[] = [];
    
    // Find all requirements.txt files
    const requirementsFiles = await findFiles(rootDir, 'requirements.txt');
    log.debug(`Found ${requirementsFiles.length} requirements.txt files`);
    
    for (const requirementsFile of requirementsFiles) {
      try {
        const content = fs.readFileSync(requirementsFile, 'utf8');
        const lines = content
          .split('\n')
          .map(line => line.trim())
          .filter(line => line && !line.startsWith('#'));
        
        for (const line of lines) {
          try {
            // Parse package name and version constraint
            const match = line.match(/^([\w-]+)(?:[=<>!~]+(\d+\.\d+\.\d+))?.*$/);
            if (match) {
              const [, name, version] = match;
              if (!name) continue;
              
              // Get latest version from PyPI
              const { data } = await axios.get(`https://pypi.org/pypi/${name}/json`);
              const latestVersion = data.info?.version;
              
              if (latestVersion && (!version || version !== latestVersion)) {
                const severity = determineSeverity({
                  versionDifference: { current: version || '0.0.0', latest: latestVersion },
                  isDirectDependency: true
                });
                
                const remediationSteps = getRemediation({
                  type: 'dependency',
                  packageManager: 'pip',
                  name,
                  currentVersion: version || 'unknown',
                  latestVersion
                });
                
                results.push({
                  name,
                  currentVersion: version || 'unknown',
                  latestVersion,
                  packageManager: 'pip',
                  filePath: requirementsFile,
                  isDirectDependency: true,
                  isDev: false,
                  severity,
                  remediationSteps,
                  detectedAt: new Date()
                });
              }
            }
          } catch (lineError) {
            log.warn(`Error parsing Python dependency: ${line}`, { error: lineError });
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${requirementsFile}`, { error: fileError });
      }
    }
    
    log.info(`Found ${results.length} outdated Python dependencies`);
    return results;
  } catch (error) {
    log.error('Error scanning Python dependencies', { error });
    return [];
  }
}

/**
 * Scan for outdated Ruby dependencies
 */
async function scanRubyDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Scanning Ruby dependencies');
    const results: OutdatedDependency[] = [];
    
    // Find all Gemfile files
    const gemfiles = await findFiles(rootDir, 'Gemfile');
    log.debug(`Found ${gemfiles.length} Gemfile files`);
    
    for (const gemfile of gemfiles) {
      try {
        const content = fs.readFileSync(gemfile, 'utf8');
        const gemfileDir = path.dirname(gemfile);
        
        // Check if bundler is installed
        try {
          await execAsync('bundle --version');
          
          // Execute bundle outdated in the gemfile directory
          const { stdout } = await execAsync('bundle outdated --parseable', { cwd: gemfileDir });
          
          const outdatedGems = stdout.split('\n').filter(Boolean);
          for (const gemLine of outdatedGems) {
            const [name, currentVersion, latestVersion] = gemLine.split(',');
            if (name && currentVersion && latestVersion) {
              const severity = determineSeverity({
                versionDifference: { current: currentVersion, latest: latestVersion },
                isDirectDependency: true
              });
              
              const remediationSteps = getRemediation({
                type: 'dependency',
                packageManager: 'gem',
                name,
                currentVersion,
                latestVersion
              });
              
              results.push({
                name,
                currentVersion,
                latestVersion,
                packageManager: 'gem',
                filePath: gemfile,
                isDirectDependency: true,
                isDev: false,
                severity,
                remediationSteps,
                detectedAt: new Date()
              });
            }
          }
        } catch (execError) {
          log.warn(`Bundler not available or error running bundle outdated`, { error: execError });
          
          // Fallback: parse Gemfile manually
          const gemRegex = /gem\s+['"]([\w-]+)['"](?:[,]\s*['"]([\d.]+)['"])?/g;
          let match;
          
          while ((match = gemRegex.exec(content)) !== null) {
            const [, name, version] = match;
            if (name) {
              try {
                // Try to get latest version info
                const { data } = await axios.get(`https://rubygems.org/api/v1/gems/${name}.json`);
                const latestVersion = data.version;
                
                if (latestVersion && (!version || version !== latestVersion)) {
                  const severity = determineSeverity({
                    versionDifference: { current: version || '0.0.0', latest: latestVersion },
                    isDirectDependency: true
                  });
                  
                  const remediationSteps = getRemediation({
                    type: 'dependency',
                    packageManager: 'gem',
                    name,
                    currentVersion: version || 'unknown',
                    latestVersion
                  });
                  
                  results.push({
                    name,
                    currentVersion: version || 'unknown',
                    latestVersion,
                    packageManager: 'gem',
                    filePath: gemfile,
                    isDirectDependency: true,
                    isDev: false,
                    severity,
                    remediationSteps,
                    detectedAt: new Date()
                  });
                }
              } catch (gemError) {
                log.warn(`Error checking Ruby gem ${name}`, { error: gemError });
              }
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${gemfile}`, { error: fileError });
      }
    }
    
    log.info(`Found ${results.length} outdated Ruby dependencies`);
    return results;
  } catch (error) {
    log.error('Error scanning Ruby dependencies', { error });
    return [];
  }
}

/**
 * Scan for outdated PHP dependencies
 */
async function scanPhpDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Scanning PHP dependencies');
    const results: OutdatedDependency[] = [];
    
    // Find all composer.json files
    const composerFiles = await findFiles(rootDir, 'composer.json');
    log.debug(`Found ${composerFiles.length} composer.json files`);
    
    for (const composerFile of composerFiles) {
      try {
        const composerJson = JSON.parse(fs.readFileSync(composerFile, 'utf8'));
        const composerDir = path.dirname(composerFile);
        
        // Check if composer is installed
        try {
          await execAsync('composer --version');
          
          // Execute composer outdated in the composer directory
          const { stdout } = await execAsync('composer outdated --format=json', { cwd: composerDir });
          const outdatedPackages = JSON.parse(stdout).installed;
          
          for (const pkg of outdatedPackages) {
            if (pkg.name && pkg.version && pkg.latest) {
              const isDev = !!composerJson.require-dev?.[pkg.name];
              
              const severity = determineSeverity({
                versionDifference: { current: pkg.version, latest: pkg.latest },
                isDirectDependency: true,
                isDev
              });
              
              const remediationSteps = getRemediation({
                type: 'dependency',
                packageManager: 'composer',
                name: pkg.name,
                currentVersion: pkg.version,
                latestVersion: pkg.latest,
                isDev
              });
              
              results.push({
                name: pkg.name,
                currentVersion: pkg.version,
                latestVersion: pkg.latest,
                packageManager: 'composer',
                filePath: composerFile,
                isDirectDependency: true,
                isDev,
                severity,
                remediationSteps,
                detectedAt: new Date()
              });
            }
          }
        } catch (execError) {
          log.warn(`Composer not available or error running composer outdated`, { error: execError });
          
          // Fallback: parse composer.json manually
          const allDeps = {
            ...composerJson.require || {},
            ...composerJson['require-dev'] || {}
          };
          
          for (const [name, versionConstraint] of Object.entries<string>(allDeps)) {
            if (name === 'php') continue; // Skip PHP version constraint
            
            try {
              // Clean up version string (remove constraints like ^, ~, etc)
              const cleanVersion = versionConstraint.replace(/^[\^~]/, '');
              
              // Get info from Packagist
              const { data } = await axios.get(`https://repo.packagist.org/p2/${name}.json`);
              const packageData = data.packages[name];
              if (packageData && packageData.length > 0) {
                const latestVersion = packageData[0].version;
                
                if (latestVersion && cleanVersion !== latestVersion) {
                  const isDev = !!composerJson['require-dev']?.[name];
                  
                  const severity = determineSeverity({
                    versionDifference: { current: cleanVersion, latest: latestVersion },
                    isDirectDependency: true,
                    isDev
                  });
                  
                  const remediationSteps = getRemediation({
                    type: 'dependency',
                    packageManager: 'composer',
                    name,
                    currentVersion: cleanVersion,
                    latestVersion,
                    isDev
                  });
                  
                  results.push({
                    name,
                    currentVersion: cleanVersion,
                    latestVersion,
                    packageManager: 'composer',
                    filePath: composerFile,
                    isDirectDependency: true,
                    isDev,
                    severity,
                    remediationSteps,
                    detectedAt: new Date()
                  });
                }
              }
            } catch (pkgError) {
              log.warn(`Error checking PHP package ${name}`, { error: pkgError });
            }
          }
        }
      } catch (fileError) {
        log.warn(`Error processing ${composerFile}`, { error: fileError });
      }
    }
    
    log.info(`Found ${results.length} outdated PHP dependencies`);
    return results;
  } catch (error) {
    log.error('Error scanning PHP dependencies', { error });
    return [];
  }
}

/**
 * Scan for outdated Java dependencies
 */
async function scanJavaDependencies(rootDir: string): Promise<OutdatedDependency[]> {
  try {
    log.info('Scanning Java dependencies');
    const results: OutdatedDependency[] = [];
    
    // Find all pom.xml files (Maven)
    const pomFiles = await findFiles(rootDir, 'pom.xml');
    log.debug(`Found ${pomFiles.length} pom.xml files`);
    
    // Find all build.gradle files (Gradle)
    const gradleFiles = await findFiles(rootDir, 'build.gradle');
    const gradleKtsFiles = await findFiles(rootDir, 'build.gradle.kts');
    const allGradleFiles = [...gradleFiles, ...gradleKtsFiles];
    log.debug(`Found ${allGradleFiles.length} Gradle files`);
    
    // Process Maven projects
    for (const pomFile of pomFiles) {
      try {
        const pomDir = path.dirname(pomFile);
        
        // Check if Maven is installed
        try {
          await execAsync('mvn --version');
          
          // Run Maven versions plugin for dependency checking
          const { stdout } = await execAsync(
            'mvn versions:display-dependency-updates -DprocessDependencyManagement=false -q',
            { cwd: pomDir }
          );
          
          // Parse the output to find outdated dependencies
          const outdatedRegex = /\s+([\w.-]+):([\w.-]+)\s+\S+\s+->\s+(\S+)/g;
          let match;
          
          while ((match = outdatedRegex.exec(stdout)) !== null) {
            const [, groupId, artifactId, latestVersion] = match;
            const name = `${groupId}:${artifactId}`;
            
            // Try to extract current version from the output
            const currentVersionMatch = new RegExp(
              `${groupId}:${artifactId}\s+(\S+)\s+->`,
              'g'
            ).exec(stdout);
            const currentVersion = currentVersionMatch ? currentVersionMatch[1] : 'unknown';
            
            const severity = determineSeverity({
              versionDifference: { current: currentVersion, latest: latestVersion },
              isDirectDependency: true
            });
            
            const remediationSteps = getRemediation({
              type: 'dependency',
              packageManager: 'maven',
              name,
              currentVersion,
              latestVersion
            });
            
            results.push({
              name,
              currentVersion,
              latestVersion,
              packageManager: 'maven',
              filePath: pomFile,
              isDirectDependency: true,
              isDev: false,
              severity,
              remediationSteps,
              detectedAt: new Date()
            });
          }
        } catch (execError) {
          log.warn(`Maven not available or error running mvn versions plugin`, { error: execError });
        }
      } catch (fileError) {
        log.warn(`Error processing ${pomFile}`, { error: fileError });
      }
    }
    
    // Process Gradle projects
    for (const gradleFile of allGradleFiles) {
      try {
        const gradleDir = path.dirname(gradleFile);
        
        // Check if Gradle is installed
        try {
          await execAsync('gradle --version');
          
          // Run Gradle dependencies task
          const { stdout } = await execAsync(
            'gradle dependencies --configuration runtimeClasspath',
            { cwd: gradleDir }
          );
          
          // Parse the output to find outdated dependencies
          // This is a simplified parsing and might need adjustment for specific gradle outputs
          const dependencyRegex = /--- ([\w.-]+):([\w.-]+):(\S+)/g;
          const content = fs.readFileSync(gradleFile, 'utf8');
          
          // Extract mentioned versions from build.gradle
          const versionRegex = /['"]([\w.-]+):([\w.-]+):([\d.]+)['"]|implementation\(['"](\S+):([\d.]+)/g;
          let match;
          
          while ((match = versionRegex.exec(content)) !== null) {
            const [, groupId, artifactId, version] = match;
            if (groupId && artifactId && version) {
              const name = `${groupId}:${artifactId}`;
              
              // Get latest version (simplified - in a real implementation you might use
              // Gradle dependency insights or call Maven central API)
              try {
                const { data } = await axios.get(
                  `https://search.maven.org/solrsearch/select?q=g:${groupId}+AND+a:${artifactId}&rows=1&wt=json`
                );
                
                if (data?.response?.docs?.[0]?.latestVersion) {
                  const latestVersion = data.response.docs[0].latestVersion;
                  
                  if (version !== latestVersion) {
                    const severity = determineSeverity({
                      versionDifference: { current: version, latest: latestVersion },
                      isDirectDependency: true
                    });
                    
                    const remediationSteps = getRemediation({
                      type: 'dependency',
                      packageManager: 'gradle',
                      name,
                      currentVersion: version,
                      latestVersion
                    });
                    
                    results.push({
                      name,
                      currentVersion: version,
                      latestVersion,
                      packageManager: 'gradle',
                      filePath: gradleFile,
                      isDirectDependency: true,
                      isDev: false,
                      severity,
                      remediationSteps,
                      detectedAt: new Date()
                    });
                  }
                }
              } catch (apiError) {
                log.warn(`Error checking Maven Central for ${name}`, { error: apiError });
              }
            }
          }
        } catch (execError) {
          log.warn(`Gradle not available or error running gradle dependencies`, { error: execError });
        }
      } catch (fileError) {
        log.warn(`Error processing ${gradleFile}`, { error: fileError });
      }
    }
    
    log.info(`Found ${results.length} outdated Java dependencies`);
    return results;
  } catch (error) {
    log.error('Error scanning Java dependencies', { error });
    return [];
  }
}

/**
 * Find files with a specific name recursively
 */
async function findFiles(rootDir: string, fileName: string): Promise<string[]> {
  try {
    const { stdout } = await execAsync(`find ${rootDir} -name "${fileName}" -type f`);
    return stdout.trim().split('\n').filter(Boolean);
  } catch (error) {
    log.error(`Error finding ${fileName} files`, { error });
    return [];
  }
}
