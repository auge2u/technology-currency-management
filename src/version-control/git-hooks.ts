import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as semver from 'semver';
import { OutdatedCommitAlert } from '../types/scanning';
import { log } from '../utils/logging';

const execAsync = promisify(exec);

/**
 * Configuration for Git hooks
 */
export interface GitHookConfig {
  packageManagers: Array<'npm' | 'yarn' | 'pip' | 'pipenv' | 'maven' | 'gradle' | 'bundler' | 'cargo' | 'go'>;
  blockCommitSeverity: 'critical' | 'high' | 'medium' | 'low';
  blockCommits: boolean;
  maxDependencyAgeDays: number;
  alertsPath: string;
  notify: boolean;
  notificationEmails: string[];
  repositories: Array<{
    name: string;
    path: string;
    blockCommits?: boolean;
    excludedDependencies?: string[];
    excludedFiles?: string[];
  }>;
  allowedDependencies: string[];
  criticalDependencies: string[];
}

/**
 * Get diff of files changed in the current commit
 */
async function getGitDiff(): Promise<string> {
  try {
    const { stdout } = await execAsync('git diff --cached --name-only');
    return stdout.trim();
  } catch (error) {
    log.error('Failed to get git diff', { error });
    return '';
  }
}

/**
 * Parse package.json from diff
 */
async function getPackageJsonFromDiff(repoPath: string): Promise<Array<{ path: string; content: any }>> {
  try {
    const { stdout } = await execAsync('git diff --cached --name-only | grep -E "package.json$"');
    const packageJsonFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (packageJsonFiles.length === 0) {
      return [];
    }
    
    const results: Array<{ path: string; content: any }> = [];
    
    for (const relativePath of packageJsonFiles) {
      const fullPath = path.join(repoPath, relativePath);
      
      try {
        const { stdout: fileContent } = await execAsync(`git show :${relativePath}`);
        const packageJson = JSON.parse(fileContent);
        
        results.push({
          path: relativePath,
          content: packageJson
        });
      } catch (fileError) {
        log.warn(`Failed to parse package.json at ${fullPath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    return [];
  }
}

/**
 * Parse requirements.txt from diff
 */
async function getPythonRequirementsFromDiff(repoPath: string): Promise<Array<{ path: string; content: string }>> {
  try {
    const { stdout } = await execAsync('git diff --cached --name-only | grep -E "requirements.txt$"');
    const requirementsFiles = stdout.trim().split('\n').filter(Boolean);
    
    if (requirementsFiles.length === 0) {
      return [];
    }
    
    const results: Array<{ path: string; content: string }> = [];
    
    for (const relativePath of requirementsFiles) {
      const fullPath = path.join(repoPath, relativePath);
      
      try {
        const { stdout: fileContent } = await execAsync(`git show :${relativePath}`);
        
        results.push({
          path: relativePath,
          content: fileContent
        });
      } catch (fileError) {
        log.warn(`Failed to read requirements.txt at ${fullPath}`, { error: fileError });
      }
    }
    
    return results;
  } catch (error) {
    return [];
  }
}

/**
 * Check NPM dependencies for outdated versions
 */
async function checkNpmDependencies(
  packageJsonFiles: Array<{ path: string; content: any }>,
  config: GitHookConfig
): Promise<OutdatedCommitAlert[]> {
  const alerts: OutdatedCommitAlert[] = [];
  
  for (const { path: filePath, content } of packageJsonFiles) {
    const repo = config.repositories.find(r => filePath.startsWith(r.path));
    if (repo?.excludedFiles?.some(pattern => filePath.includes(pattern))) {
      continue;
    }
    
    const dependencies = { ...content.dependencies };
    if (content.devDependencies) {
      Object.assign(dependencies, content.devDependencies);
    }
    
    const outdatedDeps: Array<{
      name: string;
      currentVersion: string;
      recommendedVersion: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
    }> = [];
    
    for (const [name, versionSpec] of Object.entries(dependencies)) {
      if (config.allowedDependencies.includes(name)) {
        continue;
      }
      
      if (repo?.excludedDependencies?.includes(name)) {
        continue;
      }
      
      if (typeof versionSpec !== 'string') {
        continue;
      }
      
      const currentVersion = versionSpec.replace(/^[\^~><=]/, '');
      
      try {
        const latestVersion = await getLatestNpmVersion(name);
        
        if (latestVersion && currentVersion && semver.valid(currentVersion) && semver.valid(latestVersion)) {
          if (semver.lt(currentVersion, latestVersion)) {
            const diff = semver.diff(currentVersion, latestVersion);
            const behind = getVersionsBehind(currentVersion, latestVersion);
            
            let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';
            
            if (config.criticalDependencies.includes(name)) {
              severity = 'critical';
            } else if (diff) {
              severity = getSeverityForVersionDiff(diff, behind);
            }
            
            outdatedDeps.push({
              name,
              currentVersion,
              recommendedVersion: latestVersion,
              severity
            });
          }
        }
      } catch (error) {
        log.warn(`Failed to check latest version for ${name}`, { error });
      }
    }
    
    if (outdatedDeps.length > 0) {
      const { stdout: gitConfig } = await execAsync('git config --get remote.origin.url');
      const { stdout: branchName } = await execAsync('git symbolic-ref --short HEAD');
      const { stdout: commitSha } = await execAsync('git rev-parse HEAD');
      const { stdout: userName } = await execAsync('git config user.name');
      const { stdout: userEmail } = await execAsync('git config user.email');
      
      const repoName = gitConfig.trim().split('/').pop()?.replace('.git', '') || 'unknown';
      
      const shouldBlock = config.blockCommits && 
        outdatedDeps.some(dep => {
          const severityValue = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
          const thresholdValue = severityValue[config.blockCommitSeverity];
          return severityValue[dep.severity] >= thresholdValue;
        });
      
      const criticalAndHighCount = outdatedDeps.filter(dep => 
        dep.severity === 'critical' || dep.severity === 'high'
      ).length;
      
      const warningMessage = [
        `⚠️ Outdated dependencies detected in ${filePath}`,
        `Found ${outdatedDeps.length} outdated dependencies (${criticalAndHighCount} critical/high severity)`,
        '',
        'Outdated dependencies:',
        ...outdatedDeps.map(dep => 
          `- ${dep.name}: ${dep.currentVersion} → ${dep.recommendedVersion} (${dep.severity.toUpperCase()})`
        ),
        '',
        shouldBlock 
          ? 'Commit blocked. Please update these dependencies before committing.'
          : 'Consider updating these dependencies to ensure security and compatibility.'
      ].join('\n');
      
      const alert: OutdatedCommitAlert = {
        id: `${repoName}-${commitSha.substring(0, 8)}`,
        repositoryName: repoName,
        branchName: branchName.trim(),
        commitSha: commitSha.trim(),
        developerName: userName.trim(),
        developerEmail: userEmail.trim(),
        timestamp: new Date(),
        filesChanged: [filePath],
        outdatedDependencies: outdatedDeps,
        blockCommit: shouldBlock,
        warningMessage
      };
      
      alerts.push(alert);
    }
  }
  
  return alerts;
}

/**
 * Install git hooks for a repository
 */
export async function installGitHooks(repoPath: string): Promise<void> {
  try {
    log.info(`Installing git hooks in ${repoPath}`);
    
    const hooksDir = path.join(repoPath, '.git', 'hooks');
    
    if (!fs.existsSync(hooksDir)) {
      log.warn(`Hooks directory not found: ${hooksDir}`);
      return;
    }
    
    const preCommitPath = path.join(hooksDir, 'pre-commit');
    const preCommitScript = [
      '#!/bin/sh',
      '',
      '# Installed by tech-currency-management',
      '# Hook to check for outdated dependencies in commits',
      '',
      'npx tech-currency-check-commit',
      '',
      '# Exit with the status from the dependency check',
      'exit $?'
    ].join('\n');
    
    fs.writeFileSync(preCommitPath, preCommitScript, { mode: 0o755 });
    
    log.info(`Git hooks installed in ${repoPath}`);
  } catch (error) {
    log.error(`Failed to install git hooks in ${repoPath}`, { error });
    throw error;
  }
}

/**
 * Run the pre-commit hook
 */
export async function runPreCommitHook(config: GitHookConfig): Promise<OutdatedCommitAlert[]> {
  try {
    log.info('Running pre-commit hook');
    
    const { stdout: gitRoot } = await execAsync('git rev-parse --show-toplevel');
    const repoPath = gitRoot.trim();
    
    const repoConfig = config.repositories.find(r => r.path === repoPath);
    const shouldBlockForRepo = repoConfig?.blockCommits ?? config.blockCommits;
    
    const packageJsonFiles = await getPackageJsonFromDiff(repoPath);
    const requirementsFiles = await getPythonRequirementsFromDiff(repoPath);
    
    if (packageJsonFiles.length === 0 && requirementsFiles.length === 0) {
      log.info('No dependency files found in commit, skipping check');
      return [];
    }
    
    const npmAlerts = config.packageManagers.includes('npm') 
      ? await checkNpmDependencies(packageJsonFiles, config)
      : [];
    
    const allAlerts = [...npmAlerts];
    
    if (allAlerts.length > 0 && config.alertsPath) {
      const alertsDir = path.resolve(config.alertsPath);
      
      if (!fs.existsSync(alertsDir)) {
        fs.mkdirSync(alertsDir, { recursive: true });
      }
      
      for (const alert of allAlerts) {
        const alertPath = path.join(alertsDir, `${alert.id}.json`);
        fs.writeFileSync(alertPath, JSON.stringify(alert, null, 2));
      }
    }
    
    for (const alert of allAlerts) {
      console.log(alert.warningMessage);
    }
    
    const blockingAlerts = allAlerts.filter(alert => alert.blockCommit);
    
    if (blockingAlerts.length > 0 && shouldBlockForRepo) {
      console.error('Commit blocked due to outdated dependencies. Please update them and try again.');
      process.exit(1);
    }
    
    return allAlerts;
  } catch (error) {
    log.error('Failed to run pre-commit hook', { error });
    return [];
  }
}

// Helper function implementations (simplified for brevity)
async function getLatestNpmVersion(packageName: string): Promise<string | null> {
  return '1.0.0'; // Placeholder implementation
}

function getVersionsBehind(current: string, latest: string): { major: number; minor: number; patch: number; } {
  return { major: 0, minor: 1, patch: 0 }; // Placeholder implementation
}

function getSeverityForVersionDiff(
  diff: string,
  behind: { major: number; minor: number; patch: number }
): 'low' | 'medium' | 'high' | 'critical' {
  return 'medium'; // Placeholder implementation
}
