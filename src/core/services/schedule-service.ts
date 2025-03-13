import { CronJob } from 'cron';
import { log } from '../../utils/logging';
import config from '../../config';
import { runCodebaseScan } from '../scanners/codebase-scanner';
import { runDependencyScan } from '../scanners/dependency-scanner';
import { runSecurityVulnerabilityScan } from '../scanners/security-scanner';
import { runExtensionScan } from '../scanners/extension-scanner';
import { getActiveScans, setActiveScan, clearActiveScan } from '../utils/scan-state';

// Track all active cron jobs
const scheduledJobs: CronJob[] = [];

/**
 * Sets up all scheduled tasks for the application
 */
export async function setupScheduler(): Promise<void> {
  // Clean up any previously scheduled jobs
  cleanupScheduler();

  // Schedule the full technology scan
  scheduleFullScan();

  // Schedule daily dependency vulnerability check
  scheduleDependencyVulnerabilityScan();

  // Schedule browser extension scans if enabled
  if (config.scanning.extension.enabled) {
    scheduleExtensionScan();
  }

  log.info('Scheduler initialized successfully', {
    cronSchedule: config.scanning.cronSchedule,
    jobsScheduled: scheduledJobs.length,
    extensionScanEnabled: config.scanning.extension.enabled
  });
}

/**
 * Cleans up and stops all scheduled jobs
 */
export function cleanupScheduler(): void {
  scheduledJobs.forEach(job => {
    if (job.running) {
      job.stop();
    }
  });

  // Clear the array
  scheduledJobs.length = 0;
}

/**
 * Schedules the full comprehensive technology scan
 */
function scheduleFullScan(): void {
  const job = new CronJob(
    config.scanning.cronSchedule,
    async () => {
      try {
        // Check if a scan is already running
        const activeScans = getActiveScans();
        if (activeScans.includes('full-scan')) {
          log.warn('Full scan already in progress, skipping scheduled scan');
          return;
        }

        log.info('Starting scheduled full technology scan');
        setActiveScan('full-scan');

        // Run all scan types sequentially
        await runCodebaseScan();
        await runDependencyScan();
        await runSecurityVulnerabilityScan();

        if (config.scanning.extension.enabled) {
          await runExtensionScan();
        }

        log.info('Completed scheduled full technology scan');
      } catch (error) {
        log.error('Error during scheduled full scan', { error });
      } finally {
        clearActiveScan('full-scan');
      }
    },
    null, // onComplete
    true, // start
    'UTC' // timezone
  );

  scheduledJobs.push(job);
}

/**
 * Schedules dependency vulnerability scans
 */
function scheduleDependencyVulnerabilityScan(): void {
  // Run vulnerability scans twice a day (more frequent than full scan)
  const job = new CronJob(
    '0 */12 * * *', // Every 12 hours
    async () => {
      try {
        const activeScans = getActiveScans();
        if (activeScans.includes('vulnerability-scan')) {
          log.warn('Vulnerability scan already in progress, skipping scheduled scan');
          return;
        }

        log.info('Starting scheduled vulnerability scan');
        setActiveScan('vulnerability-scan');

        await runSecurityVulnerabilityScan();

        log.info('Completed scheduled vulnerability scan');
      } catch (error) {
        log.error('Error during scheduled vulnerability scan', { error });
      } finally {
        clearActiveScan('vulnerability-scan');
      }
    },
    null,
    true,
    'UTC'
  );

  scheduledJobs.push(job);
}

/**
 * Schedules browser extension scans
 */
function scheduleExtensionScan(): void {
  // Schedule weekly extension scans
  const job = new CronJob(
    '0 0 * * 0', // Every Sunday at midnight
    async () => {
      try {
        const activeScans = getActiveScans();
        if (activeScans.includes('extension-scan')) {
          log.warn('Extension scan already in progress, skipping scheduled scan');
          return;
        }

        log.info('Starting scheduled browser extension scan');
        setActiveScan('extension-scan');

        await runExtensionScan();

        log.info('Completed scheduled browser extension scan');
      } catch (error) {
        log.error('Error during scheduled extension scan', { error });
      } finally {
        clearActiveScan('extension-scan');
      }
    },
    null,
    true,
    'UTC'
  );

  scheduledJobs.push(job);
}

/**
 * Runs an immediate full scan
 * @returns Promise that resolves when the scan is complete
 */
export async function runImmediateFullScan(): Promise<void> {
  try {
    // Check if a scan is already running
    const activeScans = getActiveScans();
    if (activeScans.includes('full-scan')) {
      throw new Error('Full scan already in progress');
    }

    log.info('Starting immediate full technology scan');
    setActiveScan('full-scan');

    // Run all scan types sequentially
    await runCodebaseScan();
    await runDependencyScan();
    await runSecurityVulnerabilityScan();

    if (config.scanning.extension.enabled) {
      await runExtensionScan();
    }

    log.info('Completed immediate full technology scan');
  } catch (error) {
    log.error('Error during immediate full scan', { error });
    throw error;
  } finally {
    clearActiveScan('full-scan');
  }
}
