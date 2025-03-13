import { log } from '../../utils/logging';

// Track all currently active scans by type
let activeScans: string[] = [];

/**
 * Set a scan as active
 * @param scanType The type of scan (e.g., 'full-scan', 'vulnerability-scan')
 */
export function setActiveScan(scanType: string): void {
  if (!activeScans.includes(scanType)) {
    activeScans.push(scanType);
    log.debug(`Scan activated: ${scanType}`, { activeScans });
  }
}

/**
 * Clear a scan from the active list
 * @param scanType The type of scan to clear
 */
export function clearActiveScan(scanType: string): void {
  activeScans = activeScans.filter(type => type !== scanType);
  log.debug(`Scan completed: ${scanType}`, { activeScans });
}

/**
 * Get all currently active scans
 * @returns Array of active scan types
 */
export function getActiveScans(): string[] {
  return [...activeScans];
}

/**
 * Check if a specific scan is currently active
 * @param scanType The scan type to check
 * @returns True if the scan is active
 */
export function isScanActive(scanType: string): boolean {
  return activeScans.includes(scanType);
}

/**
 * Check if any scan is currently active
 * @returns True if any scan is active
 */
export function isAnyScanActive(): boolean {
  return activeScans.length > 0;
}

/**
 * Get the progress of active scans
 * @returns Object containing scan progress information
 */
export function getScanProgress(): Record<string, any> {
  // In a real implementation, this would track progress percentages
  // For this example, we just return which scans are active
  return {
    activeScans,
    scanCount: activeScans.length,
    isActive: activeScans.length > 0,
    timestamp: new Date().toISOString()
  };
}
