/**
 * Logging utilities for technology currency management
 */

// Log levels
type LogLevel = 'debug' | 'info' | 'warn' | 'error';

// Log entry with metadata
interface LogEntry {
  timestamp: Date;
  level: LogLevel;
  message: string;
  context?: any;
  component?: string;
}

// Logger configuration
interface LoggerConfig {
  minLevel: LogLevel;
  enableConsole: boolean;
  enableFile: boolean;
  filePath?: string;
  enableMetrics: boolean;
  metricsSink?: (metrics: any) => void;
}

// Default configuration
const defaultConfig: LoggerConfig = {
  minLevel: 'info',
  enableConsole: true,
  enableFile: false,
  enableMetrics: false,
};

// Current configuration
let currentConfig: LoggerConfig = { ...defaultConfig };

// In-memory log buffer for last N entries
const logBuffer: LogEntry[] = [];
const LOG_BUFFER_SIZE = 1000;

/**
 * Convert log level to numeric value for comparison
 */
function levelToNumber(level: LogLevel): number {
  switch (level) {
    case 'debug': return 0;
    case 'info': return 1;
    case 'warn': return 2;
    case 'error': return 3;
    default: return 1;
  }
}

/**
 * Format a log entry as a string
 */
function formatLogEntry(entry: LogEntry): string {
  const timestamp = entry.timestamp.toISOString();
  const level = entry.level.toUpperCase().padEnd(5);
  const component = entry.component ? `[${entry.component}] ` : '';
  let message = `${timestamp} ${level} ${component}${entry.message}`;
  
  // Add context if available
  if (entry.context) {
    try {
      // For errors, extract the message
      if (entry.context.error instanceof Error) {
        message += ` - ${entry.context.error.message}`;
        if (entry.context.error.stack) {
          message += `\n${entry.context.error.stack}`;
        }
      } else {
        // For other context, stringify
        const contextStr = JSON.stringify(entry.context);
        if (contextStr !== '{}') {
          message += ` - ${contextStr}`;
        }
      }
    } catch (e) {
      message += ` - [Context serialization failed]`;
    }
  }
  
  return message;
}

/**
 * Write a log entry
 */
function writeLog(entry: LogEntry): void {
  // Check minimum log level
  if (levelToNumber(entry.level) < levelToNumber(currentConfig.minLevel)) {
    return;
  }
  
  // Format the entry
  const formattedEntry = formatLogEntry(entry);
  
  // Console output
  if (currentConfig.enableConsole) {
    switch (entry.level) {
      case 'debug':
        console.debug(formattedEntry);
        break;
      case 'info':
        console.info(formattedEntry);
        break;
      case 'warn':
        console.warn(formattedEntry);
        break;
      case 'error':
        console.error(formattedEntry);
        break;
    }
  }
  
  // File output (would be implemented with fs.appendFile in a real implementation)
  if (currentConfig.enableFile && currentConfig.filePath) {
    // In a real implementation:
    // fs.appendFile(currentConfig.filePath, formattedEntry + '\n', (err) => {
    //   if (err) console.error(`Failed to write to log file: ${err.message}`);
    // });
  }
  
  // Metrics output
  if (currentConfig.enableMetrics && currentConfig.metricsSink) {
    const metricData = {
      timestamp: entry.timestamp,
      level: entry.level,
      component: entry.component || 'unknown'
    };
    currentConfig.metricsSink(metricData);
  }
  
  // Add to in-memory buffer
  logBuffer.push(entry);
  if (logBuffer.length > LOG_BUFFER_SIZE) {
    logBuffer.shift();
  }
}

/**
 * Create a log entry
 */
function createLogEntry(
  level: LogLevel,
  message: string,
  context?: any,
  component?: string
): LogEntry {
  return {
    timestamp: new Date(),
    level,
    message,
    context,
    component
  };
}

/**
 * Configure the logger
 */
export function configureLogger(config: Partial<LoggerConfig>): void {
  currentConfig = { ...currentConfig, ...config };
}

/**
 * Get recent log entries
 */
export function getRecentLogs(
  count: number = 100,
  level?: LogLevel
): LogEntry[] {
  let logs = [...logBuffer];
  
  // Filter by level if specified
  if (level) {
    const minLevelValue = levelToNumber(level);
    logs = logs.filter(entry => levelToNumber(entry.level) >= minLevelValue);
  }
  
  // Return the most recent entries
  return logs.slice(-count);
}

/**
 * Clear the log buffer
 */
export function clearLogBuffer(): void {
  logBuffer.length = 0;
}

/**
 * The logger object with methods for each log level
 */
export const log = {
  debug: (message: string, context?: any, component?: string) => {
    writeLog(createLogEntry('debug', message, context, component));
  },
  
  info: (message: string, context?: any, component?: string) => {
    writeLog(createLogEntry('info', message, context, component));
  },
  
  warn: (message: string, context?: any, component?: string) => {
    writeLog(createLogEntry('warn', message, context, component));
  },
  
  error: (message: string, context?: any, component?: string) => {
    writeLog(createLogEntry('error', message, context, component));
  },
  
  /**
   * Log with component context
   */
  withComponent: (component: string) => ({
    debug: (message: string, context?: any) => {
      writeLog(createLogEntry('debug', message, context, component));
    },
    
    info: (message: string, context?: any) => {
      writeLog(createLogEntry('info', message, context, component));
    },
    
    warn: (message: string, context?: any) => {
      writeLog(createLogEntry('warn', message, context, component));
    },
    
    error: (message: string, context?: any) => {
      writeLog(createLogEntry('error', message, context, component));
    }
  })
};
