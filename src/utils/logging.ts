/**
 * Logging utility for the technology currency management system
 */

// Log levels
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4
}

// Interface for log metadata
interface LogMeta {
  [key: string]: any;
}

/**
 * Logger configuration options
 */
interface LoggerConfig {
  // Minimum log level to display
  minLevel: LogLevel;
  // Whether to include timestamps in logs
  showTimestamps: boolean;
  // Whether to colorize console output
  colorize: boolean;
  // Whether to output logs to a file
  logToFile: boolean;
  // Path to log file (if logToFile is true)
  logFilePath?: string;
  // Format string for log output
  format?: string;
}

/**
 * Default configuration
 */
const defaultConfig: LoggerConfig = {
  minLevel: LogLevel.INFO,
  showTimestamps: true,
  colorize: true,
  logToFile: false
};

/**
 * Main logger class
 */
class Logger {
  private config: LoggerConfig;
  
  constructor(config: Partial<LoggerConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
  }
  
  /**
   * Update logger configuration
   */
  configure(config: Partial<LoggerConfig>): void {
    this.config = { ...this.config, ...config };
  }
  
  /**
   * Log a debug message
   */
  debug(message: string, meta?: LogMeta): void {
    this.log(LogLevel.DEBUG, message, meta);
  }
  
  /**
   * Log an info message
   */
  info(message: string, meta?: LogMeta): void {
    this.log(LogLevel.INFO, message, meta);
  }
  
  /**
   * Log a warning message
   */
  warn(message: string, meta?: LogMeta): void {
    this.log(LogLevel.WARN, message, meta);
  }
  
  /**
   * Log an error message
   */
  error(message: string, meta?: LogMeta): void {
    this.log(LogLevel.ERROR, message, meta);
  }
  
  /**
   * Internal log method
   */
  private log(level: LogLevel, message: string, meta?: LogMeta): void {
    // Skip if level is below minimum
    if (level < this.config.minLevel) {
      return;
    }
    
    // Build log message
    let logMessage = '';
    
    // Add timestamp if enabled
    if (this.config.showTimestamps) {
      logMessage += `[${new Date().toISOString()}] `;
    }
    
    // Add log level
    const levelNames = ['DEBUG', 'INFO', 'WARN', 'ERROR'];
    logMessage += `[${levelNames[level]}] `;
    
    // Add message
    logMessage += message;
    
    // Add metadata if provided
    if (meta) {
      logMessage += ' ' + JSON.stringify(meta);
    }
    
    // Output to console with appropriate color
    if (this.config.colorize) {
      this.colorizedConsoleLog(level, logMessage);
    } else {
      console.log(logMessage);
    }
    
    // Output to file if enabled
    if (this.config.logToFile && this.config.logFilePath) {
      this.fileLog(logMessage);
    }
  }
  
  /**
   * Output colorized log to console
   */
  private colorizedConsoleLog(level: LogLevel, message: string): void {
    // ANSI color codes
    const colors = {
      reset: '\x1b[0m',
      bright: '\x1b[1m',
      dim: '\x1b[2m',
      blue: '\x1b[34m',    // Debug
      green: '\x1b[32m',   // Info
      yellow: '\x1b[33m',  // Warn
      red: '\x1b[31m'      // Error
    };
    
    let color;
    switch (level) {
      case LogLevel.DEBUG:
        color = colors.blue;
        break;
      case LogLevel.INFO:
        color = colors.green;
        break;
      case LogLevel.WARN:
        color = colors.yellow;
        break;
      case LogLevel.ERROR:
        color = colors.red;
        break;
      default:
        color = colors.reset;
    }
    
    console.log(`${color}${message}${colors.reset}`);
  }
  
  /**
   * Output log to file
   */
  private fileLog(message: string): void {
    // In a real implementation, this would append to the log file
    // For example:
    // const fs = require('fs');
    // fs.appendFileSync(this.config.logFilePath, message + '\n');
    
    // For this mock implementation, we'll do nothing
  }
}

// Create and export a default logger instance
export const log = new Logger();

// Export the Logger class for creating custom loggers
export { Logger };
