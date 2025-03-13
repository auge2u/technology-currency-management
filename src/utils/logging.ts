/**
 * Logging utility for technology currency management
 */

// Different log levels
type LogLevel = 'debug' | 'info' | 'warn' | 'error';

// Log entry structure
interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: Record<string, any>;
}

// Logger interface
interface Logger {
  debug(message: string, context?: Record<string, any>): void;
  info(message: string, context?: Record<string, any>): void;
  warn(message: string, context?: Record<string, any>): void;
  error(message: string, context?: Record<string, any>): void;
  setLevel(level: LogLevel): void;
  getEntries(): LogEntry[];
}

/**
 * Logger implementation for technology currency management
 */
class TechCurrencyLogger implements Logger {
  private level: LogLevel = 'info';
  private entries: LogEntry[] = [];
  private maxEntries: number = 1000;
  private outputToConsole: boolean = true;
  
  /**
   * Create a new logger instance
   * @param options Logger configuration options
   */
  constructor(options?: {
    level?: LogLevel;
    maxEntries?: number;
    outputToConsole?: boolean;
  }) {
    if (options) {
      if (options.level) {
        this.level = options.level;
      }
      if (options.maxEntries !== undefined) {
        this.maxEntries = options.maxEntries;
      }
      if (options.outputToConsole !== undefined) {
        this.outputToConsole = options.outputToConsole;
      }
    }
  }
  
  /**
   * Log a debug message
   * @param message Message to log
   * @param context Additional context data
   */
  debug(message: string, context?: Record<string, any>): void {
    this.log('debug', message, context);
  }
  
  /**
   * Log an info message
   * @param message Message to log
   * @param context Additional context data
   */
  info(message: string, context?: Record<string, any>): void {
    this.log('info', message, context);
  }
  
  /**
   * Log a warning message
   * @param message Message to log
   * @param context Additional context data
   */
  warn(message: string, context?: Record<string, any>): void {
    this.log('warn', message, context);
  }
  
  /**
   * Log an error message
   * @param message Message to log
   * @param context Additional context data
   */
  error(message: string, context?: Record<string, any>): void {
    this.log('error', message, context);
  }
  
  /**
   * Set the minimum log level
   * @param level Minimum log level
   */
  setLevel(level: LogLevel): void {
    this.level = level;
  }
  
  /**
   * Get all log entries
   * @returns Array of log entries
   */
  getEntries(): LogEntry[] {
    return this.entries;
  }
  
  /**
   * Get entries filtered by level
   * @param level Log level to filter by
   * @returns Filtered log entries
   */
  getEntriesByLevel(level: LogLevel): LogEntry[] {
    return this.entries.filter(entry => entry.level === level);
  }
  
  /**
   * Clear all log entries
   */
  clear(): void {
    this.entries = [];
  }
  
  /**
   * Export logs to JSON
   * @returns JSON string of log entries
   */
  exportToJson(): string {
    return JSON.stringify(this.entries, null, 2);
  }
  
  /**
   * Base log method used by all level-specific methods
   * @param level Log level
   * @param message Message to log
   * @param context Additional context data
   */
  private log(level: LogLevel, message: string, context?: Record<string, any>): void {
    // Check if this level should be logged based on minimum level
    if (!this.shouldLog(level)) {
      return;
    }
    
    const timestamp = new Date().toISOString();
    const entry: LogEntry = {
      timestamp,
      level,
      message,
      context
    };
    
    // Add to log entries, maintaining max size
    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.shift();
    }
    
    // Output to console if enabled
    if (this.outputToConsole) {
      this.outputToConsoleLog(entry);
    }
  }
  
  /**
   * Check if a log level should be processed
   * @param level Log level to check
   * @returns Whether the level should be logged
   */
  private shouldLog(level: LogLevel): boolean {
    const levelOrder: Record<LogLevel, number> = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3
    };
    
    return levelOrder[level] >= levelOrder[this.level];
  }
  
  /**
   * Output a log entry to the console
   * @param entry Log entry to output
   */
  private outputToConsoleLog(entry: LogEntry): void {
    const { timestamp, level, message, context } = entry;
    const prefix = `[${timestamp}] [${level.toUpperCase()}]`;
    
    switch (level) {
      case 'debug':
        console.debug(prefix, message, context || '');
        break;
      case 'info':
        console.info(prefix, message, context || '');
        break;
      case 'warn':
        console.warn(prefix, message, context || '');
        break;
      case 'error':
        console.error(prefix, message, context || '');
        break;
    }
  }
}

// Create and export a singleton instance
export const log = new TechCurrencyLogger();

// Export the types for consumers
export type { LogLevel, LogEntry, Logger };
