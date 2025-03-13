import winston from 'winston';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { WinstonTransport } from '@opentelemetry/instrumentation-winston';
import { trace, context, SpanStatusCode } from '@opentelemetry/api';
import config from '../config';

// Create custom format for console output
const consoleFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.colorize(),
  winston.format.printf(({ level, message, timestamp, ...meta }) => {
    return `${timestamp} ${level}: ${message} ${Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''}`;
  })
);

// Create OpenTelemetry-compatible format for structured logging
const otelFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.json()
);

// Create Winston logger
const logger = winston.createLogger({
  level: config.logging.level || 'info',
  defaultMeta: {
    service: 'tcms',
    environment: config.environment
  },
  transports: [
    new winston.transports.Console({
      format: config.environment === 'production' ? otelFormat : consoleFormat
    })
  ]
});

// Add additional transports based on environment
if (config.environment === 'production') {
  // Add OpenTelemetry transport
  logger.add(new WinstonTransport());
  
  // Add file transport for error logs
  logger.add(
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: otelFormat
    })
  );
}

// Create wrapper methods with trace context
export const log = {
  info: (message: string, meta = {}) => {
    const span = trace.getActiveSpan();
    if (span) {
      Object.entries(meta).forEach(([key, value]) => {
        span.setAttribute(`app.log.${key}`, String(value));
      });
    }
    logger.info(message, meta);
  },
  
  warn: (message: string, meta = {}) => {
    const span = trace.getActiveSpan();
    if (span) {
      Object.entries(meta).forEach(([key, value]) => {
        span.setAttribute(`app.log.${key}`, String(value));
      });
    }
    logger.warn(message, meta);
  },
  
  error: (message: string, meta = {}) => {
    const span = trace.getActiveSpan();
    if (span) {
      span.setStatus({ code: SpanStatusCode.ERROR });
      Object.entries(meta).forEach(([key, value]) => {
        span.setAttribute(`app.log.${key}`, String(value));
      });
      if (meta['error'] instanceof Error) {
        span.recordException(meta['error'] as Error);
      }
    }
    logger.error(message, meta);
  },
  
  debug: (message: string, meta = {}) => {
    const span = trace.getActiveSpan();
    if (span) {
      Object.entries(meta).forEach(([key, value]) => {
        span.setAttribute(`app.log.${key}`, String(value));
      });
    }
    logger.debug(message, meta);
  }
};
