import { Request, Response, NextFunction } from 'express';
import { trace } from '@opentelemetry/api';
import { log } from '../../utils/logging';
import config from '../../config';

// Custom error classes
export class ApiError extends Error {
  statusCode: number;
  errorCode: string;
  details?: Record<string, any>;

  constructor(statusCode: number, message: string, errorCode: string, details?: Record<string, any>) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.name = 'ApiError';
    Object.setPrototypeOf(this, ApiError.prototype);
  }

  static badRequest(message: string, details?: Record<string, any>) {
    return new ApiError(400, message, 'BAD_REQUEST', details);
  }

  static unauthorized(message: string = 'Unauthorized', details?: Record<string, any>) {
    return new ApiError(401, message, 'UNAUTHORIZED', details);
  }

  static forbidden(message: string = 'Forbidden', details?: Record<string, any>) {
    return new ApiError(403, message, 'FORBIDDEN', details);
  }

  static notFound(message: string = 'Resource not found', details?: Record<string, any>) {
    return new ApiError(404, message, 'NOT_FOUND', details);
  }

  static conflict(message: string, details?: Record<string, any>) {
    return new ApiError(409, message, 'CONFLICT', details);
  }

  static internal(message: string = 'Internal server error', details?: Record<string, any>) {
    return new ApiError(500, message, 'INTERNAL_SERVER_ERROR', details);
  }

  static serviceUnavailable(message: string = 'Service temporarily unavailable', details?: Record<string, any>) {
    return new ApiError(503, message, 'SERVICE_UNAVAILABLE', details);
  }
}

// Global error handler middleware
export const errorHandler = (err: Error, req: Request, res: Response, next: NextFunction) => {
  // Get current span for adding error attributes
  const span = trace.getActiveSpan();
  
  // Default to 500 internal server error
  let statusCode = 500;
  let errorCode = 'INTERNAL_SERVER_ERROR';
  let errorMessage = 'Internal server error';
  let errorDetails: Record<string, any> | undefined;

  // Handle known error types
  if (err instanceof ApiError) {
    statusCode = err.statusCode;
    errorCode = err.errorCode;
    errorMessage = err.message;
    errorDetails = err.details;
  } else if (err.name === 'ValidationError') {
    // Handle validation errors (e.g., from a validation library)
    statusCode = 400;
    errorCode = 'VALIDATION_ERROR';
    errorMessage = err.message;
  } else if (err.name === 'SyntaxError' && (err as any).status === 400) {
    // Handle JSON parsing errors
    statusCode = 400;
    errorCode = 'INVALID_JSON';
    errorMessage = 'Invalid JSON payload';
  } else {
    // For unknown errors, use generic message in production
    errorMessage = config.environment === 'production' ? 'Internal server error' : err.message;
  }

  // Add error to span
  if (span) {
    span.setAttribute('error.type', err.name);
    span.setAttribute('error.message', err.message);
    span.setAttribute('error.code', errorCode);
    span.setAttribute('http.status_code', statusCode);
  }

  // Log the error (only detailed in non-production)
  const logData = {
    error: err,
    requestId: req.headers['x-request-id'] || 'unknown',
    path: req.path,
    method: req.method,
    statusCode,
    errorCode,
    ...(config.environment !== 'production' && { stack: err.stack })
  };

  log.error(`Request error: ${errorMessage}`, logData);

  // Send error response
  const errorResponse = {
    error: {
      code: errorCode,
      message: errorMessage,
      ...(errorDetails && { details: errorDetails }),
      ...(config.environment !== 'production' && { stack: err.stack })
    },
    requestId: req.headers['x-request-id'] || 'unknown',
    timestamp: new Date().toISOString()
  };

  res.status(statusCode).json(errorResponse);
};
