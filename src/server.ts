import express, { Express } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { apiRoutes } from './api/routes';
import { errorHandler } from './api/middleware/error-handler';
import { log } from './utils/logging';
import config from './config';

export function setupServer(): Express {
  const app = express();

  // Security middleware
  app.use(helmet());
  app.use(cors({
    origin: config.security.corsOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  }));

  // Apply rate limiting
  const limiter = rateLimit({
    windowMs: config.security.rateLimitWindowMs,
    max: config.security.rateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again later.'
  });
  app.use(limiter);

  // Request parsing middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  
  // Compression middleware
  app.use(compression());

  // Logging middleware
  if (config.environment !== 'test') {
    app.use(morgan('combined', {
      stream: {
        write: (message: string) => {
          log.info(message.trim());
        }
      }
    }));
  }

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // API routes
  app.use(config.server.apiPrefix, apiRoutes);

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({ message: 'Resource not found' });
  });

  // Error handling middleware
  app.use(errorHandler);

  return app;
}
