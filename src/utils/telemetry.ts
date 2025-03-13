import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-proto';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-proto';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { WinstonInstrumentation } from '@opentelemetry/instrumentation-winston';
import { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import { diag, DiagConsoleLogger, DiagLogLevel } from '@opentelemetry/api';
import config from '../config';

// Set up diagnostic logging for OpenTelemetry itself
if (config.environment === 'development') {
  diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.INFO);
}

// SDK instance to be used globally
let sdk: NodeSDK;

/**
 * Sets up OpenTelemetry instrumentation for tracing and metrics
 * @param serviceName The name of the service
 */
export function setupTelemetry(serviceName: string): void {
  // Define the resource with service info
  const resource = new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
    [SemanticResourceAttributes.SERVICE_VERSION]: process.env.npm_package_version || '0.0.0',
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: config.environment,
  });

  // Configure OTLP exporters if endpoints are provided
  // This is for distributed tracing with tools like Jaeger or Tempo
  const traceExporter = new OTLPTraceExporter({
    url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318/v1/traces',
  });
  
  // Setup metric exporters
  // OTLP for systems like OpenTelemetry Collector
  const metricExporter = new OTLPMetricExporter({
    url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318/v1/metrics',
  });

  // Prometheus for local scraping
  const prometheusExporter = new PrometheusExporter({
    port: config.telemetry.metricsPort, 
    endpoint: '/metrics',
    preventServerStart: false,
  });

  // Set up the SDK with auto-instrumentation
  sdk = new NodeSDK({
    resource,
    traceExporter,
    metricReader: new PeriodicExportingMetricReader({
      exporter: metricExporter,
      exportIntervalMillis: 15000, // Export metrics every 15 seconds
    }),
    instrumentations: [
      getNodeAutoInstrumentations(),
      new ExpressInstrumentation(),
      new HttpInstrumentation(),
      new WinstonInstrumentation(),
    ],
  });

  // Also set up Prometheus metrics endpoint
  sdk.addMetricReader(new PeriodicExportingMetricReader({
    exporter: prometheusExporter,
    exportIntervalMillis: 1000, // More frequent for Prometheus
  }));

  // Start the SDK
  sdk.start();

  // Register shutdown handler
  process.on('SIGTERM', () => {
    gracefulShutdown();
  });

  process.on('SIGINT', () => {
    gracefulShutdown();
  });
}

/**
 * Gracefully shuts down the OpenTelemetry SDK
 */
function gracefulShutdown(): void {
  if (sdk) {
    sdk
      .shutdown()
      .then(() => {
        console.log('Tracing and metrics terminated');
        process.exit(0);
      })
      .catch((error) => {
        console.error('Error shutting down OpenTelemetry', error);
        process.exit(1);
      });
  } else {
    process.exit(0);
  }
}
