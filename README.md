# Technology Currency Management System (TCMS)

[![CI Status](https://github.com/habitusnet/technology-currency-management/workflows/CI/badge.svg)](https://github.com/habitusnet/technology-currency-management/actions)
[![License](https://img.shields.io/github/license/habitusnet/technology-currency-management)](LICENSE)

An enterprise-grade system for maintaining technological currency across the full technology stack. This system automates the monitoring, analysis, and remediation of outdated dependencies, frameworks, libraries, and system components.

## 🌟 Key Features

- **Automated Dependency Monitoring**: Continuously scan codebases, dependencies, frameworks, libraries, and system components to detect outdated or deprecated technologies
- **Security Vulnerability Detection**: Identify security vulnerabilities in outdated components with remediation pathways
- **Browser Extension Ecosystem Analysis**: Scan browser extensions (Chrome, Firefox, Safari, Edge) to identify update or replacement needs
- **Proactive Notification System**: Alert teams before technologies reach end-of-life or fall behind current standards
- **Version Control Integration**: Flag outdated dependencies in pull requests
- **Technical Debt Reporting**: Detailed reporting on technical debt related to outdated technologies
- **DevOps Pipeline Integration**: Seamlessly integrate with CI/CD pipelines
- **Comprehensive Dashboard**: Single view of technological currency status across the organization

## 🏗️ System Architecture

TCMS is built on a modular, microservices-based architecture with these key components:

### Core Components

- **Analyzer Services**: Scan different aspects of technology stack (dependencies, frameworks, extensions, security)
- **Resolver Services**: Provide remediation pathways for identified issues
- **Core Services**: Manage notifications, scheduling, reporting, and dashboard data
- **Integration Layer**: Connect to external tools (GitHub, Snyk, SonarQube, etc.)
- **API Layer**: RESTful API for system functionality
- **Dashboard UI**: Interactive frontend for visualizing and managing technology currency

### Technology Stack

- **Backend**: Node.js with TypeScript, Express
- **Frontend**: React, TypeScript, Material UI
- **Database**: PostgreSQL
- **Infrastructure**: Docker, Kubernetes
- **CI/CD**: GitHub Actions
- **Monitoring**: Prometheus, Grafana

## 📋 Prerequisites

- Node.js (v18 or higher)
- PostgreSQL (v14 or higher)
- Docker and Docker Compose
- Kubernetes cluster (for production deployment)
- GitHub account (for repository scanning and integration)

## 🚀 Getting Started

### Local Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/habitusnet/technology-currency-management.git
   cd technology-currency-management
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Configure environment variables**

   Create a `.env` file in the root directory based on `.env.example`:

   ```bash
   cp .env.example .env
   # Edit the .env file with your configuration
   ```

4. **Start the development environment**

   ```bash
   # Start PostgreSQL database using Docker
   docker-compose up -d postgres
   
   # Run database migrations
   npm run migrate
   
   # Start the development server
   npm run dev
   ```

5. **Access the application**

   - API: http://localhost:3000
   - Dashboard UI: http://localhost:3001

### Docker Setup

To run the entire application using Docker:

```bash
docker-compose up -d
```

## 🔧 Configuration

TCMS can be configured through environment variables and configuration files:

- **Environment Variables**: Control database connections, service ports, and external API credentials
- **Configuration Files**: Define scanning rules, notification preferences, and remediation strategies

See the [Configuration Guide](docs/configuration.md) for detailed options.

## 🧪 Testing

```bash
# Run all tests
npm test

# Run unit tests
npm run test:unit

# Run integration tests
npm run test:integration

# Run end-to-end tests
npm run test:e2e
```

## 📦 Deployment

### Production Deployment with Kubernetes

1. **Build Docker images**

   ```bash
   docker build -t habitusnet/tcms-api:latest -f infra/docker/Dockerfile .
   docker build -t habitusnet/tcms-worker:latest -f infra/docker/Dockerfile.worker .
   ```

2. **Push images to registry**

   ```bash
   docker push habitusnet/tcms-api:latest
   docker push habitusnet/tcms-worker:latest
   ```

3. **Deploy to Kubernetes**

   ```bash
   kubectl apply -k infra/kubernetes/overlays/prod
   ```

See the [Deployment Guide](docs/deployment.md) for detailed deployment instructions.

## 📚 Documentation

- [API Documentation](docs/api/README.md)
- [Configuration Guide](docs/configuration.md)
- [Development Guide](docs/development/README.md)
- [Deployment Guide](docs/deployment.md)
- [Architecture Design](docs/architecture/README.md)
- [Integration Guide](docs/integrations/README.md)

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [Platform Engineering Visualizer](https://github.com/habitusnet/platform-engineering-visualizer)
- [Auto Pipeline Crafter](https://github.com/habitusnet/auto-pipeline-crafter)
