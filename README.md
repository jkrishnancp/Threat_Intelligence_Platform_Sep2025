# Threat Intelligence Platform - Phase 1 Foundation

A comprehensive threat intelligence platform built with a modern microservices architecture, featuring automated data ingestion from multiple security feeds, AI-powered analysis, and role-based access control.

## Architecture

### Monorepo Structure
```
├── apps/
│   ├── web/          # Next.js frontend (App Router, TypeScript, Tailwind)
│   └── api/          # FastAPI backend
├── workers/
│   └── etl/          # Celery workers for data ingestion
├── packages/
│   └── db/           # Prisma schema and client
└── docker-compose.yml
```

### Tech Stack
- **Frontend**: Next.js 14, TypeScript, Tailwind CSS, shadcn/ui
- **Backend**: FastAPI, Python 3.11
- **Database**: PostgreSQL with Prisma
- **Cache/Queue**: Redis
- **Workers**: Celery with Redis broker
- **Auth**: NextAuth.js with magic link authentication
- **AI**: Claude API for content summarization
- **Deployment**: Docker Compose

## Features

### 🔐 Authentication & RBAC
- Magic link authentication (email-based)
- Organization-based multi-tenancy
- Role-based access control (OWNER, ADMIN, ANALYST, VIEWER)
- User invitation system

### 📊 Data Sources
- **NVD**: National Vulnerability Database CVEs
- **OSV.dev**: Open source vulnerability database
- **GitHub Security Advisories**: GHSA feed
- **CISA KEV**: Known Exploited Vulnerabilities
- **RSS Feeds**: Configurable RSS/Atom feeds
- **MSRC**: Microsoft Security Response Center (optional)

### 🤖 AI-Powered Analysis
- Executive summaries (≤80 words) for business stakeholders
- Technical bullet-point summaries for security teams
- Powered by Claude API with automatic content analysis

### ⚡ Automated Processing
- 8-hour scheduled data ingestion from all sources
- Delta updates using last-run timestamps
- Robust retry mechanisms with exponential backoff
- Rate limiting compliance for external APIs

### 🎨 Modern UI
- Custom color palette with professional branding
- Responsive design for all devices
- Advanced filtering and search capabilities
- Real-time dashboard with threat metrics
- Admin panel for data source management

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Node.js 18+ (for local development)
- pnpm (recommended package manager)

### Environment Setup
1. Copy the environment template:
   ```bash
   cp .env.example .env
   ```

2. Update `.env` with your configuration:
   ```bash
   # Required for AI summaries
   CLAUDE_API_KEY=your-claude-api-key
   
   # Optional for GitHub Security Advisories
   GITHUB_TOKEN=your-github-token
   
   # Email configuration for magic links
   EMAIL_SERVER_HOST=smtp.gmail.com
   EMAIL_SERVER_USER=your-email@example.com
   EMAIL_SERVER_PASSWORD=your-app-password
   EMAIL_FROM=tip-noreply@your-domain.com
   ```

### Development Setup

#### Full Stack (Docker)
```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Stop services
docker compose down
```

#### Local Development
```bash
# Install dependencies
pnpm install

# Generate Prisma client
pnpm db:generate

# Start database and Redis
docker compose up -d db redis

# Run database migrations
pnpm db:migrate

# Seed initial data
pnpm db:seed

# Start development servers
pnpm dev
```

### First Login
After seeding the database, you can sign in with:
- Email: `admin@example.com`
- The system will send a magic link to this email (configure email settings first)

## API Documentation

### Authentication
All API endpoints (except `/health`) require JWT authentication via the `Authorization: Bearer <token>` header.

### Core Endpoints

#### Health Check
```http
GET /health
```

#### Admin Status
```http
GET /admin/status
```
Returns status of all data sources with last run timestamps.

#### Trigger Manual Refresh
```http
POST /admin/run/{sourceKind}
```
Where `sourceKind` is one of: `NVD`, `OSV`, `GHSA`, `RSS`, `MSRC`, `CISA_KEV`

Rate limited to once per 2 minutes per source.

#### Data Queries
```http
# CVEs with filtering
GET /cves?query=&severity=&isKev=&skip=0&limit=50

# OSV Vulnerabilities
GET /osv?query=&ecosystem=&severity=&skip=0&limit=50

# Security Advisories  
GET /advisories?query=&source=&skip=0&limit=50
```

#### Data Source Management
```http
# Create RSS or MSRC data source
POST /datasources
Content-Type: application/json

{
  "kind": "RSS",
  "label": "CISA Current Activity",
  "configJson": {
    "url": "https://www.cisa.gov/news.xml"
  }
}
```

## Database Schema

### Core Models
- **Org**: Organizations with multi-tenancy support
- **User**: User accounts with email authentication
- **UserOrg**: User-organization relationships with roles
- **DataSource**: Configured data sources with scheduling info

### Threat Intelligence Data
- **Cve**: CVE records from NVD with CVSS scoring
- **OsvVuln**: Open source vulnerabilities from OSV.dev
- **Advisory**: Security advisories with AI-generated summaries

### Key Features
- UUID primary keys for security
- Audit timestamps on all records
- JSON configuration storage for flexible data sources
- Array fields for CWE IDs and CPE strings
- AI-generated summary fields

## Monitoring & Operations

### Health Checks
- All services include Docker health checks
- Database connectivity verification
- Redis connectivity verification
- API endpoint monitoring

### Logging
- Structured logging throughout the application
- Celery task execution logs
- API request/response logging
- Error tracking and alerting

### Scaling Considerations
- Horizontal scaling supported for web and API services
- Celery workers can be scaled independently
- Database connection pooling configured
- Redis clustering support for high availability

## Security Features

### Data Protection
- Organization-scoped data isolation
- Row-level security policies
- Input validation and sanitization
- SQL injection protection via parameterized queries

### Access Control
- JWT-based API authentication
- Role-based route protection
- Server-side authorization checks
- Rate limiting on sensitive endpoints

### External API Security
- API key management through environment variables
- Request timeout configuration
- Retry limits and circuit breaker patterns
- User-Agent identification for API calls

## Testing

### Unit Tests
```bash
# Run API tests
cd apps/api
python -m pytest

# Run frontend tests  
cd apps/web
npm run test
```

### Integration Tests
```bash
# Test full data ingestion pipeline
docker compose exec worker celery -A tasks call tasks.task_nvd_pull

# Verify database updates
docker compose exec db psql -U postgres -d tip -c "SELECT COUNT(*) FROM cves;"
```

## Deployment

### Production Configuration
1. Update environment variables for production:
   - Set secure `NEXTAUTH_SECRET`
   - Configure production email settings
   - Add external API keys
   - Set up SSL termination

2. Database considerations:
   - Use managed PostgreSQL service
   - Enable connection pooling
   - Configure backup schedules
   - Set up monitoring

3. Scaling recommendations:
   - Use container orchestration (Kubernetes/ECS)
   - Implement load balancing for web services
   - Scale Celery workers based on queue depth
   - Use Redis cluster for high availability

### Infrastructure as Code
The platform is designed to be easily deployed using:
- Docker Compose for development and small deployments
- Kubernetes manifests for production scaling
- Terraform modules for cloud infrastructure
- Ansible playbooks for configuration management

## Contributing

### Development Workflow
1. Create feature branches from `main`
2. Follow conventional commit messages
3. Add unit tests for new functionality
4. Update documentation as needed
5. Submit pull requests for review

### Code Standards
- TypeScript strict mode enabled
- ESLint and Prettier configuration
- Python Black formatting
- Prisma schema validation
- Docker best practices

## Roadmap

### Phase 2 Enhancements
- [ ] Real-time WebSocket notifications
- [ ] Advanced threat correlation
- [ ] Custom dashboard widgets
- [ ] Report generation and scheduling
- [ ] MISP integration
- [ ] STIX/TAXII support

### Phase 3 Enterprise Features
- [ ] Single Sign-On (SSO) integration
- [ ] Advanced analytics and ML models
- [ ] Threat hunting workbench
- [ ] API rate limiting and quotas
- [ ] Multi-region deployment
- [ ] Compliance reporting (SOC2, ISO27001)

## License

MIT License - see LICENSE file for details.

## Support

For questions, bug reports, or feature requests:
1. Check the documentation
2. Search existing GitHub issues
3. Create a new issue with detailed information
4. Contact the development team

---

Built with ❤️ for the cybersecurity community