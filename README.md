# Threat Intelligence Platform (Phase 1)

## Quick start
1) Copy `.env.example` to `.env` and set values.
2) Install Prisma CLI locally: `npm i -g prisma` or use npx.
3) Run migrations: `npx prisma migrate dev --schema packages/db/prisma/schema.prisma`
4) Start stack: `docker compose up --build`
5) Visit http://localhost:3000/admin/jobs and click "Refresh RSS" or "Refresh NVD".

## Services
- Next.js web (apps/web)
- FastAPI (apps/api)
- Celery worker + beat (workers/etl)
- Postgres, Redis

## API
- GET /health
- GET /admin/status
- POST /admin/run/{sourceKind}?token=INTERNAL_SERVICE_TOKEN
- GET /cves
- GET /advisories