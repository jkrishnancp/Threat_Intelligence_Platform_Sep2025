import os, json
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
from psycopg2.extras import RealDictCursor
import redis

INTERNAL = os.getenv('INTERNAL_SERVICE_TOKEN','changeme')

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

conn = psycopg2.connect(os.getenv('DATABASE_URL'))
conn.autocommit = True
r = redis.from_url(os.getenv('REDIS_URL','redis://redis:6379/0'))

@app.get('/health')
async def health():
    return {'ok': True}

@app.get('/admin/status')
async def status():
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT id, kind, label, "lastRunAt", "lastStatus" FROM "DataSource" ORDER BY kind')
    return {'dataSources': cur.fetchall()}

@app.post('/admin/run/{sourceKind}')
async def run_now(sourceKind: str, request: Request):
    token = request.query_params.get('token')
    if token != INTERNAL: raise HTTPException(401, 'Unauthorized')
    r.publish('manual_run', sourceKind.upper())
    return {'queued': sourceKind.upper()}

@app.get('/cves')
async def cves(query: str = '', severity: str = '', isKev: bool | None = None, limit: int = 50, offset: int = 0):
    cur = conn.cursor(cursor_factory=RealDictCursor)
    conds=[]; params=[]
    if query:
        conds.append('(id ILIKE %s OR sourceRaw::text ILIKE %s)'); params += [f'%{query}%', f'%{query}%']
    if severity:
        conds.append('"cvssSeverity" = %s'); params.append(severity)
    if isKev is not None:
        conds.append('"isKev" = %s'); params.append(isKev)
    where = ('WHERE ' + ' AND '.join(conds)) if conds else ''
    cur.execute(f'SELECT * FROM "Cve" {where} ORDER BY "modifiedAt" DESC NULLS LAST LIMIT %s OFFSET %s', params+[limit, offset])
    return {'items': cur.fetchall()}

@app.get('/advisories')
async def advisories(query: str = '', source: str = '', limit: int = 50, offset: int = 0):
    cur = conn.cursor(cursor_factory=RealDictCursor)
    conds=[]; params=[]
    if query:
        conds.append('(title ILIKE %s OR summary ILIKE %s OR summaryTech ILIKE %s)'); params += [f'%{query}%',]*3
    if source:
        conds.append('source = %s'); params.append(source)
    where = ('WHERE ' + ' AND '.join(conds)) if conds else ''
    cur.execute(f'SELECT * FROM "Advisory" {where} ORDER BY "publishedAt" DESC NULLS LAST LIMIT %s OFFSET %s', params+[limit, offset])
    return {'items': cur.fetchall()}