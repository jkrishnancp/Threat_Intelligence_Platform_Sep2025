from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os
import psycopg2
import redis
import json
from datetime import datetime, timedelta
from celery import Celery

app = FastAPI(title="Threat Intelligence Platform API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Database connection
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Redis client for Celery
redis_client = redis.from_url(REDIS_URL)

# Celery client
celery_app = Celery(
    "tip_api",
    broker=REDIS_URL,
    backend=REDIS_URL
)

# Pydantic models
class HealthResponse(BaseModel):
    status: str
    timestamp: datetime

class DataSourceStatus(BaseModel):
    id: str
    kind: str
    label: str
    lastRunAt: Optional[datetime]
    lastStatus: Optional[str]

class AdminStatusResponse(BaseModel):
    dataSources: List[DataSourceStatus]

class CreateDataSourceRequest(BaseModel):
    kind: str
    label: str
    configJson: Optional[Dict[str, Any]] = None

class CVEResponse(BaseModel):
    id: str
    description: str
    severity: Optional[str]
    baseScore: Optional[float]
    isKev: bool
    publishedAt: Optional[datetime]
    cweIds: List[str]
    cpes: List[str]

class OSVResponse(BaseModel):
    id: str
    ecosystem: Optional[str]
    packageName: Optional[str]
    summary: str
    severity: Optional[str]
    publishedAt: Optional[datetime]

class AdvisoryResponse(BaseModel):
    id: str
    title: str
    summary: Optional[str]
    summaryTech: Optional[str]
    source: str
    sourceUrl: Optional[str]
    publishedAt: Optional[datetime]

def get_db_connection():
    """Get database connection"""
    return psycopg2.connect(DATABASE_URL)

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token - simplified for demo"""
    # In production, this would verify NextAuth JWT tokens
    token = credentials.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="ok",
        timestamp=datetime.utcnow()
    )

@app.get("/admin/status", response_model=AdminStatusResponse)
async def get_admin_status(token: str = Depends(verify_token)):
    """Get data source status for admin panel"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, kind, label, "lastRunAt", "lastStatus"
                FROM data_sources
                WHERE enabled = true
                ORDER BY kind
            """)
            rows = cur.fetchall()
            
            data_sources = []
            for row in rows:
                data_sources.append(DataSourceStatus(
                    id=row[0],
                    kind=row[1],
                    label=row[2],
                    lastRunAt=row[3],
                    lastStatus=row[4]
                ))
            
            return AdminStatusResponse(dataSources=data_sources)
    finally:
        conn.close()

@app.post("/admin/run/{source_kind}")
async def trigger_source_run(source_kind: str, token: str = Depends(verify_token)):
    """Trigger immediate run of a data source"""
    valid_kinds = ["NVD", "OSV", "GHSA", "RSS", "MSRC", "CISA_KEV"]
    
    if source_kind not in valid_kinds:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source kind. Must be one of: {', '.join(valid_kinds)}"
        )
    
    # Check rate limiting (2 minutes)
    rate_key = f"rate_limit:{source_kind}"
    if redis_client.exists(rate_key):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please wait 2 minutes between manual runs."
        )
    
    # Set rate limit
    redis_client.setex(rate_key, 120, "1")
    
    # Trigger Celery task based on source kind
    task_map = {
        "NVD": "tasks.task_nvd_pull",
        "OSV": "tasks.task_osv_pull", 
        "GHSA": "tasks.task_ghsa_pull",
        "RSS": "tasks.task_rss_pull_all",
        "MSRC": "tasks.task_msrc_pull",
        "CISA_KEV": "tasks.task_cisa_kev_sync"
    }
    
    task_name = task_map[source_kind]
    result = celery_app.send_task(task_name)
    
    return {"message": f"Triggered {source_kind} data pull", "task_id": result.id}

@app.post("/datasources")
async def create_data_source(request: CreateDataSourceRequest, token: str = Depends(verify_token)):
    """Create a new data source (RSS or MSRC)"""
    if request.kind not in ["RSS", "MSRC"]:
        raise HTTPException(
            status_code=400,
            detail="Only RSS and MSRC data sources can be created via API"
        )
    
    # For demo purposes, using hardcoded org_id
    # In production, this would come from the authenticated user's context
    org_id = "default_org"
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO data_sources (id, "orgId", kind, label, enabled, "configJson", "createdAt", "updatedAt")
                VALUES (gen_random_uuid(), %s, %s, %s, true, %s, NOW(), NOW())
                RETURNING id
            """, (org_id, request.kind, request.label, json.dumps(request.configJson) if request.configJson else None))
            
            source_id = cur.fetchone()[0]
            conn.commit()
            
            return {"id": source_id, "message": "Data source created successfully"}
    finally:
        conn.close()

@app.get("/cves")
async def get_cves(
    query: Optional[str] = None,
    severity: Optional[str] = None,
    isKev: Optional[bool] = None,
    skip: int = 0,
    limit: int = 50,
    token: str = Depends(verify_token)
):
    """Get paginated list of CVEs with filters"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            where_conditions = []
            params = []
            
            if query:
                where_conditions.append("(id ILIKE %s OR description ILIKE %s)")
                params.extend([f"%{query}%", f"%{query}%"])
            
            if severity:
                where_conditions.append("severity = %s")
                params.append(severity)
                
            if isKev is not None:
                where_conditions.append('"isKev" = %s')
                params.append(isKev)
            
            where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
            
            # Get total count
            cur.execute(f"SELECT COUNT(*) FROM cves WHERE {where_clause}", params)
            total = cur.fetchone()[0]
            
            # Get paginated results
            cur.execute(f"""
                SELECT id, description, severity, "baseScore", "isKev", "publishedAt", "cweIds", cpes
                FROM cves
                WHERE {where_clause}
                ORDER BY "publishedAt" DESC NULLS LAST
                LIMIT %s OFFSET %s
            """, params + [limit, skip])
            
            rows = cur.fetchall()
            cves = []
            
            for row in rows:
                cves.append(CVEResponse(
                    id=row[0],
                    description=row[1],
                    severity=row[2],
                    baseScore=row[3],
                    isKev=row[4],
                    publishedAt=row[5],
                    cweIds=row[6] or [],
                    cpes=row[7] or []
                ))
            
            return {
                "data": cves,
                "total": total,
                "skip": skip,
                "limit": limit
            }
    finally:
        conn.close()

@app.get("/osv")
async def get_osv_vulns(
    query: Optional[str] = None,
    ecosystem: Optional[str] = None,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    token: str = Depends(verify_token)
):
    """Get paginated list of OSV vulnerabilities with filters"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            where_conditions = []
            params = []
            
            if query:
                where_conditions.append("(id ILIKE %s OR summary ILIKE %s OR \"packageName\" ILIKE %s)")
                params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])
            
            if ecosystem:
                where_conditions.append("ecosystem = %s")
                params.append(ecosystem)
                
            if severity:
                where_conditions.append("severity = %s")
                params.append(severity)
            
            where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
            
            # Get total count
            cur.execute(f'SELECT COUNT(*) FROM "osv_vulns" WHERE {where_clause}', params)
            total = cur.fetchone()[0]
            
            # Get paginated results
            cur.execute(f"""
                SELECT id, ecosystem, "packageName", summary, severity, "publishedAt"
                FROM "osv_vulns"
                WHERE {where_clause}
                ORDER BY "publishedAt" DESC NULLS LAST
                LIMIT %s OFFSET %s
            """, params + [limit, skip])
            
            rows = cur.fetchall()
            vulns = []
            
            for row in rows:
                vulns.append(OSVResponse(
                    id=row[0],
                    ecosystem=row[1],
                    packageName=row[2],
                    summary=row[3],
                    severity=row[4],
                    publishedAt=row[5]
                ))
            
            return {
                "data": vulns,
                "total": total,
                "skip": skip,
                "limit": limit
            }
    finally:
        conn.close()

@app.get("/advisories")
async def get_advisories(
    query: Optional[str] = None,
    source: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    token: str = Depends(verify_token)
):
    """Get paginated list of advisories with filters"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            where_conditions = []
            params = []
            
            if query:
                where_conditions.append("(title ILIKE %s OR content ILIKE %s)")
                params.extend([f"%{query}%", f"%{query}%"])
            
            if source:
                where_conditions.append("source = %s")
                params.append(source)
            
            where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
            
            # Get total count
            cur.execute(f"SELECT COUNT(*) FROM advisories WHERE {where_clause}", params)
            total = cur.fetchone()[0]
            
            # Get paginated results
            cur.execute(f"""
                SELECT id, title, summary, "summaryTech", source, "sourceUrl", "publishedAt"
                FROM advisories
                WHERE {where_clause}
                ORDER BY "publishedAt" DESC NULLS LAST
                LIMIT %s OFFSET %s
            """, params + [limit, skip])
            
            rows = cur.fetchall()
            advisories = []
            
            for row in rows:
                advisories.append(AdvisoryResponse(
                    id=row[0],
                    title=row[1],
                    summary=row[2],
                    summaryTech=row[3],
                    source=row[4],
                    sourceUrl=row[5],
                    publishedAt=row[6]
                ))
            
            return {
                "data": advisories,
                "total": total,
                "skip": skip,
                "limit": limit
            }
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)