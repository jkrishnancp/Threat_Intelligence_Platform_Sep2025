import os
import psycopg2
from psycopg2.extras import Json
conn = psycopg2.connect(os.getenv('DATABASE_URL'))
conn.autocommit = True

def upsert_cve(cve, kev_ids):
    cve_id = cve.get('id') or cve.get('CVE',{}).get('CVE_data_meta',{}).get('ID')
    if not cve_id: return
    metrics = (cve.get('metrics') or {}).get('cvssMetricV31') or []
    score = severity = None
    if metrics:
        m = metrics[0].get('cvssData', {})
        score = m.get('baseScore'); severity = m.get('baseSeverity')
    cwes = []
    for p in cve.get('weaknesses', []):
        for d in p.get('description', []):
            if d.get('value'): cwes.append(d['value'])
    cpes = []
    for c in cve.get('configurations', []):
        for n in c.get('nodes', []):
            for m in n.get('cpeMatch', []):
                if m.get('criteria'): cpes.append(m['criteria'])
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO "Cve" (id, publishedAt, modifiedAt, sourceRaw, cvssScore, cvssSeverity, cwes, cpes, isKev)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (id) DO UPDATE SET
          publishedAt=EXCLUDED.publishedAt,
          modifiedAt=EXCLUDED.modifiedAt,
          sourceRaw=EXCLUDED.sourceRaw,
          cvssScore=EXCLUDED.cvssScore,
          cvssSeverity=EXCLUDED.cvssSeverity,
          cwes=EXCLUDED.cwes,
          cpes=EXCLUDED.cpes,
          isKev=EXCLUDED.isKev
    """, (cve_id, cve.get('published'), cve.get('lastModified'), Json(cve), score, severity, cwes, cpes, cve_id in kev_ids))

def upsert_osv(v):
    vid = v.get('id')
    eco = pkg = None
    if v.get('affected'):
        a = v['affected'][0]
        eco = a.get('package',{}).get('ecosystem')
        pkg = a.get('package',{}).get('name')
    score = severity = None
    if v.get('severity'):
        sev = v['severity'][0]
        severity = sev.get('type')
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO "OsvVuln" (id, ecosystem, package, affected, sourceRaw, publishedAt, modifiedAt, cvssScore, cvssSeverity)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (id) DO UPDATE SET
          ecosystem=EXCLUDED.ecosystem,
          package=EXCLUDED.package,
          affected=EXCLUDED.affected,
          sourceRaw=EXCLUDED.sourceRaw,
          publishedAt=EXCLUDED.publishedAt,
          modifiedAt=EXCLUDED.modifiedAt,
          cvssScore=EXCLUDED.cvssScore,
          cvssSeverity=EXCLUDED.cvssSeverity
    """, (vid, eco, pkg, Json(v.get('affected')), Json(v), v.get('published'), v.get('modified'), score, severity))

def upsert_advisory(source, entry, summaries=None):
    title = getattr(entry,'title', None) or entry.get('title')
    link = getattr(entry,'link', None) or entry.get('link')
    guid = getattr(entry,'id', None) or entry.get('id') or link or title
    pub = getattr(entry,'published', None) or entry.get('published')
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO "Advisory" (id, source, title, link, publishedAt, sourceRaw, summary, summaryTech, tags)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (id) DO UPDATE SET
          source=EXCLUDED.source,
          title=EXCLUDED.title,
          link=EXCLUDED.link,
          publishedAt=EXCLUDED.publishedAt,
          sourceRaw=EXCLUDED.sourceRaw,
          summary=COALESCE(EXCLUDED.summary, "Advisory".summary),
          summaryTech=COALESCE(EXCLUDED.summaryTech, "Advisory".summaryTech)
    """, (guid, source, title, link, pub, Json(getattr(entry, '.__dict__', None) or dict(entry)), (summaries or {}).get('exec'), (summaries or {}).get('tech'), []))

def update_datasource_status(kind: str, status: str):
    cur = conn.cursor()
    cur.execute('UPDATE "DataSource" SET "lastRunAt" = NOW(), "lastStatus" = %s WHERE kind = %s', (status, kind))