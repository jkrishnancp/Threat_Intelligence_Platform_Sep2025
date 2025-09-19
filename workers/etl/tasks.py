import os
import time
import json
import requests
import feedparser
import psycopg2
from datetime import datetime, timedelta
from celery import Celery
from celery.schedules import crontab
import logging
from typing import Dict, List, Optional, Any
import csv
from io import StringIO

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Celery app configuration
app = Celery('tip_etl')
app.conf.broker_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
app.conf.result_backend = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Celery Beat schedule - run every 8 hours
app.conf.beat_schedule = {
    'nvd-pull': {
        'task': 'tasks.task_nvd_pull',
        'schedule': crontab(minute=0, hour='*/8'),
    },
    'osv-pull': {
        'task': 'tasks.task_osv_pull', 
        'schedule': crontab(minute=15, hour='*/8'),
    },
    'ghsa-pull': {
        'task': 'tasks.task_ghsa_pull',
        'schedule': crontab(minute=30, hour='*/8'),
    },
    'cisa-kev-sync': {
        'task': 'tasks.task_cisa_kev_sync',
        'schedule': crontab(minute=45, hour='*/8'),
    },
    'rss-pull-all': {
        'task': 'tasks.task_rss_pull_all',
        'schedule': crontab(minute=0, hour='*/8'),
    },
}
app.conf.timezone = 'UTC'

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL')
CLAUDE_API_KEY = os.getenv('CLAUDE_API_KEY')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')

def get_db_connection():
    """Get database connection"""
    return psycopg2.connect(DATABASE_URL)

def update_data_source_status(source_kind: str, status: str):
    """Update data source last run status"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE data_sources 
                SET "lastRunAt" = NOW(), "lastStatus" = %s, "updatedAt" = NOW()
                WHERE kind = %s
            """, (status, source_kind))
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to update data source status: {e}")
        conn.rollback()
    finally:
        conn.close()

def get_claude_summaries(content: str) -> Dict[str, str]:
    """Generate executive and technical summaries using Claude"""
    if not CLAUDE_API_KEY or not content:
        return {"summary": "", "summaryTech": ""}
    
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
        
        prompt = f"""
        Please analyze this security advisory and provide two summaries:

        1. Executive Summary (≤80 words): A brief, business-focused overview for executives
        2. Technical Summary: Key technical points in bullet format for security teams

        Content:
        {content[:4000]}  # Limit content length

        Format your response as:
        EXECUTIVE: [executive summary]
        TECHNICAL: [bullet points]
        """
        
        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        
        text = response.content[0].text
        lines = text.split('\n')
        
        exec_summary = ""
        tech_summary = ""
        current_section = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('EXECUTIVE:'):
                exec_summary = line.replace('EXECUTIVE:', '').strip()
                current_section = 'exec'
            elif line.startswith('TECHNICAL:'):
                tech_summary = line.replace('TECHNICAL:', '').strip()
                current_section = 'tech'
            elif current_section == 'exec' and line:
                exec_summary += ' ' + line
            elif current_section == 'tech' and line:
                tech_summary += '\n' + line
        
        return {
            "summary": exec_summary[:300],  # Limit length
            "summaryTech": tech_summary[:1000]
        }
    except Exception as e:
        logger.error(f"Claude API error: {e}")
        return {"summary": "", "summaryTech": ""}

@app.task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 60})
def task_nvd_pull(self):
    """Pull CVE data from NVD"""
    logger.info("Starting NVD CVE pull")
    
    try:
        # Get last run time for delta updates
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT "lastRunAt" FROM data_sources 
                WHERE kind = 'NVD' AND enabled = true 
                LIMIT 1
            """)
            result = cur.fetchone()
            last_run = result[0] if result else datetime.now() - timedelta(days=7)
        conn.close()
        
        # Format dates for NVD API
        if last_run:
            start_date = last_run.strftime('%Y-%m-%dT%H:%M:%S.000')
        else:
            start_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000')
        
        end_date = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')
        
        # NVD API call with rate limiting
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'lastModStartDate': start_date,
            'lastModEndDate': end_date,
            'resultsPerPage': 2000
        }
        
        headers = {'User-Agent': 'TIP-Platform/1.0'}
        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        cves_processed = 0
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                for cve_item in data.get('vulnerabilities', []):
                    cve_data = cve_item.get('cve', {})
                    cve_id = cve_data.get('id')
                    
                    if not cve_id:
                        continue
                    
                    # Extract description
                    descriptions = cve_data.get('descriptions', [])
                    description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
                    
                    # Extract CVSS data
                    severity = None
                    base_score = None
                    vector = None
                    
                    metrics = cve_data.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss = metrics['cvssMetricV31'][0]['cvssData']
                        base_score = cvss.get('baseScore')
                        severity = cvss.get('baseSeverity')
                        vector = cvss.get('vectorString')
                    elif 'cvssMetricV3' in metrics:
                        cvss = metrics['cvssMetricV3'][0]['cvssData']
                        base_score = cvss.get('baseScore')
                        severity = cvss.get('baseSeverity')
                        vector = cvss.get('vectorString')
                    
                    # Extract CWE IDs
                    cwe_ids = []
                    weaknesses = cve_data.get('weaknesses', [])
                    for weakness in weaknesses:
                        for desc in weakness.get('description', []):
                            if desc.get('lang') == 'en':
                                cwe_ids.append(desc.get('value', ''))
                    
                    # Extract CPEs
                    cpes = []
                    configurations = cve_data.get('configurations', [])
                    for config in configurations:
                        for node in config.get('nodes', []):
                            for cpe_match in node.get('cpeMatch', []):
                                if cpe_match.get('vulnerable'):
                                    cpes.append(cpe_match.get('criteria', ''))
                    
                    published_at = None
                    if cve_data.get('published'):
                        try:
                            published_at = datetime.fromisoformat(cve_data['published'].replace('Z', '+00:00'))
                        except:
                            pass
                    
                    # Upsert CVE
                    cur.execute("""
                        INSERT INTO cves (id, "orgId", description, severity, "baseScore", vector, "cweIds", cpes, "publishedAt", "updatedAt", "createdAt")
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                        ON CONFLICT (id) DO UPDATE SET
                        description = EXCLUDED.description,
                        severity = EXCLUDED.severity,
                        "baseScore" = EXCLUDED."baseScore",
                        vector = EXCLUDED.vector,
                        "cweIds" = EXCLUDED."cweIds",
                        cpes = EXCLUDED.cpes,
                        "publishedAt" = EXCLUDED."publishedAt",
                        "updatedAt" = NOW()
                    """, (
                        cve_id, 'default_org', description, severity, base_score,
                        vector, cwe_ids, cpes, published_at
                    ))
                    cves_processed += 1
                
                conn.commit()
        finally:
            conn.close()
        
        update_data_source_status('NVD', f'SUCCESS: {cves_processed} CVEs processed')
        logger.info(f"NVD pull completed: {cves_processed} CVEs processed")
        
        # Rate limiting - NVD recommends no more than 1 request per 6 seconds
        time.sleep(6)
        
    except Exception as e:
        error_msg = f'ERROR: {str(e)}'
        update_data_source_status('NVD', error_msg)
        logger.error(f"NVD pull failed: {e}")
        raise

@app.task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 60})
def task_osv_pull(self):
    """Pull vulnerability data from OSV.dev"""
    logger.info("Starting OSV vulnerability pull")
    
    try:
        ecosystems = ['npm', 'PyPI', 'Go', 'Maven', 'NuGet', 'RubyGems']
        vulns_processed = 0
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                for ecosystem in ecosystems:
                    # Query OSV API for recent vulnerabilities
                    url = "https://api.osv.dev/v1/query"
                    payload = {
                        "query": f"ecosystem:{ecosystem}",
                        "page_token": ""
                    }
                    
                    response = requests.post(url, json=payload, timeout=30)
                    response.raise_for_status()
                    
                    data = response.json()
                    
                    for vuln in data.get('vulns', [])[:50]:  # Limit to recent 50 per ecosystem
                        vuln_id = vuln.get('id')
                        if not vuln_id:
                            continue
                        
                        summary = vuln.get('summary', '')
                        
                        # Extract package info
                        package_name = None
                        affected = vuln.get('affected', [])
                        if affected:
                            package = affected[0].get('package', {})
                            package_name = package.get('name')
                        
                        # Extract severity (simplified)
                        severity = None
                        severity_data = vuln.get('severity', [])
                        if severity_data:
                            severity = severity_data[0].get('score', 'UNKNOWN')
                        
                        published_at = None
                        if vuln.get('published'):
                            try:
                                published_at = datetime.fromisoformat(vuln['published'].replace('Z', '+00:00'))
                            except:
                                pass
                        
                        # Upsert OSV vulnerability
                        cur.execute("""
                            INSERT INTO "osv_vulns" (id, "orgId", ecosystem, "packageName", summary, severity, "publishedAt", "updatedAt", "createdAt")
                            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                            ON CONFLICT (id) DO UPDATE SET
                            ecosystem = EXCLUDED.ecosystem,
                            "packageName" = EXCLUDED."packageName",
                            summary = EXCLUDED.summary,
                            severity = EXCLUDED.severity,
                            "publishedAt" = EXCLUDED."publishedAt",
                            "updatedAt" = NOW()
                        """, (
                            vuln_id, 'default_org', ecosystem, package_name,
                            summary, severity, published_at
                        ))
                        vulns_processed += 1
                    
                    # Rate limiting
                    time.sleep(1)
                
                conn.commit()
        finally:
            conn.close()
        
        update_data_source_status('OSV', f'SUCCESS: {vulns_processed} vulnerabilities processed')
        logger.info(f"OSV pull completed: {vulns_processed} vulnerabilities processed")
        
    except Exception as e:
        error_msg = f'ERROR: {str(e)}'
        update_data_source_status('OSV', error_msg)
        logger.error(f"OSV pull failed: {e}")
        raise

@app.task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 60})
def task_ghsa_pull(self):
    """Pull GitHub Security Advisories"""
    logger.info("Starting GHSA pull")
    
    if not GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN not set, skipping GHSA pull")
        update_data_source_status('GHSA', 'SKIPPED: No GitHub token configured')
        return
    
    try:
        # GraphQL query to get recent advisories
        query = """
        query {
          securityAdvisories(first: 50, orderBy: {field: UPDATED_AT, direction: DESC}) {
            nodes {
              id
              summary
              description
              permalink
              publishedAt
              updatedAt
              severity
              identifiers {
                type
                value
              }
            }
          }
        }
        """
        
        headers = {
            'Authorization': f'Bearer {GITHUB_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            'https://api.github.com/graphql',
            json={'query': query},
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        advisories_processed = 0
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                for advisory in data['data']['securityAdvisories']['nodes']:
                    ghsa_id = advisory.get('id')
                    summary = advisory.get('summary', '')
                    description = advisory.get('description', '')
                    permalink = advisory.get('permalink')
                    
                    published_at = None
                    if advisory.get('publishedAt'):
                        try:
                            published_at = datetime.fromisoformat(advisory['publishedAt'].replace('Z', '+00:00'))
                        except:
                            pass
                    
                    # Generate AI summaries
                    summaries = get_claude_summaries(description)
                    
                    # Upsert advisory
                    cur.execute("""
                        INSERT INTO advisories (id, "orgId", title, content, summary, "summaryTech", source, "sourceUrl", "publishedAt", "updatedAt", "createdAt")
                        VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                        ON CONFLICT ("sourceUrl") DO UPDATE SET
                        title = EXCLUDED.title,
                        content = EXCLUDED.content,
                        summary = EXCLUDED.summary,
                        "summaryTech" = EXCLUDED."summaryTech",
                        "publishedAt" = EXCLUDED."publishedAt",
                        "updatedAt" = NOW()
                        WHERE advisories."sourceUrl" = EXCLUDED."sourceUrl"
                    """, (
                        'default_org', summary, description,
                        summaries['summary'], summaries['summaryTech'],
                        'GHSA', permalink, published_at
                    ))
                    advisories_processed += 1
                
                conn.commit()
        finally:
            conn.close()
        
        update_data_source_status('GHSA', f'SUCCESS: {advisories_processed} advisories processed')
        logger.info(f"GHSA pull completed: {advisories_processed} advisories processed")
        
    except Exception as e:
        error_msg = f'ERROR: {str(e)}'
        update_data_source_status('GHSA', error_msg)
        logger.error(f"GHSA pull failed: {e}")
        raise

@app.task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 60})
def task_cisa_kev_sync(self):
    """Sync CISA Known Exploited Vulnerabilities"""
    logger.info("Starting CISA KEV sync")
    
    try:
        # Download CISA KEV CSV
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Parse CSV
        csv_content = StringIO(response.text)
        reader = csv.DictReader(csv_content)
        
        kev_cves = set()
        for row in reader:
            cve_id = row.get('cveID')
            if cve_id:
                kev_cves.add(cve_id)
        
        # Update CVEs in database
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # Reset all KEV flags first
                cur.execute('UPDATE cves SET "isKev" = false')
                
                # Set KEV flag for known exploited CVEs
                if kev_cves:
                    placeholders = ','.join(['%s'] * len(kev_cves))
                    cur.execute(f'''
                        UPDATE cves SET "isKev" = true, "updatedAt" = NOW()
                        WHERE id IN ({placeholders})
                    ''', list(kev_cves))
                
                conn.commit()
                
                # Get count of KEV CVEs updated
                cur.execute('SELECT COUNT(*) FROM cves WHERE "isKev" = true')
                kev_count = cur.fetchone()[0]
        finally:
            conn.close()
        
        update_data_source_status('CISA_KEV', f'SUCCESS: {kev_count} KEV CVEs updated')
        logger.info(f"CISA KEV sync completed: {kev_count} CVEs marked as KEV")
        
    except Exception as e:
        error_msg = f'ERROR: {str(e)}'
        update_data_source_status('CISA_KEV', error_msg)
        logger.error(f"CISA KEV sync failed: {e}")
        raise

@app.task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 60})
def task_rss_pull_all(self):
    """Pull all enabled RSS feeds"""
    logger.info("Starting RSS feed pull")
    
    try:
        # Get all enabled RSS data sources
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, label, "configJson" FROM data_sources 
                WHERE kind = 'RSS' AND enabled = true
            """)
            rss_sources = cur.fetchall()
        conn.close()
        
        if not rss_sources:
            update_data_source_status('RSS', 'SUCCESS: No RSS sources configured')
            return
        
        advisories_processed = 0
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                for source_id, label, config_json in rss_sources:
                    if not config_json:
                        continue
                    
                    config = json.loads(config_json) if isinstance(config_json, str) else config_json
                    rss_url = config.get('url')
                    
                    if not rss_url:
                        continue
                    
                    try:
                        # Parse RSS feed
                        feed = feedparser.parse(rss_url)
                        
                        for entry in feed.entries[:20]:  # Limit to recent 20 entries
                            title = getattr(entry, 'title', '')
                            content = getattr(entry, 'summary', '') or getattr(entry, 'description', '')
                            source_url = getattr(entry, 'link', '')
                            
                            published_at = None
                            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                                published_at = datetime(*entry.published_parsed[:6])
                            
                            # Generate AI summaries
                            summaries = get_claude_summaries(content)
                            
                            # Upsert advisory
                            cur.execute("""
                                INSERT INTO advisories (id, "orgId", title, content, summary, "summaryTech", source, "sourceUrl", "publishedAt", "updatedAt", "createdAt")
                                VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                                ON CONFLICT ("sourceUrl") DO UPDATE SET
                                title = EXCLUDED.title,
                                content = EXCLUDED.content,
                                summary = EXCLUDED.summary,
                                "summaryTech" = EXCLUDED."summaryTech",
                                "publishedAt" = EXCLUDED."publishedAt",
                                "updatedAt" = NOW()
                                WHERE advisories."sourceUrl" = EXCLUDED."sourceUrl"
                            """, (
                                'default_org', title, content,
                                summaries['summary'], summaries['summaryTech'],
                                label, source_url, published_at
                            ))
                            advisories_processed += 1
                    
                    except Exception as e:
                        logger.error(f"Failed to process RSS feed {rss_url}: {e}")
                    
                    # Rate limiting between feeds
                    time.sleep(2)
                
                conn.commit()
        finally:
            conn.close()
        
        update_data_source_status('RSS', f'SUCCESS: {advisories_processed} advisories processed')
        logger.info(f"RSS pull completed: {advisories_processed} advisories processed")
        
    except Exception as e:
        error_msg = f'ERROR: {str(e)}'
        update_data_source_status('RSS', error_msg)
        logger.error(f"RSS pull failed: {e}")
        raise

if __name__ == '__main__':
    app.start()