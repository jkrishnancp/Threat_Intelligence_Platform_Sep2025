import os
from celery import Celery
from datetime import datetime, timezone, timedelta
from clients import nvd, osv, ghsa, rss, cisa_kev
from db import upsert_cve, upsert_osv, upsert_advisory, update_datasource_status
from ai import summarize

REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')
celery_app = Celery('tasks', broker=REDIS_URL, backend=REDIS_URL)

@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(8*60*60, task_nvd_pull.s(), name='NVD every 8h')
    sender.add_periodic_task(8*60*60, task_osv_pull.s(), name='OSV every 8h')
    sender.add_periodic_task(8*60*60, task_ghsa_pull.s(), name='GHSA every 8h')
    sender.add_periodic_task(8*60*60, task_cisa_kev_sync.s(), name='KEV every 8h')
    sender.add_periodic_task(8*60*60, task_rss_pull_all.s(), name='RSS every 8h')

def _iso(dt): return dt.astimezone(timezone.utc).isoformat()

@celery_app.task
def task_cisa_kev_sync():
    kev = cisa_kev.fetch()
    update_datasource_status('CISA_KEV', f"synced {len(kev)} IDs")
    return len(kev)

@celery_app.task
def task_nvd_pull():
    last = datetime.now(timezone.utc) - timedelta(hours=10)
    kev = cisa_kev.fetch()
    items = nvd.fetch_since(last)
    for c in items: upsert_cve(c, kev)
    update_datasource_status('NVD', f"upserted {len(items)} CVEs")
    return len(items)

@celery_app.task
def task_osv_pull():
    last = datetime.now(timezone.utc) - timedelta(hours=10)
    vulns = osv.fetch_since(_iso(last))
    for v in vulns: upsert_osv(v)
    update_datasource_status('OSV', f"upserted {len(vulns)} vulns")
    return len(vulns)

@celery_app.task
def task_ghsa_pull():
    last = datetime.now(timezone.utc) - timedelta(hours=24)
    nodes = ghsa.fetch_updated_since(_iso(last))
    for n in nodes:
        v = {"id": n.get('ghsaId'), "affected": [], "severity":[{"type": n.get('severity')}],
             "published": n.get('updatedAt'), "modified": n.get('updatedAt'), "summary": n.get('summary'),
             "references": n.get('references')}
        upsert_osv(v)
    update_datasource_status('GHSA', f"upserted {len(nodes)} advisories")
    return len(nodes)

@celery_app.task
def task_rss_pull_all():
    feeds = [
        ("CISA", "https://www.cisa.gov/uscert/ncas/current-activity.xml"),
        ("MSRC", "https://msrc.microsoft.com/update-guide/rss")
    ]
    count = 0
    for source, url in feeds:
        for entry in rss.fetch(url):
            text = getattr(entry,'summary','') or getattr(entry,'title','')
            sums = summarize(text)
            upsert_advisory(source, entry, sums)
            count += 1
    update_datasource_status('RSS', f"upserted {count} advisories")
    return count