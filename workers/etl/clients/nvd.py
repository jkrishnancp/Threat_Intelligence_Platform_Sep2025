from datetime import datetime, timedelta, timezone
from .http import Http
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
def fetch_since(last_dt: datetime):
    http = Http()
    start = (last_dt or datetime.now(timezone.utc) - timedelta(days=2))
    end = datetime.now(timezone.utc)
    params = {
        'lastModStartDate': start.isoformat(timespec='seconds').replace('+00:00','Z'),
        'lastModEndDate': end.isoformat(timespec='seconds').replace('+00:00','Z'),
        'startIndex': 0
    }
    items = []
    while True:
        r = http.get(BASE, params=params).json()
        vulns = r.get('vulnerabilities', [])
        for v in vulns:
            items.append(v.get('cve', {}))
        if len(vulns) == 0 or params['startIndex'] + len(vulns) >= r.get('totalResults', 0):
            break
        params['startIndex'] += len(vulns)
    return items