from .http import Http
OSV_QUERY = "https://api.osv.dev/v1/query"
def fetch_since(updated_since_iso: str, ecosystems=("PyPI","npm","Maven","Go","RubyGems")):
    http = Http()
    out = []
    for eco in ecosystems:
        payload = {"ecosystem": eco, "modified": updated_since_iso}
        r = http.post(OSV_QUERY, json=payload).json()
        out.extend(r.get('vulns', []))
    return out