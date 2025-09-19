import os
from .http import Http
GQL = "https://api.github.com/graphql"
def fetch_updated_since(updated_iso: str):
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        return []
    http = Http()
    query = {
      "query": """
      query($since: DateTime!) {
        securityAdvisories(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}, publishedSince: $since) {
          nodes { ghsaId summary updatedAt severity permalink identifiers { type value } references { url } }
        }
      }
      """,
      "variables": {"since": updated_iso}
    }
    r = http.post(GQL, json=query, headers={"Authorization": f"bearer {token}"}).json()
    return r.get('data',{}).get('securityAdvisories',{}).get('nodes',[])