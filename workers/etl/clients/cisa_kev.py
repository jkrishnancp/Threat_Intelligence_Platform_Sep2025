import pandas as pd
from .http import Http
CSV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv"
def fetch():
    http = Http()
    r = http.get(CSV_URL)
    df = pd.read_csv(pd.io.common.StringIO(r.text))
    return set(df['cveID'].dropna().astype(str).unique())