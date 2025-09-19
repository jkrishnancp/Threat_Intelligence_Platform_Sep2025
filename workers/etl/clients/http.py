import time, requests
DEFAULT_TIMEOUT = 30
class Http:
    def __init__(self, retries=3, backoff=1.5):
        self.retries = retries
        self.backoff = backoff
    def get(self, url, **kwargs):
        return self._call('GET', url, **kwargs)
    def post(self, url, **kwargs):
        return self._call('POST', url, **kwargs)
    def _call(self, method, url, **kwargs):
        timeout = kwargs.pop('timeout', DEFAULT_TIMEOUT)
        for i in range(self.retries + 1):
            try:
                r = requests.request(method, url, timeout=timeout, **kwargs)
                r.raise_for_status()
                return r
            except Exception:
                if i == self.retries:
                    raise
                time.sleep(self.backoff ** (i+1))