import sys
from urllib.request import Request, urlopen

URL = "http://127.0.0.1:8501/_stcore/health"

try:
    request = Request(URL, headers={"User-Agent": "NetSage-HealthCheck/1.0"})
    with urlopen(request, timeout=4) as response:
        body = response.read().decode("utf-8", errors="replace").strip().lower()
        if response.status == 200 and "ok" in body:
            sys.exit(0)
except Exception:
    pass

sys.exit(1)
