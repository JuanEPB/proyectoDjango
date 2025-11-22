# api_client.py
import os
from urllib.parse import urljoin

# intenta leer de env directo; si Django settings ya cargó .env, esto funcionará
API_BASE_URL = os.getenv("API_URL") or "http://127.0.0.1:3000"

def build_url(path: str) -> str:
    return urljoin(API_BASE_URL.rstrip('/') + '/', path.lstrip('/'))

# helpers
import requests
DEFAULT_TIMEOUT = 10

def api_get(path, token=None, params=None):
    url = build_url(path)
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)

def api_post(path, token=None, json=None, data=None):
    url = build_url(path)
    headers = {"Content-Type": "application/json"} if json else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.post(url, headers=headers, json=json, data=data, timeout=DEFAULT_TIMEOUT)

