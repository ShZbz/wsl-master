"""Integration test: start server, hit API endpoints."""

import json
import urllib.request
import pytest

from wsl_master.web.server import WslWebServer, RequestHandler
from wsl_master.scan.controller import ScanController

# Bypass system HTTP proxy for localhost tests
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _api_request(method, url, data=None, token=None):
    """Make an API request, optionally with auth token."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Auth-Token"] = token
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    resp = _opener.open(req)
    return json.loads(resp.read())


@pytest.fixture
def server():
    controller = ScanController()
    srv = WslWebServer(host="127.0.0.1", port=0)
    port = srv.start(controller)
    token = RequestHandler.auth_token
    base = f"http://127.0.0.1:{port}"
    yield (base, token)
    srv.stop()


def test_health(server):
    base, _ = server
    req = urllib.request.Request(f"{base}/api/health")
    resp = _opener.open(req)
    data = json.loads(resp.read())
    assert data["status"] == "ok"


def test_static_index(server):
    base, _ = server
    req = urllib.request.Request(f"{base}/")
    resp = _opener.open(req)
    assert resp.status == 200
    html = resp.read().decode()
    assert "WSL Storage Master" in html
    assert "treemap-canvas" in html
    assert 'auth-token' in html


def test_scan_list_empty(server):
    base, token = server
    data = _api_request("GET", f"{base}/api/scan/list", token=token)
    assert "scans" in data


def test_scan_status(server):
    base, token = server
    data = _api_request("GET", f"{base}/api/scan/status", token=token)
    assert "running" in data
    assert data["running"] is False


def test_scan_start_stop(server):
    base, token = server
    data = _api_request("POST", f"{base}/api/scan/start", data={"mode": "quick"}, token=token)
    assert data["status"] == "started"

    _api_request("POST", f"{base}/api/scan/stop", data={}, token=token)


def test_tree_empty(server):
    base, token = server
    data = _api_request("GET", f"{base}/api/tree", token=token)
    assert "nodes" in data
    assert "total" in data


def test_vhdx_detect(server):
    base, token = server
    data = _api_request("GET", f"{base}/api/vhdx/detect", token=token)
    assert "instances" in data


def test_api_rejects_without_token(server):
    base, _ = server
    req = urllib.request.Request(f"{base}/api/scan/status")
    try:
        _opener.open(req)
        assert False, "Should have raised HTTPError 401"
    except urllib.error.HTTPError as e:
        assert e.code == 401
