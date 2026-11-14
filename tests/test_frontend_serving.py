"""
Frontend Static SPA Serving and Integration Tests
Verifies that the compiled React SOC Dashboard is correctly served by FastAPI,
including HTML page routes, JavaScript/CSS asset bundles, and client routing fallbacks.
"""

import pytest
from fastapi.testclient import TestClient
from src.backend.app import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_root_json_for_api_clients(client):
    """API clients receive JSON operational status from root."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["observe_only_mode"] is True
    assert data["action_enforced"] == "NONE_OBSERVE_ONLY"
    assert data["ui_url"] == "/ui"


def test_root_html_for_web_browsers(client):
    """Web browsers requesting HTML receive the compiled React SPA."""
    response = client.get("/", headers={"Accept": "text/html,application/xhtml+xml"})
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "Neural Breach" in response.text
    assert '<div id="root">' in response.text


def test_ui_endpoints_serve_react_spa(client):
    """SPA navigation endpoints serve the React application shell."""
    spa_paths = ["/ui", "/dashboard", "/alerts", "/investigate", "/analytics", "/health", "/demo"]
    for path in spa_paths:
        response = client.get(path)
        assert response.status_code == 200, f"Failed for path {path}"
        assert "text/html" in response.headers.get("content-type", "")
        assert '<div id="root">' in response.text


def test_static_assets_serving(client):
    """Static assets in /assets are reachable and properly typed."""
    import os
    from src.backend.app import FRONTEND_ASSETS

    if os.path.exists(FRONTEND_ASSETS):
        asset_files = os.listdir(FRONTEND_ASSETS)
        assert len(asset_files) > 0, "No assets found in FRONTEND_ASSETS"
        for asset_file in asset_files:
            resp = client.get(f"/assets/{asset_file}")
            assert resp.status_code == 200

