"""
Tests for SideportDaemon basic functionality.
"""

from aiohttp.test_utils import TestClient


class TestHealth:
    """Test /health endpoint."""

    async def test_health_returns_ok(self, client: TestClient):
        """Health endpoint returns 200 with status ok."""
        resp = await client.get("/health")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"
        assert "sessions" in data

    async def test_health_shows_session_count(self, client: TestClient):
        """Health endpoint shows number of sessions."""
        resp = await client.get("/health")
        data = await resp.json()
        assert data["sessions"] == 0  # No sessions initially

    async def test_health_shows_mcp_server_status(self, client: TestClient):
        """Health endpoint shows MCP server config."""
        resp = await client.get("/health")
        data = await resp.json()
        assert "mcpServer" in data
        assert "mcpConnected" in data
        assert "uptime" in data
        assert "version" in data
        assert "backgroundTasks" in data


class TestLaunch:
    """Test /launch endpoint."""

    async def test_launch_requires_resource_uri(self, client: TestClient):
        """Launch returns 400 if resourceUri is missing."""
        resp = await client.post("/launch", json={})
        assert resp.status == 400
        data = await resp.json()
        assert "resourceUri required" in data["error"]

    async def test_launch_creates_session(self, client: TestClient):
        """Launch creates a new session and returns sessionId."""
        resp = await client.post(
            "/launch",
            json={
                "resourceUri": "ui://test/app",
                "title": "Test App",
            },
        )
        assert resp.status == 200
        data = await resp.json()
        assert "sessionId" in data
        assert data["status"] == "pending"
        assert "appUrl" in data

    async def test_launch_with_invalid_json(self, client: TestClient):
        """Launch returns 400 for invalid JSON."""
        resp = await client.post(
            "/launch",
            data="not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status == 400


class TestApp:
    """Test /app/{session_id} endpoint."""

    async def test_app_returns_404_for_unknown_session(self, client: TestClient):
        """App returns 404 for unknown session ID."""
        resp = await client.get("/app/nonexistent-session-id")
        assert resp.status == 404

    async def test_app_returns_html_for_valid_session(self, client: TestClient):
        """App returns HTML for a valid session."""
        # First create a session
        launch_resp = await client.post(
            "/launch",
            json={
                "resourceUri": "ui://test/app",
            },
        )
        session_id = (await launch_resp.json())["sessionId"]

        # Then access the app
        resp = await client.get(f"/app/{session_id}")
        assert resp.status == 200
        assert resp.content_type == "text/html"


class TestApiHandlers:
    """Test custom API handler registration and invocation."""

    async def test_api_returns_404_for_unknown_handler(self, client: TestClient):
        """API returns 404 for unregistered handler."""
        resp = await client.get("/api/unknown")
        assert resp.status == 404
        data = await resp.json()
        assert "Unknown API" in data["error"]

    async def test_api_invokes_registered_handler(self, client_with_handlers: TestClient):
        """API invokes registered handler and returns result."""
        resp = await client_with_handlers.get("/api/status")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"
        assert data["count"] == 42

    async def test_api_handler_receives_query_params(
        self, daemon_with_handlers, client_with_handlers: TestClient
    ):
        """API handler receives query parameters."""

        # Register handler that echoes params
        def echo_params(**kwargs):
            return {"params": kwargs}

        daemon_with_handlers.register_api("echo", echo_params)

        resp = await client_with_handlers.get("/api/echo?foo=bar&num=123")
        assert resp.status == 200
        data = await resp.json()
        assert data["params"]["foo"] == "bar"
        assert data["params"]["num"] == "123"

    async def test_api_async_handler(self, client_with_async_handlers: TestClient):
        """API properly awaits async handlers."""
        resp = await client_with_async_handlers.get("/api/async_status")
        # This will fail until we fix Issue #2 (sync handlers in async context)
        assert resp.status == 200
        data = await resp.json()
        assert data["async"] is True


class TestActionHandlers:
    """Test custom action handler registration and invocation."""

    async def test_action_returns_400_for_missing_action(self, client: TestClient):
        """Action returns 400 if action name is missing."""
        resp = await client.post("/api/action", json={})
        assert resp.status == 400
        data = await resp.json()
        assert "action required" in data["error"]

    async def test_action_returns_400_for_unknown_action(self, client: TestClient):
        """Action returns 400 for unregistered action."""
        resp = await client.post("/api/action", json={"action": "unknown"})
        assert resp.status == 400
        data = await resp.json()
        assert "Unknown action" in data["error"]

    async def test_action_invokes_registered_handler(self, client_with_handlers: TestClient):
        """Action invokes registered handler."""
        resp = await client_with_handlers.post(
            "/api/action",
            json={
                "action": "do_something",
                "args": {"value": "test"},
            },
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["result"] == "did test"

    async def test_action_with_default_args(self, client_with_handlers: TestClient):
        """Action works with default arguments."""
        resp = await client_with_handlers.post(
            "/api/action",
            json={
                "action": "do_something",
            },
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["result"] == "did default"

    async def test_action_async_handler(self, client_with_async_handlers: TestClient):
        """Action properly awaits async handlers."""
        resp = await client_with_async_handlers.post(
            "/api/action",
            json={
                "action": "async_action",
                "args": {"value": "async_test"},
            },
        )
        # This will fail until we fix Issue #2
        assert resp.status == 200
        data = await resp.json()
        assert data["async"] is True

    async def test_action_with_invalid_json(self, client: TestClient):
        """Action returns 400 for invalid JSON."""
        resp = await client.post(
            "/api/action",
            data="not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status == 400


class TestCors:
    """Test CORS headers."""

    async def test_cors_preflight(self, client: TestClient):
        """CORS preflight returns correct headers."""
        resp = await client.options("/api/action")
        assert resp.status == 204
        assert resp.headers.get("Access-Control-Allow-Origin") == "*"
        assert "POST" in resp.headers.get("Access-Control-Allow-Methods", "")

    async def test_api_response_has_cors_headers(self, client_with_handlers: TestClient):
        """API responses include CORS headers."""
        resp = await client_with_handlers.get("/api/status")
        assert resp.headers.get("Access-Control-Allow-Origin") == "*"

    async def test_action_response_has_cors_headers(self, client_with_handlers: TestClient):
        """Action responses include CORS headers."""
        resp = await client_with_handlers.post(
            "/api/action",
            json={
                "action": "do_something",
            },
        )
        assert resp.headers.get("Access-Control-Allow-Origin") == "*"
