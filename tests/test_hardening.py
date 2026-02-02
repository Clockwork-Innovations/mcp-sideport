"""
Tests for production hardening features (Issue #1).
"""

import asyncio
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
from aiohttp.test_utils import TestClient

from mcp_sideport.daemon import (
    DEFAULT_CLIENT_MAX_SIZE,
    MCP_FETCH_MAX_RETRIES,
    SideportDaemon,
)


class TestRequestBodyLimits:
    """Test request body size limits."""

    def test_default_client_max_size(self):
        """Daemon uses default client_max_size (5MB)."""
        daemon = SideportDaemon(auto_open_browser=False)
        assert daemon.client_max_size == DEFAULT_CLIENT_MAX_SIZE
        assert daemon.client_max_size == 5 * 1024 * 1024  # 5MB

    def test_custom_client_max_size(self):
        """Daemon accepts custom client_max_size."""
        daemon = SideportDaemon(
            auto_open_browser=False,
            client_max_size=512 * 1024,  # 512KB
        )
        assert daemon.client_max_size == 512 * 1024

    def test_app_configured_with_client_max_size(self):
        """Application is configured with client_max_size."""
        daemon = SideportDaemon(
            auto_open_browser=False,
            client_max_size=1024,
        )
        # aiohttp stores this in _client_max_size
        assert daemon.app._client_max_size == 1024


class TestEnhancedHealthCheck:
    """Test enhanced /health endpoint."""

    @pytest.fixture
    def daemon(self) -> SideportDaemon:
        return SideportDaemon(auto_open_browser=False)

    @pytest.fixture
    async def client(self, daemon: SideportDaemon) -> TestClient:
        from aiohttp.test_utils import TestServer

        server = TestServer(daemon.app)
        client = TestClient(server)
        await client.start_server()
        yield client
        await client.close()

    async def test_health_includes_uptime(self, client: TestClient):
        """Health check includes uptime in seconds."""
        resp = await client.get("/health")
        data = await resp.json()
        assert "uptime" in data
        assert isinstance(data["uptime"], (int, float))
        assert data["uptime"] >= 0

    async def test_health_includes_version(self, client: TestClient):
        """Health check includes package version."""
        resp = await client.get("/health")
        data = await resp.json()
        assert "version" in data
        assert isinstance(data["version"], str)

    async def test_health_includes_background_tasks(self, client: TestClient):
        """Health check includes background task count."""
        resp = await client.get("/health")
        data = await resp.json()
        assert "backgroundTasks" in data
        assert isinstance(data["backgroundTasks"], int)
        assert data["backgroundTasks"] >= 0

    async def test_health_includes_mcp_connected(self, client: TestClient):
        """Health check includes MCP connection status."""
        resp = await client.get("/health")
        data = await resp.json()
        assert "mcpConnected" in data
        assert isinstance(data["mcpConnected"], bool)


class TestMcpSessionRecovery:
    """Test MCP session recovery on errors."""

    def test_reset_mcp_session_clears_session_id(self):
        """_reset_mcp_session clears the cached session ID."""
        daemon = SideportDaemon(
            auto_open_browser=False,
            mcp_server_url="http://localhost:3850",
        )
        daemon._html_cache["mcp_session_id"] = "test-session-123"
        daemon._reset_mcp_session()
        assert daemon._html_cache["mcp_session_id"] is None

    async def test_fetch_resets_session_on_network_error(self):
        """_fetch_from_mcp resets session on network errors."""
        daemon = SideportDaemon(
            auto_open_browser=False,
            mcp_server_url="http://localhost:3850",
        )
        daemon._html_cache["mcp_session_id"] = "old-session"

        # Mock client session to raise error
        mock_session = AsyncMock()
        mock_session.closed = False  # Mark as not closed so it won't be recreated
        mock_session.post.side_effect = aiohttp.ClientError("Connection failed")
        daemon._client_session = mock_session

        with pytest.raises(aiohttp.ClientError):
            await daemon._fetch_from_mcp("ui://test")

        assert daemon._html_cache["mcp_session_id"] is None

    async def test_fetch_retries_on_network_error(self):
        """_fetch_from_mcp retries with backoff on network errors."""
        daemon = SideportDaemon(
            auto_open_browser=False,
            mcp_server_url="http://localhost:3850",
        )

        call_count = 0

        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise aiohttp.ClientError("Connection failed")

        mock_session = AsyncMock()
        mock_session.closed = False
        mock_session.post.side_effect = mock_post
        daemon._client_session = mock_session

        with pytest.raises(aiohttp.ClientError):
            await daemon._fetch_from_mcp("ui://test")

        # Should have retried MCP_FETCH_MAX_RETRIES times
        assert call_count == MCP_FETCH_MAX_RETRIES + 1


class TestMcpSessionExpiry:
    """Test MCP session expiry handling."""

    async def test_fetch_resets_and_retries_on_401(self):
        """_fetch_from_mcp resets session and retries once on 401."""
        daemon = SideportDaemon(
            auto_open_browser=False,
            mcp_server_url="http://localhost:3850",
        )
        daemon._html_cache["mcp_session_id"] = "expired-session"

        call_count = 0

        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = AsyncMock()
            resp.status = 401
            resp.headers = {}
            return resp

        mock_session = AsyncMock()
        mock_session.closed = False
        mock_session.post.side_effect = mock_post
        daemon._client_session = mock_session

        result = await daemon._fetch_from_mcp("ui://test")

        assert result is None
        # Should have tried original + 1 retry
        assert call_count >= 2

    async def test_fetch_resets_and_retries_on_404(self):
        """_fetch_from_mcp resets session and retries once on 404."""
        daemon = SideportDaemon(
            auto_open_browser=False,
            mcp_server_url="http://localhost:3850",
        )
        daemon._html_cache["mcp_session_id"] = "expired-session"

        call_count = 0

        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = AsyncMock()
            resp.status = 404
            resp.headers = {}
            return resp

        mock_session = AsyncMock()
        mock_session.closed = False
        mock_session.post.side_effect = mock_post
        daemon._client_session = mock_session

        result = await daemon._fetch_from_mcp("ui://test")

        assert result is None
        assert daemon._html_cache["mcp_session_id"] is None
