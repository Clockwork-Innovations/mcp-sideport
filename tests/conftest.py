"""
Pytest fixtures for mcp-sideport tests.
"""

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from mcp_sideport.daemon import SideportDaemon


@pytest.fixture
def daemon() -> SideportDaemon:
    """Create a SideportDaemon instance for testing."""
    return SideportDaemon(
        host="127.0.0.1",
        port=3999,  # Use different port to avoid conflicts
        auto_open_browser=False,  # Don't open browser during tests
    )


@pytest_asyncio.fixture
async def client(daemon: SideportDaemon) -> TestClient:
    """Create an aiohttp test client for the daemon."""
    server = TestServer(daemon.app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


@pytest.fixture
def daemon_with_handlers() -> SideportDaemon:
    """Create a SideportDaemon with sample handlers."""
    daemon = SideportDaemon(
        host="127.0.0.1",
        port=3999,
        auto_open_browser=False,
    )

    # Register sync API handler
    def get_status():
        return {"status": "ok", "count": 42}

    daemon.register_api("status", get_status)

    # Register sync action handler
    def do_something(value: str = "default"):
        return {"result": f"did {value}"}

    daemon.register_action("do_something", do_something)

    return daemon


@pytest_asyncio.fixture
async def client_with_handlers(daemon_with_handlers: SideportDaemon) -> TestClient:
    """Create a test client for daemon with handlers."""
    server = TestServer(daemon_with_handlers.app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


@pytest.fixture
def daemon_with_async_handlers() -> SideportDaemon:
    """Create a SideportDaemon with async handlers."""
    daemon = SideportDaemon(
        host="127.0.0.1",
        port=3999,
        auto_open_browser=False,
    )

    # Register async API handler
    async def get_async_status():
        return {"async": True, "status": "ok"}

    daemon.register_api("async_status", get_async_status)

    # Register async action handler
    async def async_action(value: str = "default"):
        return {"async": True, "result": value}

    daemon.register_action("async_action", async_action)

    return daemon


@pytest_asyncio.fixture
async def client_with_async_handlers(daemon_with_async_handlers: SideportDaemon) -> TestClient:
    """Create a test client for daemon with async handlers."""
    server = TestServer(daemon_with_async_handlers.app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()
