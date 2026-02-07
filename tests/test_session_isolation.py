"""
Tests for session isolation in mcp-sideport.

Ensures MCP sessions are properly isolated and app sessions belong to their parent MCP session.
"""

import asyncio

from aiohttp.test_utils import TestClient


class TestSessionCreation:
    """Test session creation and tracking."""

    async def test_each_launch_creates_unique_session(self, client: TestClient):
        """Each launch creates a unique session ID."""
        resp1 = await client.post("/launch", json={"resourceUri": "ui://app1"})
        resp2 = await client.post("/launch", json={"resourceUri": "ui://app2"})

        data1 = await resp1.json()
        data2 = await resp2.json()

        assert data1["sessionId"] != data2["sessionId"]

    async def test_sessions_tracked_in_health(self, client: TestClient):
        """All sessions are tracked in health endpoint."""
        # Create multiple sessions
        for i in range(3):
            await client.post("/launch", json={"resourceUri": f"ui://app{i}"})

        resp = await client.get("/health")
        data = await resp.json()
        assert data["sessions"] == 3


class TestSessionIsolation:
    """Test that sessions are properly isolated."""

    async def test_sessions_have_separate_content(self, client: TestClient):
        """Each session has its own content."""
        # Create two sessions with different URIs
        resp1 = await client.post(
            "/launch",
            json={
                "resourceUri": "ui://app1",
                "title": "App 1",
            },
        )
        resp2 = await client.post(
            "/launch",
            json={
                "resourceUri": "ui://app2",
                "title": "App 2",
            },
        )

        session1_id = (await resp1.json())["sessionId"]
        session2_id = (await resp2.json())["sessionId"]

        # Access both sessions
        app1_resp = await client.get(f"/app/{session1_id}")
        app2_resp = await client.get(f"/app/{session2_id}")

        assert app1_resp.status == 200
        assert app2_resp.status == 200

        # Content should exist for both (even if just loading placeholder)
        content1 = await app1_resp.text()
        content2 = await app2_resp.text()

        assert "Loading" in content1 or "app1" in content1.lower()
        assert "Loading" in content2 or "app2" in content2.lower()

    async def test_session_not_accessible_by_other_id(self, client: TestClient):
        """Session content is not accessible with wrong ID."""
        # Create a session
        resp = await client.post("/launch", json={"resourceUri": "ui://secret"})
        session_id = (await resp.json())["sessionId"]

        # Real session works
        real_resp = await client.get(f"/app/{session_id}")
        assert real_resp.status == 200

        # Modified ID doesn't work
        fake_id = session_id[:-5] + "xxxxx"
        fake_resp = await client.get(f"/app/{fake_id}")
        assert fake_resp.status == 404


class TestConcurrentSessions:
    """Test concurrent session handling."""

    async def test_concurrent_session_creation(self, client: TestClient):
        """Multiple sessions can be created concurrently."""
        # Create 10 sessions concurrently
        tasks = [client.post("/launch", json={"resourceUri": f"ui://app{i}"}) for i in range(10)]
        responses = await asyncio.gather(*tasks)

        # All should succeed
        for resp in responses:
            assert resp.status == 200

        # All should have unique IDs
        session_ids = [(await resp.json())["sessionId"] for resp in responses]
        assert len(set(session_ids)) == 10

    async def test_concurrent_session_access(self, client: TestClient):
        """Multiple sessions can be accessed concurrently."""
        # Create sessions first
        session_ids = []
        for i in range(5):
            resp = await client.post("/launch", json={"resourceUri": f"ui://app{i}"})
            session_ids.append((await resp.json())["sessionId"])

        # Access all concurrently
        tasks = [client.get(f"/app/{sid}") for sid in session_ids]
        responses = await asyncio.gather(*tasks)

        # All should succeed
        for resp in responses:
            assert resp.status == 200


class TestSessionMetadata:
    """Test session metadata storage."""

    async def test_session_stores_resource_uri(self, daemon, client: TestClient):
        """Session stores the resource URI."""
        await client.post(
            "/launch",
            json={
                "resourceUri": "ui://test/specific",
            },
        )

        # Check internal state
        assert len(daemon.sessions) == 1
        session = list(daemon.sessions.values())[0]
        assert session["resourceUri"] == "ui://test/specific"

    async def test_session_stores_title(self, daemon, client: TestClient):
        """Session stores the title."""
        await client.post(
            "/launch",
            json={
                "resourceUri": "ui://test",
                "title": "My Custom Title",
            },
        )

        session = list(daemon.sessions.values())[0]
        assert session["title"] == "My Custom Title"

    async def test_session_default_title(self, daemon, client: TestClient):
        """Session uses default title when not provided."""
        await client.post(
            "/launch",
            json={
                "resourceUri": "ui://test",
            },
        )

        session = list(daemon.sessions.values())[0]
        assert session["title"] == "MCP App"

    async def test_session_has_created_timestamp(self, daemon, client: TestClient):
        """Session has a creation timestamp."""
        import time

        before = time.time()
        await client.post("/launch", json={"resourceUri": "ui://test"})
        after = time.time()

        session = list(daemon.sessions.values())[0]
        assert "created" in session
        assert before <= session["created"] <= after

    async def test_session_initial_status(self, daemon, client: TestClient):
        """Session starts with pending status."""
        await client.post("/launch", json={"resourceUri": "ui://test"})

        session = list(daemon.sessions.values())[0]
        assert session["status"] == "pending"


class TestSessionCleanup:
    """Test session cleanup and TTL functionality."""

    async def test_close_session_removes_session(self, daemon, client: TestClient):
        """close_session removes session and its content."""
        resp = await client.post("/launch", json={"resourceUri": "ui://test"})
        session_id = (await resp.json())["sessionId"]

        assert session_id in daemon.sessions
        assert session_id in daemon.content_cache

        result = daemon.close_session(session_id)
        assert result is True
        assert session_id not in daemon.sessions
        assert session_id not in daemon.content_cache

    async def test_close_session_returns_false_for_unknown(self, daemon):
        """close_session returns False for unknown session."""
        result = daemon.close_session("nonexistent-session-id")
        assert result is False

    async def test_cleanup_expired_sessions(self, daemon, client: TestClient):
        """_cleanup_expired_sessions removes old sessions."""

        # Create a session with short TTL
        daemon.session_ttl = 0.1  # 100ms

        resp = await client.post("/launch", json={"resourceUri": "ui://test"})
        session_id = (await resp.json())["sessionId"]

        assert session_id in daemon.sessions

        # Wait for session to expire
        await asyncio.sleep(0.2)

        # Run cleanup
        daemon._cleanup_expired_sessions()

        assert session_id not in daemon.sessions

    async def test_close_clears_all_sessions(self, daemon, client: TestClient):
        """close() clears all sessions."""
        # Create multiple sessions
        for i in range(3):
            await client.post("/launch", json={"resourceUri": f"ui://app{i}"})

        assert len(daemon.sessions) == 3

        # Close the daemon
        await daemon.close()

        assert len(daemon.sessions) == 0
        assert len(daemon.content_cache) == 0
