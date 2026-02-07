# Handoff: Fix Asyncio Issues and Add Test Suite for mcp-sideport

> **⚠️ READ-ONLY HANDOFF DOCUMENT**
> This document is a snapshot created at handoff time.
> Do NOT modify this file - it serves as a historical record.
> Create a new handoff document when you complete your work.

---

## 📋 Instructions for Receiver

**To continue this work, use the `/execute_handoff` command:**

```
/execute_handoff /home/rifampin/cs-projects/mcp-sideport/tmp/handoff/handoff-2026-02-02-agentic-task-fix-asyncio-add-tests.md
```

---

## Status Overview

```
✓ What's Done     | Code review complete, 11 issues identified, validation confirmed daemon works with multiple clients
✗ What's Not      | No fixes implemented, no test suite exists
→ Next Step       | Create test suite (TDD), then fix asyncio issues
⊙ Why Stop Here   | User requested handoff to continue with TDD approach
```

---

## Project Context

**mcp-sideport** is an MCP Apps bridge for AI coding tools (CLIs like Claude Code) that don't natively support MCP Apps/UI. It acts as a sidecar that:
- Serves MCP App HTML in browser
- Provides REST API fallback for browser clients
- Proxies MCP protocol requests to upstream MCP servers
- Manages multiple concurrent MCP sessions with isolation

**Security considerations**: This is a workaround for MCP clients - must be safe and secure.

---

## Code Review Findings (11 Issues)

### Critical Issues

| # | Issue | Location | Description |
|---|-------|----------|-------------|
| 1 | Fire-and-forget asyncio task | `daemon.py:121` | `asyncio.create_task()` without exception handling - exceptions silently swallowed |
| 2 | Sync handlers in async context | `daemon.py:335, 365` | Handlers called synchronously - blocks event loop if handler does I/O |

### High Priority Issues

| # | Issue | Location | Description |
|---|-------|----------|-------------|
| 3 | No HTTP timeout | `daemon.py:160-196` | External HTTP requests have no timeout - can hang forever |
| 4 | ClientSession per-request | `daemon.py:155` | Creates new aiohttp.ClientSession for every fetch - inefficient |
| 5 | Memory leak | `daemon.py:110-116` | Sessions never cleaned up - unbounded memory growth |
| 6 | Blocking I/O in async | `daemon.py:126, 295` | `webbrowser.open()` and `read_text()` block event loop |

### Medium Priority Issues

| # | Issue | Location | Description |
|---|-------|----------|-------------|
| 7 | Race condition | `daemon.py:157-178` | `_html_cache` check-then-modify not atomic |
| 8 | XSS vulnerability | `daemon.py:240` | `resource_uri` injected into HTML without escaping |
| 9 | HMR BUILD_TIME bug | `hybrid_api.py:28` | `time_ns()` evaluated at call time, not build time |

### Low Priority Issues

| # | Issue | Location | Description |
|---|-------|----------|-------------|
| 10 | Missing CORS headers | Various | Some error responses lack CORS headers |
| 11 | Hardcoded protocol version | `daemon.py:167` | Should be a constant |

---

## Files to Modify

### `src/mcp_sideport/daemon.py` (429 lines)
- **Lines 121**: Fix fire-and-forget task
- **Lines 155-205**: Add ClientSession reuse, timeouts
- **Lines 110-116**: Add session cleanup/TTL
- **Lines 126**: Run webbrowser.open in executor
- **Lines 157-178**: Add asyncio.Lock for cache init
- **Lines 207-244**: Escape resource_uri in HTML
- **Lines 295**: Use aiofiles or run in executor
- **Lines 335, 365**: Check if handler is coroutine and await

### `src/mcp_sideport/hybrid_api.py` (157 lines)
- **Line 28**: Fix BUILD_TIME to use actual build time

### New Files to Create
- `tests/test_daemon.py` - Unit tests for SideportDaemon
- `tests/test_session_isolation.py` - Multi-client session isolation tests
- `tests/test_security.py` - XSS, injection, security tests
- `tests/conftest.py` - pytest fixtures

---

## Agentic Execution Plan & Progress

### Foundation Layer: Test Infrastructure
**Overall status**: ⏸️ Not Started

#### Step 1.1: Set up pytest and test infrastructure
- **Status**: ⏸️ Not Started
- **Files to create**: `tests/conftest.py`, `pyproject.toml` (add pytest deps)
- **Plan**:
  - Add pytest, pytest-asyncio, pytest-aiohttp to dependencies
  - Create conftest.py with fixtures for SideportDaemon
  - Create mock MCP server fixture
- **Estimated time**: 20 minutes

#### Step 1.2: Create basic daemon tests (RED phase)
- **Status**: ⏸️ Not Started
- **Files to create**: `tests/test_daemon.py`
- **Plan**:
  - Test health endpoint
  - Test API handler registration
  - Test action handler registration
  - Test session creation
- **Estimated time**: 30 minutes

#### Step 1.3: Create session isolation tests (RED phase)
- **Status**: ⏸️ Not Started
- **Files to create**: `tests/test_session_isolation.py`
- **Plan**:
  - Test that MCP sessions are isolated
  - Test that app sessions belong to their MCP session
  - Test concurrent session handling
- **Estimated time**: 30 minutes

#### Step 1.4: Create security tests (RED phase)
- **Status**: ⏸️ Not Started
- **Files to create**: `tests/test_security.py`
- **Plan**:
  - Test XSS prevention in loading HTML
  - Test malicious resource URIs
  - Test CORS headers on all responses
- **Estimated time**: 25 minutes

### Feature Layer: Fix Critical Issues
**Overall status**: ⏸️ Not Started

#### Step 2.1: Fix fire-and-forget asyncio task (Issue #1)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py:121`
- **Plan**:
  - Store task reference
  - Add exception callback
  - Consider using TaskGroup for Python 3.11+
- **Tests**: Should make asyncio tests pass
- **Estimated time**: 20 minutes

#### Step 2.2: Fix sync handlers in async context (Issue #2)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py:335, 365`
- **Plan**:
  - Check `asyncio.iscoroutine(result)`
  - Await if coroutine
  - Handle both sync and async handlers
- **Tests**: Should make handler tests pass
- **Estimated time**: 15 minutes

#### Step 2.3: Add HTTP timeouts (Issue #3)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py:160-196`
- **Plan**:
  - Add `timeout=aiohttp.ClientTimeout(total=10)`
  - Handle timeout exceptions gracefully
- **Tests**: Should make timeout tests pass
- **Estimated time**: 15 minutes

#### Step 2.4: Reuse ClientSession (Issue #4)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py:155`
- **Plan**:
  - Create `self._client_session` in `__init__`
  - Lazy initialization with lock
  - Clean up in `async def close()`
- **Tests**: Should make performance tests pass
- **Estimated time**: 25 minutes

#### Step 2.5: Add session cleanup (Issue #5)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py:110-116`
- **Plan**:
  - Add TTL to sessions (e.g., 1 hour)
  - Add cleanup task that runs periodically
  - Add `close_session` method
- **Tests**: Should make memory leak tests pass
- **Estimated time**: 30 minutes

#### Step 2.6: Fix blocking I/O (Issue #6)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py:126, 295`
- **Plan**:
  - `await asyncio.to_thread(webbrowser.open, app_url)`
  - Use aiofiles or `asyncio.to_thread(static_file.read_text)`
- **Tests**: Should make I/O tests pass
- **Estimated time**: 15 minutes

### Polish Layer: Fix Medium/Low Priority Issues
**Overall status**: ⏸️ Not Started

#### Step 3.1: Fix race condition (Issue #7)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py:157-178`
- **Plan**:
  - Add `self._init_lock = asyncio.Lock()`
  - Use `async with self._init_lock:` around initialization
- **Estimated time**: 15 minutes

#### Step 3.2: Fix XSS vulnerability (Issue #8)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py:240`
- **Plan**:
  - `import html`
  - `html.escape(resource_uri)`
- **Estimated time**: 10 minutes

#### Step 3.3: Fix HMR BUILD_TIME (Issue #9)
- **Status**: ⏸️ Not Started
- **File**: `hybrid_api.py:28`
- **Plan**:
  - Pass build_time as parameter
  - Or use hash of the HTML content
- **Estimated time**: 10 minutes

#### Step 3.4: Add missing CORS headers (Issue #10)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py` various
- **Plan**:
  - Create helper function for CORS headers
  - Apply to all responses
- **Estimated time**: 15 minutes

#### Step 3.5: Extract protocol version constant (Issue #11)
- **Status**: ⏸️ Not Started
- **File**: `daemon.py:167`
- **Plan**:
  - Add `MCP_PROTOCOL_VERSION = "2025-03-26"` constant
- **Estimated time**: 5 minutes

### Validation Layer
**Overall status**: ⏸️ Not Started

#### Step 4.1: Run full test suite
- **Status**: ⏸️ Not Started
- **Plan**: Run `pytest tests/ -v`
- **Expected**: All tests pass
- **Estimated time**: 10 minutes

#### Step 4.2: Manual validation with dashboard
- **Status**: ⏸️ Not Started
- **Plan**:
  - Start sideport
  - Create multiple MCP sessions
  - Verify session isolation
  - Test REST API fallback
- **Estimated time**: 15 minutes

---

## Remaining Tasks (for TODO List Restoration)

### ⏸️ Pending (13 tasks - IN DEPENDENCY ORDER)

1. ⏸️ **Set up pytest infrastructure** (Step 1.1)
   - Create `tests/conftest.py` with fixtures
   - Add pytest deps to pyproject.toml
   - Estimated: 20 min

2. ⏸️ **Create basic daemon tests** (Step 1.2)
   - Create `tests/test_daemon.py`
   - Test health, API handlers, sessions
   - Estimated: 30 min

3. ⏸️ **Create session isolation tests** (Step 1.3)
   - Create `tests/test_session_isolation.py`
   - Test MCP session isolation, app session ownership
   - Estimated: 30 min

4. ⏸️ **Create security tests** (Step 1.4)
   - Create `tests/test_security.py`
   - Test XSS, CORS, input validation
   - Estimated: 25 min

5. ⏸️ **Fix fire-and-forget asyncio task** (Step 2.1)
   - Fix `daemon.py:121`
   - Store task ref, add exception callback
   - Estimated: 20 min

6. ⏸️ **Fix sync handlers in async context** (Step 2.2)
   - Fix `daemon.py:335, 365`
   - Check and await coroutines
   - Estimated: 15 min

7. ⏸️ **Add HTTP timeouts** (Step 2.3)
   - Fix `daemon.py:160-196`
   - Add ClientTimeout
   - Estimated: 15 min

8. ⏸️ **Reuse ClientSession** (Step 2.4)
   - Fix `daemon.py:155`
   - Lazy init with lock
   - Estimated: 25 min

9. ⏸️ **Add session cleanup** (Step 2.5)
   - Fix `daemon.py:110-116`
   - Add TTL and cleanup task
   - Estimated: 30 min

10. ⏸️ **Fix blocking I/O** (Step 2.6)
    - Fix `daemon.py:126, 295`
    - Use asyncio.to_thread
    - Estimated: 15 min

11. ⏸️ **Fix race condition** (Step 3.1)
    - Fix `daemon.py:157-178`
    - Add asyncio.Lock
    - Estimated: 15 min

12. ⏸️ **Fix XSS vulnerability** (Step 3.2)
    - Fix `daemon.py:240`
    - Use html.escape
    - Estimated: 10 min

13. ⏸️ **Fix remaining issues** (Steps 3.3-3.5)
    - Fix BUILD_TIME, CORS, protocol version
    - Estimated: 30 min

**Total remaining**: 13 tasks, estimated 4.5 hours

---

## Framework

This work follows TDD (Test-Driven Development) with layered approach:

**Layered approach**:
- ○ Foundation: Test infrastructure (Steps 1.1-1.4)
- ○ Feature: Fix critical issues (Steps 2.1-2.6)
- ○ Polish: Fix medium/low issues (Steps 3.1-3.5)
- ○ Validation: Full test suite + manual testing (Steps 4.1-4.2)

**Completed layers**: None (code review only)

**Next layer**: Foundation - Set up test infrastructure

---

## Validation Already Performed

The daemon was manually validated and works correctly:
- **8 MCP sessions** created and tracked
- **App sessions isolated** per MCP session (Session A: 1 app, Session B: 0 apps)
- **Tool calls work** through MCP protocol
- **REST API fallback works** (`/api/sessions`, `/api/action`)

---

## Reference: Current Code State

### daemon.py Key Sections

**Line 121 - Fire-and-forget task (needs fix)**:
```python
asyncio.create_task(self._fetch_content(session_id, resource_uri))
```

**Lines 335, 365 - Sync handler call (needs fix)**:
```python
result = handler(**args) if args else handler()
```

**Line 155 - ClientSession per-request (needs fix)**:
```python
async with aiohttp.ClientSession() as session:
```

**Line 240 - XSS vulnerability (needs fix)**:
```python
<p style="font-size: 12px; opacity: 0.6;">{resource_uri}</p>
```

---

## Gotchas & Blockers

- **Running sideport**: There's already a sideport running on port 3847 from agent-dashboard-mcp. Tests should use a different port or mock.
- **MCP server dependency**: Tests need a mock MCP server or the real one on port 3850.
- **Python version**: Code uses `dict[str, ...]` syntax which requires Python 3.9+.

---

## Handoff Checklist

- ✓ Code review complete with 11 issues documented
- ✓ Manual validation confirms daemon works
- ✓ Agentic execution plan created with TDD approach
- ✓ Remaining tasks detailed for TODO restoration
- ✓ Line numbers included for all issues
- ✓ Security considerations documented
- ✗ Tests not created yet (TDD - will create first)
- ✗ No fixes implemented yet

**Ready to hand off:** YES

---

## Questions for Next Developer

- Should we add rate limiting to prevent abuse?
- Should session cleanup be configurable (TTL duration)?
- Should we add authentication/authorization?
