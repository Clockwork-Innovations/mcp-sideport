# mcp-sideport

MCP Apps bridge for AI coding tools - browser UIs with REST fallback.

## Project Structure

```
src/mcp_sideport/
├── __init__.py      # Package exports
├── __main__.py      # python -m support
├── daemon.py        # Core HTTP daemon (SideportDaemon)
└── hybrid_api.py    # JavaScript generator for hybrid MCP/REST
```

## Development

```bash
# Install in dev mode
pip install -e .

# Test CLI
mcp-sideport --help
python -m mcp_sideport --help

# Build
pip install build
python -m build
```

## Key Components

### SideportDaemon

HTTP server with these endpoints:
- `POST /launch` - Open browser with MCP App
- `GET /dashboard` - Direct dashboard access (HMR enabled)
- `GET /app/{id}` - Session-based app page
- `GET /api/{name}` - Custom GET handlers
- `POST /api/action` - Custom POST handlers
- `GET /health` - Health check (uptime, version, mcpConnected)

Key config options:
- `client_max_size` - Request body limit (default 5MB, increase for media)
- `session_ttl` - Session expiry in seconds (default 1 hour)

See README.md § Configuration for all options.

### Hybrid API

JavaScript that tries `window.mcpApps.callTool()` first, falls back to REST:

```javascript
const data = await callToolOrApi('getSessions', {}, '/api/sessions');
```

## Publishing

```bash
python -m build
twine upload dist/*
```

Then users can run: `uvx mcp-sideport --help`
