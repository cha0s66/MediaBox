# MediaBox

MediaBox is a small authenticated file server for local development or a trusted home network. It supports role-based access, uploads, media previews, public downloads, messages, and moderation.

> MediaBox is not hardened for direct internet exposure. Use HTTPS through a reverse proxy and keep the Python server bound to localhost for production deployments.

## Requirements

- Python 3.11 or newer
- Windows, macOS, or Linux

The server uses only Python's standard library.

## Quick start

From the project directory:

```powershell
python .\server.py . --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000/> in a browser and create the first account. The first account automatically becomes the owner. Stop the server with `Ctrl+C`.

On Windows, `startserver.bat` and `stopserver.bat` provide the same local workflow on port `8000`.

## Features

- Local account signup and login
- Owner, admin, moderator, and user roles
- Session-bound CSRF protection for state-changing requests
- Rate limiting for authentication and write requests
- Private uploads with image, audio, and video previews
- Public downloads from `shared/`
- Owner-approved media access for regular users

## Configuration

Configuration is provided through environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `FILESERVER_OWNER_USERNAME` | unset | Username to promote to owner when loading existing users |
| `FILESERVER_SESSION_TTL` | `28800` | Session lifetime in seconds |
| `FILESERVER_MAX_UPLOAD_SIZE` | `34359738368` | Maximum upload size in bytes |
| `FILESERVER_SECURE_COOKIE` | `0` | Set to `1` when serving through HTTPS |

For a LAN-only deployment, bind to the machine's network interfaces explicitly:

```powershell
python .\server.py . --host 0.0.0.0 --port 8000
```

Only do this on a trusted network. For internet-facing deployments, place MediaBox behind an HTTPS reverse proxy, set `FILESERVER_SECURE_COOKIE=1`, and keep port `8000` closed to the internet.

## Development

Run the test suite with:

```powershell
python -m unittest discover -s tests -v
```

The tests start an isolated temporary server and do not modify the repository's JSON, uploads, or shared files.

## Repository layout

- `server.py` - standard-library HTTP server and API
- `src/` - HTML and CSS interface
- `json/` - empty template data files populated at runtime
- `uploads/` - private uploaded files
- `shared/` - public downloads
- `tests/` - integration tests

Runtime data and local configuration are excluded by `.gitignore`. Do not commit private media, credentials, or password hashes.

## License

MediaBox is released under the MIT License. See [LICENSE](LICENSE).
