import argparse
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from functools import partial
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

parser = argparse.ArgumentParser()
parser.add_argument("directory", nargs="?", default=".")
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=8000)

args = parser.parse_args()


def positive_environment_int(name, default):
    value = os.environ.get(name, str(default))
    try:
        value = int(value)
    except ValueError as error:
        raise SystemExit(f"{name} must be a positive integer.") from error

    if value <= 0:
        raise SystemExit(f"{name} must be a positive integer.")

    return value

ROOT_DIRECTORY = Path(args.directory).resolve()
WEB_DIRECTORY = ROOT_DIRECTORY / "src"
UPLOAD_DIRECTORY = ROOT_DIRECTORY / "uploads"
PUBLIC_DOWNLOADS_DIRECTORY = ROOT_DIRECTORY / "shared"
USER_FILE = ROOT_DIRECTORY / "json" / "users.json"
MESSAGE_FILE = ROOT_DIRECTORY / "json" / "messages.json"
OWNER_USERNAME = os.environ.get("FILESERVER_OWNER_USERNAME")
SESSION_TTL_SECONDS = positive_environment_int("FILESERVER_SESSION_TTL", 28800)
SECURE_COOKIE = os.environ.get("FILESERVER_SECURE_COOKIE", "0") == "1"

SESSIONS = {}
RATE_LIMITS = {}
RATE_LIMIT_LOCK = threading.Lock()
BLOCKED_UPLOAD_EXTENSIONS = {
    ".bat", ".cmd", ".css", ".hta", ".htm", ".html", ".js", ".mjs",
    ".php", ".py", ".ps1", ".sh", ".svg", ".xml", ".xhtml",
}
MEDIA_AUTO_APPROVED_ROLES = {"owner", "admin", "moderator"}


def load_users():
    if not USER_FILE.exists():
        return {}

    try:
        raw_users = json.loads(USER_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    users = {}
    for username, value in raw_users.items():
        if isinstance(value, str):
            users[username] = {
                "password": value,
                "role": "owner" if username == OWNER_USERNAME else "user",
                "media_viewing": "approved" if username == OWNER_USERNAME else "none",
            }
        elif isinstance(value, dict) and isinstance(value.get("password"), str):
            role = value.get("role", "user")
            users[username] = {
                "password": value["password"],
                "role": role if role in {"owner", "admin", "moderator", "user"} else "user",
                "media_viewing": value.get(
                    "media_viewing",
                    "approved" if role in MEDIA_AUTO_APPROVED_ROLES else "none",
                ),
            }

    if users and not any(user["role"] == "owner" for user in users.values()):
        owner_username = OWNER_USERNAME if OWNER_USERNAME in users else next(iter(users))
        users[owner_username]["role"] = "owner"
        users[owner_username]["media_viewing"] = "approved"

    return users


def save_users(users):
    save_json(USER_FILE, users)


def load_messages():
    if not MESSAGE_FILE.exists():
        return []

    try:
        messages = json.loads(MESSAGE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    return messages if isinstance(messages, list) else []


def save_messages(messages):
    save_json(MESSAGE_FILE, messages)


def save_json(path, value):
    path.parent.mkdir(exist_ok=True)
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary_file:
            json.dump(value, temporary_file, indent=2)
            temporary_file.write("\n")
            temporary_path = temporary_file.name

        os.replace(temporary_path, path)
    finally:
        if temporary_path:
            Path(temporary_path).unlink(missing_ok=True)


def rate_limit_key(handler, bucket):
    return bucket, handler.client_address[0]


def allow_request(handler, bucket, limit, window_seconds):
    now = time.monotonic()
    key = rate_limit_key(handler, bucket)

    with RATE_LIMIT_LOCK:
        timestamps = [
            timestamp
            for timestamp in RATE_LIMITS.get(key, [])
            if now - timestamp < window_seconds
        ]
        if len(timestamps) >= limit:
            RATE_LIMITS[key] = timestamps
            return False

        timestamps.append(now)
        RATE_LIMITS[key] = timestamps
        return True


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200_000,
    ).hex()

    return f"{salt}${password_hash}"


def verify_password(password, stored_hash):
    try:
        salt, expected_hash = stored_hash.split("$", 1)
    except ValueError:
        return False

    actual_hash = hash_password(password, salt).split("$", 1)[1]

    return hmac.compare_digest(actual_hash, expected_hash)


def user_role(username):
    user = load_users().get(username)
    return user["role"] if user else None


class FileServerHandler(SimpleHTTPRequestHandler):
    DEFAULT_MAX_UPLOAD_SIZE = 32 * 1024 * 1024 * 1024
    MAX_UPLOAD_SIZE = positive_environment_int(
        "FILESERVER_MAX_UPLOAD_SIZE",
        DEFAULT_MAX_UPLOAD_SIZE,
    )

    def translate_path(self, path):
        request_path = urlsplit(path).path

        if request_path.startswith("/uploads/"):
            relative_path = Path(unquote(request_path[len("/uploads/"):]))
            if relative_path.is_absolute() or ".." in relative_path.parts:
                return str(UPLOAD_DIRECTORY / "__invalid__")
            return str(UPLOAD_DIRECTORY / relative_path)

        return super().translate_path(path)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        if urlsplit(self.path).path in {"/", "/files", "/index.html", "/auth.html", "/styles.css"}:
            self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()

    def current_user(self):
        cookies = SimpleCookie(self.headers.get("Cookie", ""))
        session_cookie = cookies.get("session")

        if session_cookie is None:
            return None

        session = SESSIONS.get(session_cookie.value)
        if not session:
            return None

        if session["expires_at"] <= time.time():
            SESSIONS.pop(session_cookie.value, None)
            return None

        session["expires_at"] = time.time() + SESSION_TTL_SECONDS
        return session["username"]

    def session_csrf_token(self):
        cookies = SimpleCookie(self.headers.get("Cookie", ""))
        session_cookie = cookies.get("session")
        session = SESSIONS.get(session_cookie.value) if session_cookie else None
        return session.get("csrf_token") if session else None

    def require_csrf(self):
        supplied_token = self.headers.get("X-CSRF-Token", "")
        expected_token = self.session_csrf_token()
        if expected_token and hmac.compare_digest(supplied_token, expected_token):
            return True

            self.send_json(403, {"error": "CSRF validation failed."})
        return False

    def require_rate_limit(self, bucket, limit, window_seconds):
        if allow_request(self, bucket, limit, window_seconds):
            return True

        self.send_json(
            429,
            {"error": "Too many requests. Please try again later."},
            {"Retry-After": str(window_seconds)},
        )
        return False

    def require_login(self):
        if self.current_user():
            return True

        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()
        return False

    def require_roles(self, *roles):
        username = self.current_user()
        if username and user_role(username) in roles:
            return True

        self.send_json(403, {"error": "You do not have permission to perform this action."})
        return False

    def has_media_viewing_permission(self):
        username = self.current_user()
        user = load_users().get(username) if username else None
        return user and (
            user["role"] in MEDIA_AUTO_APPROVED_ROLES
            or user.get("media_viewing") == "approved"
        )

    def require_media_viewing(self):
        if self.has_media_viewing_permission():
            return True

        self.send_json(
            403,
            {"error": "Owner approval is required to view files."},
        )
        return False

    def send_json(self, status, data, extra_headers=None):
        response = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))

        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)

        self.end_headers()
        self.wfile.write(response)

    def project_path(self, path):
        relative_path = Path(unquote(path[len("/shared/"):]))
        if relative_path.is_absolute() or ".." in relative_path.parts:
            return None

        project_root = PUBLIC_DOWNLOADS_DIRECTORY.resolve()
        candidate = (project_root / relative_path).resolve()
        try:
            candidate.relative_to(project_root)
        except ValueError:
            return None
        return candidate

    def project_files(self):
        PUBLIC_DOWNLOADS_DIRECTORY.mkdir(parents=True, exist_ok=True)
        project_root = PUBLIC_DOWNLOADS_DIRECTORY.resolve()
        files = []
        for file_path in PUBLIC_DOWNLOADS_DIRECTORY.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                relative_path = file_path.resolve().relative_to(project_root)
            except ValueError:
                continue
            files.append(relative_path.as_posix())
        return sorted(files)

    def upload_path(self, relative_path=""):
        relative = Path(unquote(relative_path or ""))
        if relative.is_absolute() or ".." in relative.parts:
            return None

        upload_root = UPLOAD_DIRECTORY.resolve()
        candidate = (upload_root / relative).resolve()
        try:
            candidate.relative_to(upload_root)
        except ValueError:
            return None
        return candidate

    def upload_entries(self, relative_path=""):
        directory = self.upload_path(relative_path)
        if directory is None or not directory.is_dir():
            return None

        root = UPLOAD_DIRECTORY.resolve()
        entries = []
        for entry in directory.iterdir():
            if entry.is_dir():
                entry_type = "folder"
            elif entry.is_file():
                entry_type = "file"
            else:
                continue
            entries.append({
                "name": entry.name,
                "path": entry.resolve().relative_to(root).as_posix(),
                "type": entry_type,
            })
        return sorted(entries, key=lambda entry: (entry["type"] != "folder", entry["name"].lower()))

    def send_project_download(self, path):
        file_path = self.project_path(path)
        if file_path is None or not file_path.is_file():
            self.send_error(404, "File not found.")
            return

        try:
            file_size = file_path.stat().st_size
            content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
            download_name = quote(file_path.name)
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{download_name}")
            self.send_header("Content-Length", str(file_size))
            self.end_headers()
            with file_path.open("rb") as project_file:
                shutil.copyfileobj(project_file, self.wfile)
        except OSError:
            self.send_error(404, "File not found.")

    def do_GET(self):
        path = urlsplit(self.path).path

        if path in {
            "/users.json",
            "/messages.json",
            "/server.py",
            "/startserver.bat",
        }:
            self.send_error(404, "File not found.")
            return

        if path == "/":
            if self.current_user():
                self.send_response(302)
                self.send_header("Location", "/files")
                self.end_headers()
                return

            self.path = "/auth.html"
            super().do_GET()
            return

        if path == "/files":
            if not self.require_login():
                return

            self.path = "/index.html"
            super().do_GET()
            return

        if path == "/shared":
            self.path = "/shared.html"
            super().do_GET()
            return

        if path == "/roles":
            if not self.require_roles("owner"):
                return

            self.path = "/roles.html"
            super().do_GET()
            return

        if path == "/roles.html":
            if not self.require_roles("owner"):
                return

            super().do_GET()
            return

        if path == "/management":
            if not self.require_roles("owner"):
                return

            self.path = "/management.html"
            super().do_GET()
            return

        if path == "/management.html":
            if not self.require_roles("owner"):
                return

            super().do_GET()
            return

        if path in ("/auth.html", "/styles.css"):
            super().do_GET()
            return

        if path == "/api/shared":
            self.send_json(200, self.project_files())
            return

        if path == "/api/auth/session":
            username = self.current_user()
            user = load_users().get(username) if username else None
            self.send_json(
                200,
                {
                    "authenticated": bool(username),
                    "username": username,
                    "role": user_role(username) if username else None,
                    "mediaViewing": (
                        user and (
                            user["role"] in MEDIA_AUTO_APPROVED_ROLES
                            or user.get("media_viewing") == "approved"
                        )
                    ),
                    "mediaViewingStatus": user.get("media_viewing") if user else None,
                    "csrfToken": self.session_csrf_token() if username else None,
                },
            )
            return

        if path == "/api/files":
            if not self.require_roles("owner", "admin", "moderator", "user"):
                return

            if not self.require_media_viewing():
                return

            UPLOAD_DIRECTORY.mkdir(exist_ok=True)
            relative_path = parse_qs(urlsplit(self.path).query).get("path", [""])[0]
            entries = self.upload_entries(relative_path)
            if entries is None:
                self.send_json(404, {"error": "Folder not found."})
                return

            self.send_json(200, {"path": relative_path, "entries": entries})
            return

        if path == "/api/users":
            if not self.require_roles("owner"):
                return

            users = [
                {"username": username, "role": user["role"]}
                for username, user in load_users().items()
            ]
            self.send_json(200, users)
            return

        if path == "/api/media-access":
            if not self.require_roles("owner"):
                return

            self.send_json(
                200,
                [
                    {
                        "username": username,
                        "role": user["role"],
                        "status": user.get("media_viewing", "none"),
                    }
                    for username, user in load_users().items()
                    if user["role"] == "user"
                ],
            )
            return

        if path == "/api/messages":
            if not self.require_login():
                return

            self.send_json(200, load_messages())
            return

        if path.startswith("/uploads/"):
            if not self.require_roles("owner", "admin", "moderator", "user"):
                return

            if not self.require_media_viewing():
                return

            if Path(unquote(path[len("/uploads/"):])).suffix.lower() in BLOCKED_UPLOAD_EXTENSIONS:
                self.send_error(404, "File not found.")
                return

            super().do_GET()
            return

        if path.startswith("/shared/"):
            self.send_project_download(path)
            return

        if not self.require_login():
            return

        super().do_GET()

    def do_POST(self):
        path = urlsplit(self.path).path

        if path in ("/api/auth/login", "/api/auth/signup"):
            self.handle_authentication(path)
            return

        if not self.require_rate_limit("write", 120, 60):
            return

        if path.startswith("/api/users/") and path.endswith("/role"):
            self.handle_role_assignment(path)
            return

        if path == "/api/media-access/request":
            self.handle_media_access_request()
            return

        if path.startswith("/api/media-access/"):
            self.handle_media_access_decision(path)
            return

        if path == "/api/auth/logout":
            self.handle_logout()
            return

        if path == "/api/messages":
            self.handle_message_creation()
            return

        if path in ("/upload", "/shared/upload"):
            if not self.require_roles("owner", "admin"):
                return

            target_directory = PUBLIC_DOWNLOADS_DIRECTORY if path == "/shared/upload" else UPLOAD_DIRECTORY
            if path == "/upload":
                relative_path = parse_qs(urlsplit(self.path).query).get("path", [""])[0]
                target_directory = self.upload_path(relative_path)
                if target_directory is None:
                    self.send_json(400, {"error": "Virheellinen kansio."})
                    return
            self.handle_upload(target_directory, relative_path if path == "/upload" else "")
            return

        if path == "/api/folders":
            self.handle_folder_creation()
            return

        if path == "/api/files/move":
            self.handle_item_move()
            return

        if not self.require_login():
            return

        self.send_error(404, "Unknown POST endpoint.")

    def handle_authentication(self, path):
        if not self.require_rate_limit("auth", 10, 300):
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(
                400,
                {"error": "Invalid request size."},
            )
            return

        if content_length > 10_000:
            self.send_json(
                413,
                {"error": "Request is too large."},
            )
            return

        body = self.rfile.read(content_length).decode("utf-8")
        fields = parse_qs(body)

        username = fields.get("username", [""])[0].strip()
        password = fields.get("password", [""])[0]

        if not username or not password:
            self.send_json(
                400,
                {"error": "Username and password are required."},
            )
            return

        if len(username) > 64 or len(password) > 256:
            self.send_json(
                400,
                {"error": "Username or password is too long."},
            )
            return

        users = load_users()

        if path == "/api/auth/signup":
            if username in users:
                self.send_json(
                    409,
                    {"error": "Username is already in use."},
                )
                return

            first_account = not users
            users[username] = {
                "password": hash_password(password),
                "role": "owner" if first_account else "user",
                "media_viewing": "approved" if first_account else "none",
            }
            save_users(users)

        else:
            stored_hash = users.get(username, {}).get("password")

            if stored_hash is None or not verify_password(
                password,
                stored_hash,
            ):
                self.send_json(
                    401,
                    {"error": "Incorrect username or password."},
                )
                return

        session_id = secrets.token_urlsafe(32)
        SESSIONS[session_id] = {
            "username": username,
            "csrf_token": secrets.token_urlsafe(32),
            "expires_at": time.time() + SESSION_TTL_SECONDS,
        }
        secure_cookie = "; Secure" if SECURE_COOKIE else ""

        self.send_json(
            200,
            {"ok": True, "csrfToken": SESSIONS[session_id]["csrf_token"]},
            {
                "Set-Cookie": (
                    f"session={session_id}; "
                    f"Path=/; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; SameSite=Strict"
                    f"{secure_cookie}"
                )
            },
        )

    def handle_role_assignment(self, path):
        if not self.require_roles("owner"):
            return

        if not self.require_csrf():
            return

        username = unquote(path[len("/api/users/"):-len("/role")])
        users = load_users()
        target = users.get(username)

        if target is None:
            self.send_json(404, {"error": "User not found."})
            return

        if username == self.current_user():
            self.send_json(400, {"error": "Omistajan roolia ei voi vaihtaa."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid request."})
            return

        fields = parse_qs(self.rfile.read(content_length).decode("utf-8"))
        role = fields.get("role", [""])[0]

        if role not in {"admin", "moderator", "user"}:
            self.send_json(400, {"error": "Virheellinen rooli."})
            return

        target["role"] = role
        save_users(users)
        self.send_json(200, {"ok": True, "username": username, "role": role})

    def handle_media_access_request(self):
        if not self.require_login() or not self.require_csrf():
            return

        username = self.current_user()
        users = load_users()
        user = users.get(username)

        if user is None:
            self.send_json(401, {"error": "Kirjautuminen vaaditaan."})
            return

        if user["role"] in MEDIA_AUTO_APPROVED_ROLES or user.get("media_viewing") == "approved":
            self.send_json(200, {"ok": True, "status": "approved"})
            return

        user["media_viewing"] = "pending"
        save_users(users)
        self.send_json(200, {"ok": True, "status": "pending"})

    def handle_media_access_decision(self, path):
        if not self.require_roles("owner"):
            return

        if not self.require_csrf():
            return

        username = unquote(path[len("/api/media-access/"):])
        users = load_users()
        target = users.get(username)

        if target is None or target["role"] == "owner":
            self.send_json(404, {"error": "User not found."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid request."})
            return

        fields = parse_qs(self.rfile.read(content_length).decode("utf-8"))
        status = fields.get("status", [""])[0]

        if status not in {"approved", "denied"}:
            self.send_json(400, {"error": "Invalid access status."})
            return

        target["media_viewing"] = status
        save_users(users)
        self.send_json(200, {"ok": True, "username": username, "status": status})

    def handle_message_creation(self):
        if not self.require_login():
            return

        if not self.require_media_viewing():
            return

        if not self.require_csrf():
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid request."})
            return

        if content_length > 2_500:
            self.send_json(413, {"error": "Message is too long."})
            return

        fields = parse_qs(self.rfile.read(content_length).decode("utf-8"))
        content = fields.get("content", [""])[0].strip()

        if not content:
            self.send_json(400, {"error": "Message cannot be empty."})
            return

        if len(content) > 2_000:
            self.send_json(400, {"error": "Message can contain at most 2000 characters."})
            return

        messages = load_messages()
        message = {
            "id": secrets.token_urlsafe(12),
            "username": self.current_user(),
            "content": content,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
        messages.append(message)
        save_messages(messages)
        self.send_json(201, message)

    def handle_logout(self):
        if not self.require_login() or not self.require_csrf():
            return

        cookies = SimpleCookie(self.headers.get("Cookie", ""))
        session_cookie = cookies.get("session")

        if session_cookie is not None:
            SESSIONS.pop(session_cookie.value, None)

        secure_cookie = "; Secure" if SECURE_COOKIE else ""
        self.send_json(
            200,
            {"ok": True},
            {
                "Set-Cookie": (
                    "session=; Path=/; Max-Age=0; "
                    f"HttpOnly; SameSite=Strict{secure_cookie}"
                )
            },
        )

    def handle_upload(self, target_directory, relative_path=""):
        if not self.require_csrf():
            return

        content_length = self.headers.get("Content-Length")

        if content_length is None:
            self.send_error(411, "Content-Length is required.")
            return

        try:
            content_length = int(content_length)
        except ValueError:
            self.send_error(400, "Invalid Content-Length.")
            return

        if content_length < 0:
            self.send_json(400, {"error": "Invalid request size."})
            return

        content_type = self.headers.get("Content-Type")

        if content_type is None:
            self.send_error(400, "Content-Type is required.")
            return

        body = self.rfile.read(content_length)

        message = BytesParser(policy=default).parsebytes(
            f"Content-Type: {content_type}\r\n"
            "MIME-Version: 1.0\r\n"
            "\r\n"
            .encode()
            + body
        )

        uploaded_filename = None
        uploaded_data = None

        for part in message.iter_parts():
            if part.get_param(
                "name",
                header="content-disposition",
            ) == "file":
                uploaded_filename = part.get_filename()
                uploaded_data = part.get_payload(decode=True)
                break

        if not uploaded_filename or uploaded_data is None:
            self.send_error(400, "No file was uploaded.")
            return

        if len(uploaded_data) > self.MAX_UPLOAD_SIZE:
            self.send_json(
                413,
                {
                    "error": "Tiedosto on liian suuri.",
                    "receivedBytes": len(uploaded_data),
                    "limitBytes": self.MAX_UPLOAD_SIZE,
                },
            )
            return

        target_directory.mkdir(parents=True, exist_ok=True)

        # Browsers may include a local path in the multipart filename.
        safe_filename = Path(uploaded_filename.replace("/", "\\")).name
        if (
            not safe_filename
            or len(safe_filename) > 180
            or any(ord(character) < 32 for character in safe_filename)
            or Path(safe_filename).suffix.lower() in BLOCKED_UPLOAD_EXTENSIONS
        ):
            self.send_error(400, "Unsafe filename or file type.")
            return

        upload_root = target_directory.resolve()
        destination = (upload_root / safe_filename).resolve()

        if destination.parent != upload_root:
            self.send_error(400, "Invalid filename.")
            return

        if destination.exists():
            self.send_error(
                409,
                "A file with that name already exists.",
            )
            return

        destination.write_bytes(uploaded_data)

        self.send_json(
            201,
            {
                "ok": True,
                "filename": f"{relative_path}/{safe_filename}" if relative_path else safe_filename,
                "contentType": mimetypes.guess_type(safe_filename)[0]
                or "application/octet-stream",
            },
        )

    def read_form_fields(self):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return {}
        if content_length < 0 or content_length > 20_000:
            return {}
        return {
            key: values[0]
            for key, values in parse_qs(self.rfile.read(content_length).decode("utf-8")).items()
            if values
        }

    def handle_folder_creation(self):
        if not self.require_roles("owner", "admin") or not self.require_csrf():
            return

        fields = self.read_form_fields()
        name = fields.get("name", "").strip()
        parent_path = fields.get("path", "")
        parent = self.upload_path(parent_path)
        if parent is None or not name or name in {".", ".."} or "/" in name or "\\" in name:
            self.send_json(400, {"error": "Virheellinen kansion nimi."})
            return
        if len(name) > 180 or any(ord(character) < 32 for character in name):
            self.send_json(400, {"error": "Virheellinen kansion nimi."})
            return

        parent.mkdir(parents=True, exist_ok=True)
        folder = (parent / name).resolve()
        if folder.parent != parent.resolve():
            self.send_json(400, {"error": "Virheellinen kansio."})
            return
        try:
            folder.mkdir()
        except FileExistsError:
            self.send_json(409, {"error": "Samanniminen kansio on jo olemassa."})
            return

        self.send_json(201, {"ok": True})

    def handle_item_move(self):
        if not self.require_roles("owner", "admin") or not self.require_csrf():
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(content_length))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid request."})
            return

        source = self.upload_path(payload.get("source", ""))
        destination_directory = self.upload_path(payload.get("destination", ""))
        if source is None or destination_directory is None or not source.exists() or not destination_directory.is_dir():
            self.send_json(404, {"error": "Source or destination folder not found."})
            return
        if source == destination_directory or (
            source.is_dir() and source in destination_directory.parents
        ):
            self.send_json(400, {"error": "The item cannot be moved into this folder."})
            return

        destination = destination_directory / source.name
        if destination.exists():
            self.send_json(409, {"error": "Samanniminen kohde on jo olemassa."})
            return
        shutil.move(str(source), str(destination))
        self.send_json(200, {"ok": True})

    def do_DELETE(self):
        if not self.require_rate_limit("write", 120, 60):
            return

        path = urlsplit(self.path).path

        if path.startswith("/api/messages/"):
            if not self.require_roles("owner", "admin", "moderator"):
                return

            if not self.require_csrf():
                return

            message_id = unquote(path[len("/api/messages/"):])
            messages = load_messages()
            remaining = [message for message in messages if message.get("id") != message_id]

            if len(remaining) == len(messages):
                self.send_json(404, {"error": "Message not found."})
                return

            save_messages(remaining)
            self.send_response(204)
            self.end_headers()
            return

        if path.startswith("/api/shared/"):
            if not self.require_roles("owner", "admin"):
                return

            if not self.require_csrf():
                return

            project_path = self.project_path("/shared/" + path[len("/api/shared/"):])
            if project_path is None or not project_path.is_file():
                self.send_json(404, {"error": "File not found."})
                return

            project_path.unlink()

            self.send_response(204)
            self.end_headers()
            return

        if not self.require_roles("owner", "admin"):
            return

        if not self.require_csrf():
            return

        prefix = "/api/files/"

        if not path.startswith(prefix):
            self.send_error(404, "File not found.")
            return

        filename = unquote(path[len(prefix):])
        destination = self.upload_path(filename)

        if destination is None:
            self.send_error(400, "Invalid filename.")
            return

        if not destination.is_file() and not destination.is_dir():
            self.send_error(404, "File not found.")
            return

        if destination.is_dir():
            shutil.rmtree(destination)
        else:
            destination.unlink()

        self.send_response(204)
        self.end_headers()


handler = partial(
    FileServerHandler,
    directory=str(WEB_DIRECTORY),
)

server = ThreadingHTTPServer(
    (args.host, args.port),
    handler,
)

if args.host not in {"127.0.0.1", "::1", "localhost"} and not SECURE_COOKIE:
    print("Warning: non-localhost binding is using cookies without the Secure flag.")
    print("Set FILESERVER_SECURE_COOKIE=1 when serving MediaBox over HTTPS.")

print(f"Server running at http://{args.host}:{args.port}")

try:
    server.serve_forever()
except KeyboardInterrupt:
    print("\nServer stopped.")
finally:
    server.server_close()