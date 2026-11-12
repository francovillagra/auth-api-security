"""Una API de mentira que contesta lo mismo que la real (los mismos códigos y mensajes), para probar la consola sin Docker ni Node.

Copia el comportamiento de app/api/**, proxy.ts y lib/*.ts que la consola usa: rate limit de 5 pedidos cada 10 segundos por `x-real-ip` sobre
/api/auth/*, llaves HS256 con emisor y audiencia, refresh tokens de un solo uso con detección de reutilización, rol leído de la base en cada
pedido, validación de cuerpos (415/413/400) y el registro en formato Winston.

Cada protección se puede apagar para comprobar que la consola informa lo que la API hace de verdad y no un resultado de antemano
(ver test_scenarios.py). La prueba de humo contra la API real (smoke.py) es la que confirma que esta copia no se aparta del original.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

from common import SAMPLE_CUSTOMERS

ISSUER = "auth-api-security"
RATE_LIMIT = 5
RATE_WINDOW = 10.0
MAX_JSON_BYTES = 8 * 1024
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FakeApi:
    def __init__(
        self,
        shared_dir: Path,
        admin_password: str,
        *,
        rate_limit: bool = True,
        reuse_detection: bool = True,
        verify_signature: bool = True,
        rbac_from_db: bool = True,
        validate_input: bool = True,
        revoke_access_on_logout: bool = False,
        check_roles: bool = True,
        leak_passwords: bool = False,
        trust_real_ip: bool = True,
        admin_email: str = "admin@tienda-demo.test",
        customers: tuple[tuple[str, str], ...] = tuple(SAMPLE_CUSTOMERS),     # los mismos que carga seed.mjs en la base verdadera
    ) -> None:
        self.log_path = shared_dir / "api.log"
        self.flags = dict(
            rate_limit=rate_limit, reuse_detection=reuse_detection, verify_signature=verify_signature, rbac_from_db=rbac_from_db,
            validate_input=validate_input, revoke_access_on_logout=revoke_access_on_logout, check_roles=check_roles,
            leak_passwords=leak_passwords, trust_real_ip=trust_real_ip,
        )
        self.secret = secrets.token_urlsafe(48)
        self.refresh_secret = secrets.token_urlsafe(48)
        self._lock = threading.RLock()
        self.users: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}      # jti -> {family, user_id, revoked}
        self.revoked_users_at: dict[str, int] = {}   # usuario -> segundo hasta el cual sus llaves de acceso quedaron anuladas
        self.buckets: dict[str, list[float]] = {}   # ip -> [contador, vence]
        self.requests: list[tuple[str, str, int, str]] = []   # (método, ruta, estado, ip): lo que vio la API
        self.available = True                   # False: simula una API apagada
        self.broken_paths: set[str] = set()     # rutas que contestan 500
        self._add_user(admin_email, admin_password, "Administración (práctica)", "ADMIN")
        for name, email in customers:
            self._add_user(email, secrets.token_urlsafe(18), name, "USER")
        self._server: Optional[ThreadingHTTPServer] = None

    # -- datos ------------------------------------------------------------------------------------------------------------
    def _add_user(self, email: str, password: str, name: Optional[str], role: str) -> dict:
        user = {
            "id": str(uuid.uuid4()), "email": email, "password": password, "name": name, "role": role,
            "createdAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }
        self.users[email] = user
        return user

    def by_id(self, user_id: str) -> Optional[dict]:
        return next((u for u in self.users.values() if u["id"] == user_id), None)

    @staticmethod
    def public(user: dict) -> dict:
        return {k: user[k] for k in ("id", "email", "name", "role", "createdAt")}

    # -- llaves -----------------------------------------------------------------------------------------------------------
    def _sign(self, payload: dict, secret: str) -> str:
        head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
        body = _b64(json.dumps(payload, separators=(",", ":")).encode())
        signature = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
        return f"{head}.{body}.{_b64(signature)}"

    def access_token(self, user: dict) -> str:
        now = int(time.time())
        return self._sign(
            {"userId": user["id"], "email": user["email"], "role": user["role"], "iat": now, "exp": now + 900, "aud": f"{ISSUER}:access",
             "iss": ISSUER, "sub": user["id"]}, self.secret,
        )

    def refresh_token(self, user: dict, jti: str) -> str:
        now = int(time.time())
        return self._sign(
            {"userId": user["id"], "email": user["email"], "role": user["role"], "iat": now, "exp": now + 7 * 86400, "aud": f"{ISSUER}:refresh",
             "iss": ISSUER, "sub": user["id"], "jti": jti}, self.refresh_secret,
        )

    def verify(self, token: str, use: str) -> Optional[dict]:
        try:
            head_b64, body_b64, sig_b64 = token.split(".")
            header = json.loads(_unb64(head_b64))
            claims = json.loads(_unb64(body_b64))
        except (ValueError, TypeError):
            return None
        if not isinstance(claims, dict) or not isinstance(header, dict):
            return None
        if self.flags["verify_signature"]:
            secret = self.secret if use == "access" else self.refresh_secret
            expected = _b64(hmac.new(secret.encode(), f"{head_b64}.{body_b64}".encode(), hashlib.sha256).digest())
            if header.get("alg") != "HS256" or not hmac.compare_digest(expected, sig_b64):
                return None
            if claims.get("iss") != ISSUER or claims.get("aud") != f"{ISSUER}:{use}":
                return None
        if float(claims.get("exp", 0)) < time.time() or not isinstance(claims.get("userId"), str):
            return None
        return claims

    # -- sesiones -----------------------------------------------------------------------------------------------------------
    def start_session(self, user: dict) -> str:
        jti = str(uuid.uuid4())
        self.tokens[jti] = {"family": str(uuid.uuid4()), "user_id": user["id"], "revoked": False}
        return self.refresh_token(user, jti)

    def _revoke_family(self, family: str) -> None:
        for stored in self.tokens.values():
            if stored["family"] == family:
                stored["revoked"] = True

    def rotate(self, raw: str) -> Optional[tuple[dict, str]]:
        claims = self.verify(raw, "refresh")
        if not claims or not isinstance(claims.get("jti"), str):
            return None
        stored = self.tokens.get(claims["jti"])
        if not stored or stored["user_id"] != claims["userId"]:
            return None
        if stored["revoked"]:
            if self.flags["reuse_detection"]:
                self._revoke_family(stored["family"])
                self.log("warn", f"Refresh token reuse detected: user {stored['user_id']}, session {stored['family']} revoked")
            return None
        user = self.by_id(stored["user_id"])
        if not user:
            return None
        stored["revoked"] = True
        jti = str(uuid.uuid4())
        self.tokens[jti] = {"family": stored["family"], "user_id": user["id"], "revoked": False}
        return user, self.refresh_token(user, jti)

    # -- registro -------------------------------------------------------------------------------------------------------------
    def log(self, level: str, message: str) -> None:
        colors = {"info": "32", "warn": "33", "error": "31"}
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} [\x1b[{colors[level]}m{level}\x1b[39m]: {message}\n")

    def raw_log(self, line: str) -> None:
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    # -- rate limit ---------------------------------------------------------------------------------------------------------------
    def limited(self, ip: str) -> Optional[int]:
        """None si pasa; si no, los segundos que faltan para que se libere."""
        now = time.monotonic()
        with self._lock:
            record = self.buckets.get(f"auth:{ip}")
            if record is None or record[1] <= now:
                self.buckets[f"auth:{ip}"] = [1, now + RATE_WINDOW]
                return None
            if record[0] >= RATE_LIMIT:
                return max(1, int(record[1] - now + 0.999))
            record[0] += 1
            return None

    # -- servidor -----------------------------------------------------------------------------------------------------------------
    def start(self) -> str:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "fake"
            sys_version = ""

            def log_message(self, *args) -> None:
                pass

            def _reply(self, status: int, payload: Any = None, headers: Optional[dict] = None) -> None:
                body = b"" if payload is None else json.dumps(payload).encode()
                self.send_response(status)
                if payload is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

            def _ip(self) -> str:
                real = self.headers.get("x-real-ip", "").strip() if fake.flags["trust_real_ip"] else ""
                return real or "anonymous"

            def _bearer(self) -> Optional[str]:
                match = re.match(r"^Bearer\s+(\S+)$", self.headers.get("Authorization", ""), re.I)
                return match.group(1) if match else None

            def _json_body(self, validate) -> Optional[dict]:
                """Devuelve el cuerpo ya validado, o None después de contestar el error (415, 413 o 400)."""
                if fake.flags["validate_input"]:
                    if not re.match(r"^application/json\s*(;|$)", self.headers.get("Content-Type", ""), re.I):
                        self._reply(415, {"error": "Content-Type must be application/json"})
                        return None
                    if int(self.headers.get("Content-Length") or 0) > MAX_JSON_BYTES:
                        self._reply(413, {"error": "Request body too large"})
                        return None
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    data = json.loads(raw)
                except ValueError:
                    self._reply(400, {"error": "Invalid JSON"})
                    return None
                problems = validate(data) if fake.flags["validate_input"] else None
                if problems or not isinstance(data, dict):
                    self._reply(400, {"error": "Validation failed", "details": problems or {}})
                    return None
                return data

            def _auth_user(self) -> Optional[dict]:
                token = self._bearer()
                claims = fake.verify(token, "access") if token else None
                if claims and fake.flags["revoke_access_on_logout"]:
                    if int(claims.get("iat", 0)) <= fake.revoked_users_at.get(claims["userId"], -1):
                        return None
                return claims

            def _require_role(self, allowed: tuple[str, ...]) -> Optional[dict]:
                claims = self._auth_user()
                if not claims:
                    self._reply(401, {"error": "Unauthorized", "message": "Token de autenticación faltante, inválido o expirado."})
                    return None
                user = fake.by_id(claims["userId"])
                if not user:
                    self._reply(401, {"error": "Unauthorized", "message": "Token de autenticación faltante, inválido o expirado."})
                    return None
                role = user["role"] if fake.flags["rbac_from_db"] else claims.get("role")
                if fake.flags["check_roles"] and role not in allowed:
                    self._reply(403, {"error": "Forbidden", "message": "No tenés permisos para realizar esta acción."})
                    return None
                return user

            def _dispatch(self, method: str) -> None:
                path = self.path.split("?")[0]
                started = time.monotonic()
                if not fake.available:
                    self.close_connection = True
                    return
                if path == "/" and method == "GET":
                    body = b"<html><body>Auth API</body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if path in fake.broken_paths:
                    return self._finish(method, path, started, lambda: self._reply(500, {"error": "Internal server error"}))
                with fake._lock:
                    # proxy.ts
                    if path.startswith("/api/auth") and fake.flags["rate_limit"]:
                        wait = fake.limited(self._ip())
                        if wait is not None:
                            fake.raw_log(f"[proxy] 429 rate limited: {self._ip()} → {path}")
                            fake.requests.append((method, path, 429, self._ip()))
                            return self._reply(
                                429, {"error": "Too many requests", "retryAfter": wait},
                                {"Retry-After": str(wait), "X-RateLimit-Limit": "5", "X-RateLimit-Remaining": "0"},
                            )
                    if path.startswith("/api/users") and not re.match(r"^Bearer\s+\S+$", self.headers.get("Authorization", ""), re.I):
                        fake.requests.append((method, path, 401, self._ip()))
                        return self._reply(401, {"error": "Authorization header required"})
                    self._finish(method, path, started, lambda: self._route(method, path))

            def _finish(self, method: str, path: str, started: float, handler) -> None:
                status_holder: list[int] = []
                original = self._reply

                def spy(status, payload=None, headers=None):
                    status_holder.append(status)
                    original(status, payload, headers)

                self._reply = spy  # type: ignore[method-assign]
                try:
                    handler()
                finally:
                    self._reply = original  # type: ignore[method-assign]
                status = status_holder[0] if status_holder else 0
                fake.requests.append((method, path, status, self._ip()))
                fake.log("info", f"{method} {path} {status} — {int((time.monotonic() - started) * 1000)}ms")

            # -- rutas de la API -----------------------------------------------------------------------------------------
            def _route(self, method: str, path: str) -> None:
                if method == "POST" and path == "/api/auth/register":
                    return self._register()
                if method == "POST" and path == "/api/auth/login":
                    return self._login()
                if method == "POST" and path == "/api/auth/refresh":
                    return self._refresh()
                if method == "POST" and path == "/api/auth/logout":
                    return self._logout()
                if method == "GET" and path == "/api/users/me":
                    return self._me()
                if method == "GET" and path == "/api/admin/users":
                    return self._admin_users()
                match = re.fullmatch(r"/api/admin/users/([^/]+)/role", path)
                if method == "PATCH" and match:
                    return self._change_role(match.group(1))
                self._reply(404, {"error": "Not found"})

            def _register(self) -> None:
                def validate(data):
                    problems: dict[str, list[str]] = {}
                    if not isinstance(data, dict):
                        return {"_": ["Expected object"]}
                    email = str(data.get("email", "")).strip().lower()
                    password = str(data.get("password", ""))
                    if not EMAIL_RE.match(email):
                        problems["email"] = ["Invalid email format"]
                    if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password):
                        problems["password"] = ["Password does not meet the rules"]
                    return problems

                data = self._json_body(validate)
                if data is None:
                    return
                email = str(data["email"]).strip().lower()
                if email in fake.users:
                    return self._reply(409, {"error": "Email already registered"})
                user = fake._add_user(email, data["password"], data.get("name"), "USER")
                refresh = fake.start_session(user)
                fake.log("info", f"User registered: {user['id']}")
                self._reply(201, {"user": fake.public(user), "accessToken": fake.access_token(user), "refreshToken": refresh})

            def _login(self) -> None:
                def validate(data):
                    if not isinstance(data, dict):
                        return {"_": ["Expected object"]}
                    problems = {}
                    if not EMAIL_RE.match(str(data.get("email", "")).strip().lower()):
                        problems["email"] = ["Invalid email format"]
                    if not str(data.get("password", "")):
                        problems["password"] = ["Password is required"]
                    return problems

                data = self._json_body(validate)
                if data is None:
                    return
                user = fake.users.get(str(data["email"]).strip().lower())
                if not user or user["password"] != data["password"]:
                    return self._reply(401, {"error": "Invalid credentials"})
                refresh = fake.start_session(user)
                fake.log("info", f"User logged in: {user['id']}")
                self._reply(200, {"user": fake.public(user), "accessToken": fake.access_token(user), "refreshToken": refresh})

            def _refresh(self) -> None:
                data = self._json_body(lambda d: {} if isinstance(d, dict) and d.get("refreshToken") else {"refreshToken": ["Refresh token is required"]})
                if data is None:
                    return
                rotated = fake.rotate(data["refreshToken"])
                if not rotated:
                    return self._reply(401, {"error": "Invalid or expired refresh token"})
                user, refresh = rotated
                fake.log("info", f"Tokens refreshed for: {user['id']}")
                self._reply(200, {"accessToken": fake.access_token(user), "refreshToken": refresh})

            def _logout(self) -> None:
                data = self._json_body(lambda d: {} if isinstance(d, dict) and d.get("refreshToken") else {"refreshToken": ["Refresh token is required"]})
                if data is None:
                    return
                claims = fake.verify(data["refreshToken"], "refresh")
                stored = fake.tokens.get(claims.get("jti")) if claims else None
                if stored:
                    if data.get("everywhere") is True:
                        for item in fake.tokens.values():
                            if item["user_id"] == stored["user_id"]:
                                item["revoked"] = True
                    else:
                        fake._revoke_family(stored["family"])
                    fake.log("info", f"Logout: user {stored['user_id']}, session {stored['family']}")
                    if fake.flags["revoke_access_on_logout"]:
                        fake.revoked_users_at[stored["user_id"]] = int(time.time())
                self._reply(204)

            def _me(self) -> None:
                claims = self._auth_user()
                if not claims:
                    return self._reply(401, {"error": "Invalid or expired token"})
                user = fake.by_id(claims["userId"])
                if not user:
                    return self._reply(404, {"error": "User not found"})
                self._reply(200, {"user": {**fake.public(user), "updatedAt": user["createdAt"]}})

            def _admin_users(self) -> None:
                user = self._require_role(("ADMIN",))
                if not user:
                    return
                users = [fake.public(u) | ({"password": u["password"]} if fake.flags["leak_passwords"] else {}) for u in fake.users.values()]
                self._reply(200, {"users": users, "total": len(users), "requestedBy": {"userId": user["id"], "email": user["email"], "role": user["role"]}})

            def _change_role(self, target_id: str) -> None:
                admin = self._require_role(("ADMIN",))
                if not admin:
                    return
                data = self._json_body(lambda d: {} if isinstance(d, dict) and d.get("role") in ("USER", "ADMIN") else {"role": ["Invalid role"]})
                if data is None:
                    return
                if target_id == admin["id"] and data["role"] != "ADMIN":
                    return self._reply(400, {"error": "Bad Request", "message": "No podés quitarte el rol ADMIN a vos mismo."})
                target = fake.by_id(target_id)
                if not target:
                    return self._reply(404, {"error": "Not Found", "message": "Usuario no encontrado."})
                fake.log("info", f"{admin['id']} changed role of {target['id']}: {target['role']} → {data['role']}")
                target["role"] = data["role"]
                self._reply(200, {"message": "Rol actualizado correctamente.", "user": fake.public(target), "changedBy": admin["email"]})

            def do_GET(self) -> None:  # noqa: N802
                self._dispatch("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._dispatch("POST")

            def do_PATCH(self) -> None:  # noqa: N802
                self._dispatch("PATCH")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=lambda: self._server.serve_forever(poll_interval=0.02), daemon=True).start()
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
