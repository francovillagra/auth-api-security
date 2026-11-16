"""Consola guiada de la demo de Auth API Security.

Una página que recorre la API de inicio de sesión del proyecto en dos partes: primero se la usa como lo haría un cliente de la tienda
(crear la cuenta, ver el perfil, renovar y cerrar la sesión, ver las cuentas como administración) y después se la ataca (adivinar
contraseñas, robar una sesión, fabricar llaves falsas, escalar privilegios, mandar datos mal armados) para ver cómo responde. Cada botón
hace pedidos reales a la API y el veredicto sale de lo que ella contesta, no de un guion.

Usa solo la biblioteca estándar: no hay nada que instalar y el código entero se lee en un rato. Corre dentro de la demo (docker compose),
en una red sin salida a internet; solo la consola se publica, y solo en 127.0.0.1 de la computadora. Aun así rechaza pedidos de otros
sitios web abiertos en el mismo navegador (ver `_host_allowed` y el chequeo de Origin en `do_POST`). Ver demo/README.md.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import signal
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from common import (
    ADMIN_EMAIL, ADMIN_PASSWORD_FILE, DEFAULT_SHARED_DIR, DEFAULT_STATE_DIR, MAIL_DOMAIN, SERVER_LOG, SHOP, TARGET_EMAIL,
)

try:  # importado como paquete (las pruebas)
    from . import api as apimod
    from . import explain, scenarios, serverlog
except ImportError:  # corriendo como script dentro del contenedor
    import api as apimod
    import explain
    import scenarios
    import serverlog

log = logging.getLogger("consola")

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_EVENTS = 60
MAX_BODY = 1024
LISTED_USERS = 12          # cuántas cuentas muestra el listado de administración (el total se informa aparte)
CUSTOMER_NAME = "Cliente de práctica"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


@dataclass(frozen=True)
class Config:
    api_url: str = "http://api:3000"
    public_port: int = 4200            # el puerto con el que el navegador abre la consola (el publicado por docker)
    state_dir: Path = Path(DEFAULT_STATE_DIR)
    shared_dir: Path = Path(DEFAULT_SHARED_DIR)
    admin_email: str = ADMIN_EMAIL
    target_email: str = TARGET_EMAIL   # la cuenta a la que apuntan los ataques de contraseñas
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ.get
        return cls(
            api_url=env("DEMO_API_URL", cls.api_url).rstrip("/"),
            public_port=int(env("DEMO_CONSOLE_PUBLIC_PORT", str(cls.public_port))),
            state_dir=Path(env("DEMO_STATE_DIR", str(cls.state_dir))),
            shared_dir=Path(env("DEMO_SHARED_DIR", str(cls.shared_dir))),
            listen_host=env("DEMO_LISTEN_HOST", cls.listen_host),
            listen_port=int(env("DEMO_LISTEN_PORT", str(cls.listen_port))),
        )

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset({f"localhost:{self.public_port}", f"127.0.0.1:{self.public_port}"})

    @property
    def allowed_origins(self) -> frozenset[str]:
        return frozenset(f"http://{host}" for host in self.allowed_hosts)


def read_secret(directory: Path, name: str) -> str:
    try:
        return (directory / name).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


class Refused(Exception):
    """Algo que se le dice a quien usa la consola, con el código HTTP que corresponde. El mensaje no lleva claves ni detalles internos."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Customer:
    """El cliente del recorrido. Su contraseña y sus llaves viven solo en la memoria de la consola: la página nunca las recibe."""

    email: str
    password: str
    name: str
    access: Optional[str] = None
    refresh: Optional[str] = None
    profile: Optional[dict] = None

    @property
    def session(self) -> str:
        return "active" if self.refresh else "closed"

    def access_expires_at(self) -> Optional[str]:
        exp = apimod.claims(self.access).get("exp") if self.access else None
        if not isinstance(exp, (int, float)):
            return None
        return datetime.fromtimestamp(exp, timezone.utc).isoformat(timespec="seconds")


def too_many() -> Refused:
    return Refused(
        429, f"La API limita los ingresos ({explain.RATE_LIMIT_REQUESTS} cada {explain.RATE_LIMIT_SECONDS} segundos desde una misma dirección). "
        "Esperar unos segundos y probar de nuevo.",
    )


def failed(reply: apimod.Reply, action: str) -> Refused:
    if reply.status == 429:
        return too_many()
    return Refused(502, f"La API no pudo {action} (respondió {reply.status}).")


# -- la demo --------------------------------------------------------------------------------------------------------------

class Demo:
    """Los pasos del recorrido y los ataques. Cada método hace pedidos a la API y deja constancia en «Lo que va pasando»."""

    def __init__(self, config: Config, api: apimod.Api, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.config = config
        self.api = api
        self._clock = clock
        self.origins = apimod.Origins()
        self.admin = apimod.AdminSession(
            api, config.admin_email, lambda: read_secret(config.state_dir, ADMIN_PASSWORD_FILE), apimod.Origins.ADMIN,
        )
        self._lock = threading.Lock()
        self._busy = threading.Lock()   # una prueba a la vez
        self._events: list[dict] = []
        self._seq = 0
        self._customer: Optional[Customer] = None
        self._admin_list: Optional[dict] = None
        self._results: dict[str, dict] = {}
        self._log_floor = 0

    # -- lista de acontecimientos ---------------------------------------------------------------------------------------
    def event(self, text: str, *, ok: bool = True, detail: str = "") -> None:
        with self._lock:
            self._seq += 1
            self._events.append({"n": self._seq, "t": self._clock().isoformat(timespec="seconds"), "text": text, "ok": ok, "detail": detail[:400]})
            del self._events[:-MAX_EVENTS]

    def events(self) -> list[dict]:
        with self._lock:
            return list(self._events)

    # -- el cliente -------------------------------------------------------------------------------------------------------
    def _customer_or_refuse(self) -> Customer:
        with self._lock:
            customer = self._customer
        if customer is None:
            raise Refused(409, "Primero hay que crear la cuenta de cliente.")
        return customer

    def _open_session(self, customer: Customer, reply: apimod.Reply) -> None:
        access, refresh = reply.get("accessToken"), reply.get("refreshToken")
        if not isinstance(access, str) or not isinstance(refresh, str):
            raise Refused(502, "La API contestó sin las llaves esperadas.")
        with self._lock:
            customer.access, customer.refresh = access, refresh

    def create_customer(self) -> None:
        with self._lock:
            if self._customer is not None:
                raise Refused(409, "Ya hay una cuenta de cliente. Para empezar de nuevo, reiniciar el recorrido.")
        email = f"cliente-{secrets.token_hex(3)}@{MAIL_DOMAIN}"
        password = "Aa1-" + secrets.token_urlsafe(12)   # cumple las reglas de la API: mayúscula, minúscula y número
        reply = self.api.request(
            "POST", "/api/auth/register", body={"email": email, "password": password, "name": CUSTOMER_NAME}, ip=apimod.Origins.CUSTOMER,
        )
        if reply.status != 201:
            raise failed(reply, "crear la cuenta")
        customer = Customer(email, password, CUSTOMER_NAME)
        self._open_session(customer, reply)
        with self._lock:
            self._customer = customer
        self.event(
            "Cuenta de cliente creada. La API entregó dos llaves: una de acceso "
            f"({explain.ACCESS_TOKEN_MINUTES} minutos) y una de renovación ({explain.REFRESH_TOKEN_DAYS} días, de un solo uso).",
            detail="La contraseña se guardó cifrada en la base de datos (bcrypt); la API nunca la devuelve.",
        )

    def show_profile(self, anonymous: bool = False) -> dict:
        customer = self._customer_or_refuse()
        if anonymous:
            reply = self.api.request("GET", "/api/users/me", ip=apimod.Origins.CUSTOMER)
            refused = reply.status in (401, 403)
            self.event(
                "Pedido de perfil sin ninguna llave: la API lo rechazó, como corresponde." if refused
                else "Pedido de perfil sin llave: la API contestó algo inesperado.",
                ok=refused, detail=f"Respuesta: {reply.status} ({explain.status_label(reply.status)}).",
            )
            return {"refused": refused, "status": reply.status}
        if not customer.access:
            raise Refused(409, "La sesión está cerrada. Entrar de nuevo para conseguir una llave de acceso.")
        reply = self.api.request("GET", "/api/users/me", token=customer.access, ip=apimod.Origins.CUSTOMER)
        if reply.status == 401:
            raise Refused(409, f"La llave de acceso venció (duran {explain.ACCESS_TOKEN_MINUTES} minutos). Renovar la sesión para conseguir otra.")
        user = reply.get("user")
        if reply.status != 200 or not isinstance(user, dict):
            raise failed(reply, "devolver el perfil")
        with self._lock:
            customer.profile = {
                "email": user.get("email"), "name": user.get("name"), "role": user.get("role"),
                "role_label": explain.role_label(user.get("role")), "created_at": user.get("createdAt"),
            }
        self.event(f"La API reconoció la llave de acceso y devolvió el perfil (rol: {explain.role_label(user.get('role'))}).")
        return {}

    def renew(self) -> None:
        customer = self._customer_or_refuse()
        if not customer.refresh:
            raise Refused(409, "La sesión está cerrada. Entrar de nuevo.")
        reply = self.api.request("POST", "/api/auth/refresh", body={"refreshToken": customer.refresh}, ip=apimod.Origins.CUSTOMER)
        if reply.status == 401:
            with self._lock:
                customer.access = customer.refresh = None
            raise Refused(409, "La API no aceptó la llave de renovación: la sesión ya no está abierta. Entrar de nuevo.")
        if reply.status != 200:
            raise failed(reply, "renovar la sesión")
        self._open_session(customer, reply)
        self.event("Sesión renovada: la llave de renovación se cambió por una nueva y la anterior dejó de servir.")

    def logout(self) -> None:
        customer = self._customer_or_refuse()
        if not customer.refresh:
            raise Refused(409, "La sesión ya está cerrada.")
        reply = self.api.request("POST", "/api/auth/logout", body={"refreshToken": customer.refresh}, ip=apimod.Origins.CUSTOMER)
        if reply.status != 204:
            raise failed(reply, "cerrar la sesión")
        with self._lock:
            customer.access = customer.refresh = None
        self.event("Sesión cerrada: la llave de renovación ya no sirve.")

    def login(self) -> None:
        customer = self._customer_or_refuse()
        if customer.refresh:
            raise Refused(409, "La sesión ya está abierta.")
        reply = self.api.request(
            "POST", "/api/auth/login", body={"email": customer.email, "password": customer.password}, ip=apimod.Origins.CUSTOMER,
        )
        if reply.status != 200:
            raise failed(reply, "iniciar la sesión")
        self._open_session(customer, reply)
        self.event("El cliente volvió a entrar con su contraseña: la API abrió una sesión nueva.")

    # -- la administración --------------------------------------------------------------------------------------------------
    def list_accounts(self) -> None:
        try:
            reply = self.admin.request("GET", "/api/admin/users")
        except apimod.AdminUnavailable as exc:
            raise Refused(503, str(exc)) from None
        users = reply.get("users")
        if reply.status != 200 or not isinstance(users, list):
            raise failed(reply, "dar el listado de cuentas")
        shown = [
            {
                "email": u.get("email"), "name": u.get("name"), "role": u.get("role"), "role_label": explain.role_label(u.get("role")),
                "created_at": u.get("createdAt"),
            }
            for u in users[:LISTED_USERS] if isinstance(u, dict)
        ]
        leaked = any(isinstance(u, dict) and "password" in u for u in users)
        with self._lock:
            self._admin_list = {"total": len(users), "shown": len(shown), "users": shown}
        self.event(
            f"La administración pidió el listado: {len(users)} {explain.plural(len(users), 'cuenta', 'cuentas')}, "
            + ("pero la API incluyó contraseñas." if leaked else "sin contraseñas."),
            ok=not leaked,
        )

    # -- los ataques ----------------------------------------------------------------------------------------------------------
    def run_scenario(self, scenario_id: str) -> dict:
        scenario = scenarios.SCENARIOS.get(scenario_id)
        if scenario is None:
            raise Refused(404, "No existe esa prueba.")
        if not self._busy.acquire(blocking=False):
            raise Refused(409, "Ya hay una prueba en marcha. Esperar a que termine.")
        try:
            lab = scenarios.Lab(self.api, self.origins, self.admin, self.config.target_email)
            try:
                outcome = scenario.run(lab)
            except scenarios.ScenarioError as exc:
                self.event(f"La prueba «{scenario.title}» no pudo completarse.", ok=False, detail=str(exc))
                raise Refused(502, str(exc)) from None
            result = outcome.to_json()
            result.update({"id": scenario.id, "ran_at": self._clock().isoformat(timespec="seconds")})
            with self._lock:
                self._results[scenario.id] = result
            self.event(f"«{scenario.title}»: {outcome.headline}", ok=outcome.held)
            return result
        finally:
            self._busy.release()

    # -- reinicio -------------------------------------------------------------------------------------------------------------
    def reset(self) -> None:
        _, size = serverlog.tail(self.config.shared_dir / SERVER_LOG, 0)
        with self._lock:
            self._customer = None
            self._admin_list = None
            self._results.clear()
            self._events.clear()
            self._log_floor = size
        self.event(
            "Recorrido reiniciado. Las cuentas de práctica que ya se crearon siguen en la base de datos hasta que se apague la demo.",
        )

    # -- estado para la página --------------------------------------------------------------------------------------------------
    def state(self) -> dict:
        with self._lock:
            customer = self._customer
            floor = self._log_floor
            snapshot = {
                "customer": None if customer is None else {
                    "email": customer.email, "name": customer.name, "session": customer.session,
                    "access_expires_at": customer.access_expires_at() if customer.access else None, "profile": customer.profile,
                },
                "admin_list": self._admin_list,
                "results": dict(self._results),
            }
        lines, _ = serverlog.tail(self.config.shared_dir / SERVER_LOG, floor)
        return {
            "api_ready": self.api.healthy(),
            "shop": SHOP,
            "target_email": self.config.target_email,
            "admin_email": self.config.admin_email,
            "limits": {
                "requests": explain.RATE_LIMIT_REQUESTS, "seconds": explain.RATE_LIMIT_SECONDS,
                "access_minutes": explain.ACCESS_TOKEN_MINUTES, "refresh_days": explain.REFRESH_TOKEN_DAYS,
            },
            "catalog": scenarios.CATALOG,
            "events": self.events(),
            "log": lines,
            **snapshot,
        }


# -- HTTP -----------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Asset:
    body: bytes
    content_type: str


def load_assets() -> dict[str, Asset]:
    files = {
        "/": ("index.html", "text/html; charset=utf-8"),
        "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        "/style.css": ("style.css", "text/css; charset=utf-8"),
    }
    return {url: Asset((STATIC_DIR / name).read_bytes(), ctype) for url, (name, ctype) in files.items()}


def create_server(config: Config, demo: Demo) -> ThreadingHTTPServer:
    assets = load_assets()

    class Handler(BaseHTTPRequestHandler):
        server_version = "consola"
        sys_version = ""

        # -- registro y respuestas ------------------------------------------------------------------------------------
        def log_request(self, code="-", size="-") -> None:
            # La página consulta /api/state todo el tiempo: no llenar el registro con eso.
            if str(code) == "200" and self.path.split("?")[0] in ("/api/state", "/healthz"):
                return
            super().log_request(code, size)

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            sys.stderr.write("%s\n" % (format % args))

        def send_response(self, code, message=None) -> None:
            # Igual que la clase base, pero sin la cabecera Server: no hace falta anunciar qué es.
            self.log_request(code)
            self.send_response_only(code, message)

        def _send(self, status: int, body: bytes, content_type: str, extra: Optional[dict[str, str]] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        # -- protección contra otros sitios abiertos en el mismo navegador ----------------------------------------------
        def _host_allowed(self) -> bool:
            # Un sitio ajeno que apunte su dominio a 127.0.0.1 (DNS rebinding) llega con su propio Host: se rechaza.
            return self.headers.get("Host", "").lower() in config.allowed_hosts

        def _run(self, action: Callable[[], Any]) -> None:
            try:
                self._json(200, action())
            except Refused as exc:
                self._json(exc.status, {"error": exc.message})
            except apimod.ApiUnavailable:
                self._json(503, {"error": "No se pudo hablar con la API. Puede estar todavía arrancando: esperar unos segundos."})
            except Exception:  # noqa: BLE001 - un error propio no puede dejar la consola sin responder
                log.exception("Falló %s", self.path)
                self._json(500, {"error": "La consola tuvo un error inesperado (el detalle está en su registro)."})

        # -- rutas ----------------------------------------------------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path == "/healthz":  # sin chequeo de Host: lo consulta docker desde dentro del contenedor
                return self._send(200, b"ok", "text/plain; charset=utf-8")
            if not self._host_allowed():
                return self._json(421, {"error": "host no permitido"})
            asset = assets.get(path)
            if asset:
                return self._send(200, asset.body, asset.content_type)
            if path == "/api/state":
                return self._run(demo.state)
            self._json(404, {"error": "no existe"})

        def _body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise Refused(400, "pedido inválido") from None
            if length > MAX_BODY:
                raise Refused(413, "pedido demasiado grande")
            if not length:
                return {}
            try:
                data = json.loads(self.rfile.read(length))
            except ValueError:
                raise Refused(400, "pedido inválido") from None
            return data if isinstance(data, dict) else {}

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_allowed():
                return self._json(421, {"error": "host no permitido"})
            # Los navegadores mandan siempre Origin en un POST. Si no es el de esta consola, lo mandó otra página.
            if self.headers.get("Origin") not in config.allowed_origins:
                return self._json(403, {"error": "origen no permitido"})
            path = urlsplit(self.path).path

            def action() -> Any:
                body = self._body()
                if path == "/api/customer":
                    demo.create_customer()
                elif path == "/api/profile":
                    return demo.show_profile(anonymous=body.get("anonymous") is True)
                elif path == "/api/renew":
                    demo.renew()
                elif path == "/api/logout":
                    demo.logout()
                elif path == "/api/login":
                    demo.login()
                elif path == "/api/accounts":
                    demo.list_accounts()
                elif path == "/api/scenario":
                    scenario_id = body.get("id")
                    if not isinstance(scenario_id, str):
                        raise Refused(400, "pedido inválido")
                    return demo.run_scenario(scenario_id)
                elif path == "/api/reset":
                    demo.reset()
                else:
                    raise Refused(404, "no existe")
                return {"ok": True}

            self._run(action)

    return ThreadingHTTPServer((config.listen_host, config.listen_port), Handler)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    config = Config.from_env()
    demo = Demo(config, apimod.Api(config.api_url))
    server = create_server(config, demo)
    # docker stop manda SIGTERM; como proceso 1 el intérprete lo ignoraría y la parada tardaría diez segundos.
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    print(f"Consola de la demo lista: http://localhost:{config.public_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
