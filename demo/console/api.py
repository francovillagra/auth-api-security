"""El cliente con el que la consola le habla a la API de la demo, y lo necesario para jugar a los distintos personajes.

Cada personaje (el cliente, la administración, un atacante) "llama" desde su propia dirección de internet de práctica. La API limita el ritmo
de los pedidos por dirección: si todos salieran del contenedor de la consola compartirían un mismo contador y un ataque dejaría afuera al
cliente. En producción esa dirección la fija la plataforma (Vercel); acá la fija la consola con la cabecera `x-real-ip`, que es justamente lo
que la API lee (ver proxy.ts). Las direcciones son de los bloques que RFC 5737 reserva para documentación: no son de nadie.

La consola solo le habla a la dirección que recibe por configuración (la API de la demo, dentro de la red interna). No acepta otra desde la
página.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

MAX_BODY_BYTES = 1024 * 1024   # lo máximo que se lee de una respuesta
TIMEOUT_SECONDS = 30.0


class ApiUnavailable(Exception):
    """No hubo respuesta de la API (apagada, arrancando o sin red)."""


@dataclass(frozen=True)
class Reply:
    status: int
    headers: dict[str, str] = field(default_factory=dict)   # nombres en minúsculas
    body: Any = None                                         # JSON ya leído, o None si no era JSON
    elapsed_ms: int = 0

    def get(self, name: str) -> Any:
        """Un campo del cuerpo JSON de la respuesta (None si no hay o no es un objeto)."""
        return self.body.get(name) if isinstance(self.body, dict) else None

    @property
    def retry_after(self) -> Optional[int]:
        try:
            return int(self.headers.get("retry-after", ""))
        except ValueError:
            return None


class Api:
    def __init__(self, base_url: str, timeout: float = TIMEOUT_SECONDS) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "http" or not parts.hostname:
            raise ValueError("La dirección de la API de la demo tiene que ser http://servidor:puerto")
        self.host, self.port, self.timeout = parts.hostname, parts.port or 80, timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        raw: Optional[bytes] = None,
        content_type: Optional[str] = "application/json",
        token: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Reply:
        """Un pedido a la API. `body` se envía como JSON; `raw` envía bytes tal cual (para datos mal armados). Nunca usa un proxy."""
        headers = {"Accept": "application/json", "Connection": "close"}
        data: Optional[bytes] = None
        if raw is not None:
            data = raw
        elif body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        if data is not None and content_type:
            headers["Content-Type"] = content_type
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if ip:
            headers["x-real-ip"] = ip

        started = time.monotonic()
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            try:
                connection.request(method, path, body=data, headers=headers)
            except (BrokenPipeError, ConnectionResetError):
                pass   # la API puede contestar y cerrar antes de que termine el envío (cuerpos enormes): se intenta leer igual
            response = connection.getresponse()
            payload = response.read(MAX_BODY_BYTES)
            reply_headers = {name.lower(): value for name, value in response.getheaders()}
            status = response.status
        except (OSError, http.client.HTTPException) as exc:   # sin conexión, tiempo agotado, respuesta cortada
            raise ApiUnavailable(exc.__class__.__name__) from None
        finally:
            connection.close()

        parsed: Any = None
        if payload and "json" in reply_headers.get("content-type", ""):
            try:
                parsed = json.loads(payload)
            except ValueError:
                parsed = None
        return Reply(status, reply_headers, parsed, int((time.monotonic() - started) * 1000))

    def healthy(self) -> bool:
        """La página de inicio de la API: no usa la base ni pasa por el proxy, así que no ensucia el registro ni gasta el límite."""
        connection = http.client.HTTPConnection(self.host, self.port, timeout=1.5)
        try:
            connection.request("GET", "/", headers={"Connection": "close"})
            response = connection.getresponse()
            response.read(MAX_BODY_BYTES)
            return response.status == 200
        except (OSError, http.client.HTTPException):
            return False
        finally:
            connection.close()


# -- direcciones de práctica ------------------------------------------------------------------------------------------------

class _Pool:
    """Reparte direcciones de un bloque, una distinta cada vez, empezando en un punto al azar."""

    def __init__(self, prefix: str, first: int, last: int) -> None:
        self._prefix, self._first, self._size = prefix, first, last - first + 1
        self._next = secrets.randbelow(self._size)
        self._lock = threading.Lock()

    def take(self) -> str:
        with self._lock:
            offset, self._next = self._next, (self._next + 1) % self._size
        return f"{self._prefix}.{self._first + offset}"


class Origins:
    """Las direcciones de práctica de cada personaje. Cada una tiene su propio contador de pedidos en la API."""

    CUSTOMER = "192.0.2.10"   # el cliente del recorrido
    ADMIN = "192.0.2.20"      # la administración

    def __init__(self) -> None:
        self._visitors = _Pool("192.0.2", 100, 250)     # clientes que arma cada prueba por su cuenta
        self._attackers = _Pool("203.0.113", 1, 250)    # un atacante nuevo en cada prueba
        self._spread = _Pool("198.51.100", 1, 250)      # quien controla muchas conexiones

    def visitor(self) -> str:
        return self._visitors.take()

    def attacker(self) -> str:
        return self._attackers.take()

    def spread(self) -> str:
        return self._spread.take()


# -- llaves (JWT) -----------------------------------------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def claims(token: str) -> dict:
    """Los datos que lleva una llave. Se leen SIN verificar la firma: cualquiera puede leerlos; la firma existe para que nadie los edite."""
    try:
        data = json.loads(_unb64(token.split(".")[1]))
    except (IndexError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def forge(payload: dict, secret: Optional[str], algorithm: str = "HS256") -> str:
    """Arma una llave con los datos que se quiera. Sin clave (o con el algoritmo «none») queda sin firma."""
    head = _b64(json.dumps({"alg": algorithm, "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    if algorithm == "none" or secret is None:
        return f"{head}.{body}."
    signature = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(signature)}"


def tamper(token: str, **changes: Any) -> str:
    """Edita los datos de una llave verdadera y deja la firma original, que ya no corresponde."""
    head, body, signature = token.split(".")
    data = claims(token)
    data.update(changes)
    return f"{head}.{_b64(json.dumps(data, separators=(',', ':')).encode())}.{signature}"


# -- la cuenta de administración ----------------------------------------------------------------------------------------------

class AdminUnavailable(Exception):
    """La consola no pudo entrar como administración (falta la contraseña de práctica o la API la rechazó)."""


class AdminSession:
    """Entra con la cuenta de administración de práctica y guarda su llave de acceso hasta poco antes de que venza."""

    MARGIN_SECONDS = 60

    def __init__(self, api: Api, email: str, read_password: Callable[[], str], ip: str, clock: Callable[[], float] = time.time) -> None:
        self._api, self._email, self._read_password, self._ip, self._clock = api, email, read_password, ip, clock
        self._token: Optional[str] = None
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if self._token and float(claims(self._token).get("exp", 0)) - self._clock() > self.MARGIN_SECONDS:
                return self._token
            password = self._read_password()
            if not password:
                raise AdminUnavailable("Las credenciales de la demo todavía no están listas.")
            reply = self._api.request("POST", "/api/auth/login", body={"email": self._email, "password": password}, ip=self._ip)
            access = reply.get("accessToken")
            if reply.status != 200 or not isinstance(access, str):
                raise AdminUnavailable(f"La API no dejó entrar a la cuenta de administración de práctica (respondió {reply.status}).")
            self._token = access
            return access

    def forget(self) -> None:
        with self._lock:
            self._token = None

    def request(self, method: str, path: str, *, body: Any = None) -> Reply:
        """Un pedido como administración. Si la llave guardada ya no sirve, entra de nuevo y repite una vez."""
        reply = self._api.request(method, path, body=body, token=self.token(), ip=self._ip)
        if reply.status == 401:
            self.forget()
            reply = self._api.request(method, path, body=body, token=self.token(), ip=self._ip)
        return reply
