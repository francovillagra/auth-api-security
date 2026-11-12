"""Configuración de las pruebas de la demo. Correr desde la raíz del repositorio:  python -m pytest demo/tests

Necesitan PyYAML (para leer el docker-compose.yml); el resto es la biblioteca estándar. No usan Docker ni Node: la API se reemplaza por una
de mentira (fake_api.py) que contesta lo mismo que la real y se puede debilitar para comprobar que la consola informa lo que pasa de verdad.
"""
import http.client
import json
import socket
import sys
import threading
from pathlib import Path

import pytest

DEMO_DIR = Path(__file__).resolve().parent.parent
if str(DEMO_DIR) not in sys.path:
    sys.path.insert(0, str(DEMO_DIR))
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from common import ADMIN_PASSWORD_FILE  # noqa: E402
from console import server  # noqa: E402
from fake_api import FakeApi  # noqa: E402


@pytest.fixture(scope="session")
def state_dir(tmp_path_factory) -> Path:
    """Credenciales y datos de práctica generados una vez para todas las pruebas."""
    import init

    directory = tmp_path_factory.mktemp("state")
    original = init.STATE_DIR
    init.STATE_DIR = directory
    try:
        init.ensure_secrets()
        init.write_seed()
    finally:
        init.STATE_DIR = original
    return directory


@pytest.fixture()
def shared_dir(tmp_path) -> Path:
    directory = tmp_path / "shared"
    directory.mkdir()
    return directory


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Console:
    """Una consola arrancada de verdad, más lo necesario para hablarle como lo haría un navegador."""

    def __init__(self, api: FakeApi, config: server.Config, demo: server.Demo, http_server) -> None:
        self.api, self.config, self.demo, self.http_server = api, config, demo, http_server
        self.port = config.public_port

    def request(self, method: str, path: str, body=None, *, host=None, origin="same", headers=None, raw_body=None):
        """Devuelve (estado, cabeceras, cuerpo en bytes). `origin="same"` manda el Origin de la propia consola, como un navegador."""
        send = {"Host": host or f"localhost:{self.port}"}
        if method == "POST":
            if origin == "same":
                send["Origin"] = f"http://localhost:{self.port}"
            elif origin:
                send["Origin"] = origin
        payload = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        if payload is not None:
            send["Content-Type"] = "application/json"
        send.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            connection.request(method, path, body=payload, headers=send)
            response = connection.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        finally:
            connection.close()

    def get(self, path, **kw):
        status, headers, body = self.request("GET", path, **kw)
        return status, (json.loads(body) if body and "json" in headers.get("content-type", "") else body)

    def post(self, path, body=None, **kw):
        status, headers, raw = self.request("POST", path, {} if body is None else body, **kw)
        return status, (json.loads(raw) if raw else None)

    def state(self):
        status, body = self.get("/api/state")
        assert status == 200
        return body

    def attack(self, scenario_id):
        status, body = self.post("/api/scenario", {"id": scenario_id})
        assert status == 200, body
        return body

    def customer_ready(self):
        assert self.post("/api/customer")[0] == 200


@pytest.fixture()
def make_console(state_dir, shared_dir):
    """Arma una consola contra una API de mentira. Las opciones apagan protecciones de la API (ver FakeApi)."""
    started: list[Console] = []

    def make(**flags) -> Console:
        api = FakeApi(shared_dir, (state_dir / ADMIN_PASSWORD_FILE).read_text(encoding="utf-8").strip(), **flags)
        url = api.start()
        port = free_port()
        config = server.Config(api_url=url, public_port=port, state_dir=state_dir, shared_dir=shared_dir, listen_host="127.0.0.1", listen_port=port)
        demo = server.Demo(config, server.apimod.Api(url))
        http_server = server.create_server(config, demo)
        threading.Thread(target=lambda: http_server.serve_forever(poll_interval=0.02), daemon=True).start()
        console = Console(api, config, demo, http_server)
        started.append(console)
        return console

    yield make
    for console in started:
        console.http_server.shutdown()
        console.http_server.server_close()
        console.api.stop()


@pytest.fixture()
def console(make_console):
    return make_console()
