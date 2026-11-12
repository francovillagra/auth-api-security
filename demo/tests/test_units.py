"""Las piezas chicas de la consola, una por una: el cliente de la API, las direcciones de práctica, las llaves, la sesión de administración,
el lector del registro y los textos. Las pruebas grandes (console, scenarios, smoke) dependen de que estas hagan bien su trabajo."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from console import api as apimod
from console import explain, serverlog
from console.api import AdminSession, AdminUnavailable, Api, ApiUnavailable, Origins, Reply


# -- un servidor mínimo para probar el cliente -----------------------------------------------------------------------------------

class Stub:
    """Anota cada pedido que recibe y contesta lo que se le indique."""

    def __init__(self) -> None:
        self.seen: list[SimpleNamespace] = []
        self.status = 200
        self.headers = {"Content-Type": "application/json"}
        self.payload = b"{}"
        self.delay = 0.0
        self.drop = False       # cierra la conexión sin contestar
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                stub.seen.append(SimpleNamespace(
                    method=self.command, path=self.path, body=body, headers={k.lower(): v for k, v in self.headers.items()},
                ))
                if stub.drop:
                    self.close_connection = True
                    return
                if stub.delay:
                    time.sleep(stub.delay)
                self.send_response(stub.status)
                for name, value in stub.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(stub.payload)))
                self.end_headers()
                self.wfile.write(stub.payload)

            do_GET = do_POST = do_PATCH = _handle

            def log_message(self, *args) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True).start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def stub():
    server = Stub()
    yield server
    server.stop()


@pytest.fixture()
def closed_port_url():
    from conftest import free_port

    return f"http://127.0.0.1:{free_port()}"


# -- Reply ---------------------------------------------------------------------------------------------------------------------------

def test_a_reply_exposes_fields_of_a_json_object_and_nothing_else():
    assert Reply(200, body={"accessToken": "abc"}).get("accessToken") == "abc"
    assert Reply(200, body={"a": 1}).get("b") is None
    for body in (None, [1, 2], "texto", 7):
        assert Reply(200, body=body).get("a") is None


@pytest.mark.parametrize("headers, expected", [
    ({"retry-after": "7"}, 7), ({"retry-after": " 3 "}, 3), ({}, None), ({"retry-after": "mañana"}, None), ({"retry-after": ""}, None),
])
def test_retry_after_is_a_number_of_seconds_or_none(headers, expected):
    assert Reply(429, headers).retry_after == expected


def test_a_reply_cannot_be_modified_after_it_is_built():
    with pytest.raises(Exception):
        Reply(200).status = 500  # type: ignore[misc]


# -- Api: la dirección ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", ["https://api:3000", "ftp://api", "api:3000", "", "http://", "//api:3000"])
def test_only_plain_http_addresses_with_a_host_are_accepted(url):
    with pytest.raises(ValueError):
        Api(url)


def test_the_port_defaults_to_80_and_the_timeout_can_be_chosen():
    api = Api("http://api")
    assert (api.host, api.port, api.timeout) == ("api", 80, apimod.TIMEOUT_SECONDS)
    api = Api("http://api:3000", timeout=2.5)
    assert (api.host, api.port, api.timeout) == ("api", 3000, 2.5)


# -- Api: lo que envía ---------------------------------------------------------------------------------------------------------------

def test_a_json_body_is_sent_compact_with_its_content_type(stub):
    Api(stub.url).request("POST", "/api/auth/login", body={"email": "a@b.test", "password": "x y"})
    seen = stub.seen[0]
    assert (seen.method, seen.path) == ("POST", "/api/auth/login")
    assert seen.body == b'{"email":"a@b.test","password":"x y"}'
    assert seen.headers["content-type"] == "application/json" and seen.headers["accept"] == "application/json"
    assert seen.headers["connection"] == "close"


def test_raw_bytes_are_sent_as_they_are_with_the_content_type_chosen(stub):
    Api(stub.url).request("POST", "/x", raw=b"{rota", content_type="text/plain")
    assert stub.seen[0].body == b"{rota" and stub.seen[0].headers["content-type"] == "text/plain"
    Api(stub.url).request("POST", "/x", raw=b"sin tipo", content_type=None)
    assert stub.seen[1].body == b"sin tipo" and "content-type" not in stub.seen[1].headers


def test_raw_takes_priority_over_body(stub):
    Api(stub.url).request("POST", "/x", body={"a": 1}, raw=b"crudo")
    assert stub.seen[0].body == b"crudo"


def test_a_request_without_body_has_no_content_type_and_no_extra_headers(stub):
    Api(stub.url).request("GET", "/api/users/me")
    headers = stub.seen[0].headers
    assert "content-type" not in headers and "authorization" not in headers and "x-real-ip" not in headers


def test_the_token_goes_as_bearer_and_the_origin_address_as_x_real_ip(stub):
    Api(stub.url).request("GET", "/api/users/me", token="aaa.bbb.ccc", ip="203.0.113.9")
    headers = stub.seen[0].headers
    assert headers["authorization"] == "Bearer aaa.bbb.ccc" and headers["x-real-ip"] == "203.0.113.9"


def test_proxy_settings_of_the_machine_are_never_used(stub, monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")      # nadie escucha ahí: si se usara, el pedido fallaría
    monkeypatch.setenv("NO_PROXY", "")
    assert Api(stub.url).request("GET", "/x").status == 200


# -- Api: lo que lee -----------------------------------------------------------------------------------------------------------------

def test_a_json_answer_is_parsed_and_headers_are_lowercase(stub):
    stub.status, stub.payload = 201, b'{"user":{"id":"u1"}}'
    stub.headers = {"Content-Type": "application/json; charset=utf-8", "Retry-After": "4", "X-Custom": "1"}
    reply = Api(stub.url).request("POST", "/x", body={})
    assert reply.status == 201 and reply.body == {"user": {"id": "u1"}} and reply.get("user") == {"id": "u1"}
    assert reply.headers["retry-after"] == "4" and reply.headers["x-custom"] == "1" and reply.retry_after == 4
    assert isinstance(reply.elapsed_ms, int) and reply.elapsed_ms >= 0


@pytest.mark.parametrize("content_type, payload", [
    ("text/html", b"<h1>no es json</h1>"),
    ("text/plain", b'{"parece": "json"}'),         # se confía en lo que declara el servidor
    ("application/json", b"{rota"),
    ("application/json", b""),
])
def test_an_answer_that_is_not_valid_json_has_no_body_but_keeps_its_status(stub, content_type, payload):
    stub.status, stub.headers, stub.payload = 500, {"Content-Type": content_type}, payload
    reply = Api(stub.url).request("GET", "/x")
    assert reply.status == 500 and reply.body is None


def test_a_204_answer_has_no_body(stub):
    stub.status, stub.payload, stub.headers = 204, b"", {}
    reply = Api(stub.url).request("POST", "/api/auth/logout", body={"refreshToken": "x"})
    assert reply.status == 204 and reply.body is None


def test_an_answer_larger_than_the_limit_is_cut_instead_of_filling_the_memory(stub, monkeypatch):
    monkeypatch.setattr(apimod, "MAX_BODY_BYTES", 1000)
    stub.payload = json.dumps({"x": "y" * 5000}).encode()
    reply = Api(stub.url).request("GET", "/x")
    assert reply.status == 200 and reply.body is None       # quedó cortado: no es JSON válido, pero no falló nada


# -- Api: cuando no hay respuesta ----------------------------------------------------------------------------------------------------

def test_an_api_that_is_not_there_raises_api_unavailable(closed_port_url):
    with pytest.raises(ApiUnavailable):
        Api(closed_port_url, timeout=1).request("GET", "/x")


def test_a_connection_closed_without_an_answer_raises_api_unavailable(stub):
    stub.drop = True
    with pytest.raises(ApiUnavailable):
        Api(stub.url, timeout=2).request("GET", "/x")


def test_a_slow_api_raises_api_unavailable_when_the_time_runs_out(stub):
    stub.delay = 1.5
    started = time.monotonic()
    with pytest.raises(ApiUnavailable):
        Api(stub.url, timeout=0.2).request("GET", "/x")
    assert time.monotonic() - started < 1.2


def test_the_error_does_not_leak_the_address_or_the_request_details(closed_port_url):
    with pytest.raises(ApiUnavailable) as failure:
        Api(closed_port_url, timeout=1).request("POST", "/api/auth/login", body={"password": "secreto-123"}, token="aaa.bbb.ccc")
    assert "secreto" not in str(failure.value) and "aaa.bbb" not in str(failure.value) and closed_port_url not in str(failure.value)


def test_healthy_is_true_only_for_a_200_on_the_home_page(stub):
    api = Api(stub.url)
    assert api.healthy() is True
    assert (stub.seen[0].method, stub.seen[0].path) == ("GET", "/")
    assert "x-real-ip" not in stub.seen[0].headers          # no gasta el contador de pedidos de nadie
    stub.status = 500
    assert api.healthy() is False
    stub.status, stub.drop = 200, True
    assert api.healthy() is False


def test_healthy_is_false_when_nobody_listens(closed_port_url):
    assert Api(closed_port_url).healthy() is False


# -- direcciones de práctica -------------------------------------------------------------------------------------------------------

DOCUMENTATION_BLOCKS = [ipaddress.ip_network(block) for block in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]    # RFC 5737


def test_every_practice_address_is_in_a_block_reserved_for_documentation():
    origins = Origins()
    taken = [Origins.CUSTOMER, Origins.ADMIN, *(f() for f in (origins.visitor, origins.attacker, origins.spread) for _ in range(300))]
    for address in taken:
        assert any(ipaddress.ip_address(address) in block for block in DOCUMENTATION_BLOCKS), address


def test_each_character_has_its_own_counter_on_the_api():
    origins = Origins()
    pools = {
        "visitor": {origins.visitor() for _ in range(151)},
        "attacker": {origins.attacker() for _ in range(250)},
        "spread": {origins.spread() for _ in range(250)},
    }
    fixed = {Origins.CUSTOMER, Origins.ADMIN}
    assert len(fixed) == 2
    everything = [*fixed, *pools["visitor"], *pools["attacker"], *pools["spread"]]
    assert len(everything) == len(set(everything)) == 2 + 151 + 250 + 250      # ningún personaje comparte dirección con otro
    assert all(a.startswith("192.0.2.") and 100 <= int(a.rsplit(".", 1)[1]) <= 250 for a in pools["visitor"])
    assert all(a.startswith("203.0.113.") for a in pools["attacker"]) and all(a.startswith("198.51.100.") for a in pools["spread"])


def test_a_pool_starts_somewhere_random_and_wraps_around(monkeypatch):
    monkeypatch.setattr(apimod.secrets, "randbelow", lambda size: size - 2)
    pool = apimod._Pool("203.0.113", 1, 250)
    assert [pool.take() for _ in range(4)] == ["203.0.113.249", "203.0.113.250", "203.0.113.1", "203.0.113.2"]


def test_a_pool_never_repeats_an_address_within_a_cycle_even_with_many_threads():
    pool = apimod._Pool("192.0.2", 100, 250)
    taken: list[str] = []

    def work() -> None:
        for _ in range(30):
            taken.append(pool.take())

    threads = [threading.Thread(target=work) for _ in range(5)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(taken) == 150 and len(set(taken)) == 150          # el bloque tiene 151 direcciones


def test_two_runs_do_not_start_at_the_same_address():
    starts = {Origins().attacker() for _ in range(30)}
    assert len(starts) > 1                                        # el punto de partida es al azar (30 veces el mismo: 1 en 250^29)


# -- llaves (JWT) --------------------------------------------------------------------------------------------------------------------

SECRET = "clave-de-prueba-" + "x" * 32
PAYLOAD = {"userId": "u-1", "role": "USER", "exp": 2_000_000_000}


def _signature(token: str, secret: str) -> str:
    head, body, _ = token.split(".")
    return apimod._b64(hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())


def test_a_forged_key_carries_the_data_and_a_valid_hs256_signature():
    token = apimod.forge(PAYLOAD, SECRET)
    head, body, signature = token.split(".")
    assert json.loads(apimod._unb64(head)) == {"alg": "HS256", "typ": "JWT"}
    assert apimod.claims(token) == PAYLOAD
    assert signature == _signature(token, SECRET) and signature
    assert "=" not in token                                          # base64 de URL, sin relleno


def test_a_key_without_secret_or_with_algorithm_none_has_an_empty_signature():
    unsigned = apimod.forge(PAYLOAD, None)
    assert unsigned.endswith(".") and unsigned.count(".") == 2 and json.loads(apimod._unb64(unsigned.split(".")[0]))["alg"] == "HS256"
    none = apimod.forge(PAYLOAD, SECRET, "none")
    assert none.endswith(".") and json.loads(apimod._unb64(none.split(".")[0]))["alg"] == "none"
    assert apimod.claims(none) == PAYLOAD


def test_tampering_changes_the_data_but_keeps_the_original_signature():
    original = apimod.forge(PAYLOAD, SECRET)
    edited = apimod.tamper(original, role="ADMIN", extra=True)
    assert apimod.claims(edited) == {**PAYLOAD, "role": "ADMIN", "extra": True}
    assert edited.split(".")[0] == original.split(".")[0] and edited.split(".")[2] == original.split(".")[2]
    assert edited.split(".")[2] != _signature(edited, SECRET)         # la firma ya no corresponde a los datos
    assert apimod.claims(original) == PAYLOAD                          # la original no se toca


@pytest.mark.parametrize("token", ["", "una-sola-parte", "a.b", "a.@@@.c", "a..c", "e30.e30", "a.WzEsMl0.c"])      # el último: el cuerpo es una lista
def test_claims_of_something_that_is_not_a_key_is_empty(token):
    assert apimod.claims(token) == {}


def test_claims_reads_without_checking_the_signature():
    assert apimod.claims(apimod.forge(PAYLOAD, "otra-clave")) == PAYLOAD          # leer los datos no requiere la clave


# -- sesión de administración -----------------------------------------------------------------------------------------------------

class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class ScriptedApi:
    """Contesta lo que se le diga, en orden, y anota cada pedido."""

    def __init__(self, replies, delay: float = 0.0) -> None:
        self.replies, self.calls, self.delay = list(replies), [], delay

    def request(self, method, path, *, body=None, raw=None, content_type="application/json", token=None, ip=None):
        self.calls.append(SimpleNamespace(method=method, path=path, body=body, token=token, ip=ip))
        if self.delay:
            time.sleep(self.delay)
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


def login_reply(expires_at: float, status: int = 200) -> Reply:
    return Reply(status, {}, {"accessToken": apimod.forge({"exp": expires_at, "userId": "admin"}, SECRET)} if status == 200 else {"error": "x"})


def make_admin(replies, clock=None, password="clave-admin", delay=0.0):
    clock = clock or Clock()
    api = ScriptedApi(replies, delay)
    reads = []

    def read_password() -> str:
        reads.append(1)
        return password

    return AdminSession(api, "admin@tienda-demo.test", read_password, "192.0.2.20", clock), api, clock, reads


def test_the_administration_enters_once_and_reuses_its_key_until_it_is_about_to_expire():
    clock = Clock()
    admin, api, _, reads = make_admin([login_reply(clock.now + 900)], clock)
    first = admin.token()
    assert admin.token() == first and admin.token() == first
    assert len(api.calls) == 1 and len(reads) == 1
    login = api.calls[0]
    assert (login.method, login.path, login.ip, login.token) == ("POST", "/api/auth/login", "192.0.2.20", None)
    assert login.body == {"email": "admin@tienda-demo.test", "password": "clave-admin"}


@pytest.mark.parametrize("seconds_left, logins", [(900, 1), (61, 1), (60, 2), (59, 2), (0, 2), (-30, 2)])
def test_the_key_is_renewed_when_a_minute_or_less_is_left(seconds_left, logins):
    clock = Clock()
    admin, api, _, _ = make_admin([login_reply(clock.now + 900)], clock)
    admin.token()
    clock.now += 900 - seconds_left
    admin.token()
    assert len(api.calls) == logins


def test_forget_makes_the_next_call_enter_again():
    clock = Clock()
    admin, api, _, _ = make_admin([login_reply(clock.now + 900)], clock)
    admin.token()
    admin.forget()
    admin.token()
    assert len(api.calls) == 2


def test_without_a_password_it_does_not_even_try_to_enter():
    admin, api, _, _ = make_admin([login_reply(2_000_000_000)], password="")
    with pytest.raises(AdminUnavailable, match="todavía no están listas"):
        admin.token()
    assert api.calls == []


@pytest.mark.parametrize("reply, shown", [
    (Reply(401, {}, {"error": "x"}), "401"),
    (Reply(429, {}, {"error": "x"}), "429"),
    (Reply(200, {}, {"sin": "llave"}), "200"),
    (Reply(200, {}, {"accessToken": 42}), "200"),
    (Reply(500, {}, None), "500"),
])
def test_a_refused_entry_is_reported_with_the_status_and_nothing_is_kept(reply, shown):
    admin, api, _, _ = make_admin([reply])
    with pytest.raises(AdminUnavailable, match=shown):
        admin.token()
    assert admin._token is None


def test_a_rejected_key_is_replaced_and_the_request_repeated_once():
    clock = Clock()
    first, second = login_reply(clock.now + 900), login_reply(clock.now + 900)
    ok = Reply(200, {}, {"users": []})
    admin, api, _, _ = make_admin([first, Reply(401, {}, {"error": "x"}), second, ok], clock)
    reply = admin.request("GET", "/api/admin/users")
    assert reply is ok
    assert [(c.method, c.path) for c in api.calls] == [("POST", "/api/auth/login"), ("GET", "/api/admin/users"), ("POST", "/api/auth/login"), ("GET", "/api/admin/users")]
    assert api.calls[1].token == first.body["accessToken"] and api.calls[3].token == second.body["accessToken"]
    assert all(c.ip == "192.0.2.20" for c in api.calls)


@pytest.mark.parametrize("status", [200, 204, 403, 404, 429, 500])
def test_only_a_401_is_retried(status):
    clock = Clock()
    admin, api, _, _ = make_admin([login_reply(clock.now + 900), Reply(status, {}, None)], clock)
    assert admin.request("GET", "/api/admin/users").status == status
    assert len(api.calls) == 2


def test_a_second_401_is_returned_instead_of_looping():
    clock = Clock()
    admin, api, _, _ = make_admin([login_reply(clock.now + 900), Reply(401, {}, None), login_reply(clock.now + 900), Reply(401, {}, None)], clock)
    assert admin.request("GET", "/api/admin/users").status == 401
    assert len(api.calls) == 4


def test_the_body_travels_with_the_request_as_administration():
    clock = Clock()
    admin, api, _, _ = make_admin([login_reply(clock.now + 900), Reply(200, {}, {})], clock)
    admin.request("PATCH", "/api/admin/users/u1/role", body={"role": "ADMIN"})
    assert api.calls[1].body == {"role": "ADMIN"} and api.calls[1].token


def test_many_threads_asking_at_once_cause_a_single_entry():
    clock = Clock()
    admin, api, _, _ = make_admin([login_reply(clock.now + 900)], clock, delay=0.05)
    results: list[str] = []
    threads = [threading.Thread(target=lambda: results.append(admin.token())) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(api.calls) == 1 and len(set(results)) == 1 and len(results) == 8


# -- textos --------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("status, label", [
    (200, "Aceptado"), (201, "Aceptado"), (204, "Aceptado"), (400, "Datos inválidos"), (401, "Sin identificación válida"),
    (403, "Sin permiso"), (404, "No existe"), (409, "Ya existe"), (413, "Demasiado grande"), (415, "Formato no admitido"),
    (429, "Frenado por exceso de pedidos"), (500, "Error de la API"), (503, "Error de la API"), (302, "Respuesta inesperada"), (418, "Respuesta inesperada"),
])
def test_every_status_the_api_can_answer_has_a_plain_label(status, label):
    assert explain.status_label(status) == label


def test_roles_are_shown_with_the_words_of_a_shop():
    assert explain.role_label("USER") == "cliente" and explain.role_label("ADMIN") == "administración"
    assert explain.role_label("OTRO") == "OTRO"


def test_plural_picks_the_singular_only_for_one():
    assert [explain.plural(n, "intento", "intentos") for n in (0, 1, 2, 10)] == ["intentos", "intento", "intentos", "intentos"]


# -- el registro de la API -------------------------------------------------------------------------------------------------------------

COLORS = {"info": "32", "warn": "33", "error": "31", "debug": "34"}


def winston(level: str, message: str, stamp: str = "2026-11-12 16:05:11", color: bool = True) -> str:
    tag = f"\x1b[{COLORS[level]}m{level}\x1b[39m" if color else level
    return f"{stamp} [{tag}]: {message}"


def test_a_winston_line_becomes_an_entry_with_its_time_level_and_text():
    entries = serverlog.parse([winston("info", "POST /api/auth/login 401 — 85ms")])
    assert entries == [{"t": "2026-11-12T16:05:11Z", "level": "info", "text": "POST /api/auth/login 401 — 85ms"}]


def test_lines_work_with_and_without_colors_and_with_windows_line_endings():
    plain = serverlog.parse([winston("warn", "Refresh token reuse detected: user u1, session s1 revoked", color=False)])
    colored = serverlog.parse([winston("warn", "Refresh token reuse detected: user u1, session s1 revoked") + "\r"])
    assert plain == colored and plain[0]["level"] == "warn"


def test_the_debug_level_is_hidden_but_its_time_is_remembered():
    entries = serverlog.parse([winston("debug", "Profile fetched: u1", stamp="2026-11-12 16:05:20"), "[proxy] 429 rate limited: 203.0.113.5 → /api/auth/login"])
    assert [(e["level"], e["t"]) for e in entries] == [("warn", "2026-11-12T16:05:20Z")]


def test_a_blocked_request_from_the_proxy_becomes_a_plain_warning_with_the_last_known_time():
    lines = [winston("info", "POST /api/auth/login 401 — 12ms"), "[proxy] 429 rate limited: 203.0.113.5 → /api/auth/login"]
    entries = serverlog.parse(lines)
    assert entries[1] == {"t": "2026-11-12T16:05:11Z", "level": "warn", "text": "Pedido frenado por exceso de intentos: 203.0.113.5 → /api/auth/login"}


def test_a_blocked_request_before_any_other_line_has_no_time():
    assert serverlog.parse(["[proxy] 429 rate limited: 203.0.113.5 → /api/auth/login"])[0]["t"] is None


@pytest.mark.parametrize("line", [
    "", "   ", "▲ Next.js 16.4.1", "- Local:        http://localhost:3000", "[proxy] POST /api/auth/login", "[proxy] 429 rate limited: sin-flecha",
    "Error: boom", "    at handler (/app/.next/server/app/route.js:1:1)", "2026-11-12 16:05:11 [verbose]: algo", "2026-11-12 16:05:11 info: sin corchetes",
    "[2026-11-12 16:05:11] [info]: otro formato",
])
def test_lines_that_are_not_part_of_the_log_are_not_shown(line):
    assert serverlog.parse([line]) == []


def test_only_the_first_line_of_an_error_with_a_stack_is_shown():
    entries = serverlog.parse([winston("error", "Error: connect ECONNREFUSED"), "    at connect (node:net:1:1)", "    at Object.<anonymous> (/app/x.js:2:2)"])
    assert [e["text"] for e in entries] == ["Error: connect ECONNREFUSED"]


def test_long_lines_are_cut_at_the_limit():
    entries = serverlog.parse([winston("info", "x" * 5000), "[proxy] 429 rate limited: 203.0.113.5 → /" + "y" * 5000])
    assert [len(e["text"]) for e in entries] == [serverlog.MAX_LINE_CHARS, serverlog.MAX_LINE_CHARS]


def test_the_limits_of_the_log_reader_are_the_documented_ones():
    assert (serverlog.MAX_LINES, serverlog.MAX_LINE_CHARS, serverlog.MAX_READ_BYTES) == (40, 300, 64 * 1024)


def write_lines(path, lines):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_a_missing_log_is_an_empty_one(tmp_path):
    assert serverlog.tail(tmp_path / "no-existe.log") == ([], 0)


def test_tail_keeps_the_last_forty_entries_and_reports_the_size(tmp_path):
    path = tmp_path / "api.log"
    write_lines(path, [winston("info", f"GET /{i} 200 — 1ms") for i in range(100)])
    entries, size = serverlog.tail(path)
    assert [e["text"] for e in entries] == [f"GET /{i} 200 — 1ms" for i in range(60, 100)]
    assert size == path.stat().st_size


def test_tail_from_a_floor_shows_only_what_came_after(tmp_path):
    path = tmp_path / "api.log"
    write_lines(path, [winston("info", f"viejo {i}") for i in range(10)])
    _, floor = serverlog.tail(path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(winston("info", "nuevo 1") + "\n" + winston("warn", "nuevo 2") + "\n")
    entries, size = serverlog.tail(path, floor)
    assert [e["text"] for e in entries] == ["nuevo 1", "nuevo 2"] and size > floor
    assert serverlog.tail(path, size)[0] == []


def test_if_the_file_shrinks_below_the_floor_it_is_read_from_the_start(tmp_path):
    path = tmp_path / "api.log"
    write_lines(path, [winston("info", f"largo {i}") for i in range(50)])
    _, floor = serverlog.tail(path)
    write_lines(path, [winston("info", "recortado")])                 # la API recortó el archivo al llegar a su tope
    entries, size = serverlog.tail(path, floor)
    assert [e["text"] for e in entries] == ["recortado"] and size < floor


def test_only_the_end_of_a_huge_log_is_read_and_the_cut_line_is_dropped(tmp_path):
    path = tmp_path / "api.log"
    write_lines(path, [winston("info", f"linea {i:05d} " + "." * 80 + " FIN") for i in range(3000)])
    assert path.stat().st_size > serverlog.MAX_READ_BYTES * 3
    entries, _ = serverlog.tail(path)
    assert len(entries) == serverlog.MAX_LINES
    assert all(e["text"].endswith(" FIN") and e["text"].startswith("linea ") for e in entries)
    assert entries[-1]["text"].startswith("linea 02999")


def test_bytes_that_are_not_utf8_do_not_break_the_reader(tmp_path):
    path = tmp_path / "api.log"
    path.write_bytes(b"2026-11-12 16:05:11 [info]: caf\xe9 \xff\xfe\n")
    entries, _ = serverlog.tail(path)
    assert len(entries) == 1 and entries[0]["text"].startswith("caf")
