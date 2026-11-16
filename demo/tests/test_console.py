"""La consola: la seguridad de su propio servidor, el recorrido del cliente, el estado que ve la página y lo que nunca debe filtrar."""
from __future__ import annotations

import json
import re
import threading

import pytest

from console import scenarios, server


# -- seguridad del servidor de la consola ------------------------------------------------------------------------------------------------------

def test_the_page_and_its_files_are_served_with_strict_headers(console):
    for path, content_type in (("/", "text/html"), ("/app.js", "text/javascript"), ("/style.css", "text/css")):
        status, headers, body = console.request("GET", path)
        assert status == 200 and headers["content-type"].startswith(content_type) and body
        assert "default-src 'none'" in headers["content-security-policy"] and "script-src 'self'" in headers["content-security-policy"]
        assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
        assert headers["cache-control"] == "no-store" and "server" not in headers   # no se anuncia qué servidor es
    assert b"Demo de Auth API Security" in console.request("GET", "/")[2]


def test_requests_for_other_hosts_are_refused_to_stop_dns_rebinding(console):
    assert console.request("GET", "/api/state", host="evil.example:80")[0] == 421
    assert console.request("GET", "/", host="localhost:1")[0] == 421
    assert console.request("POST", "/api/customer", {}, host="evil.example")[0] == 421
    assert console.request("GET", "/api/state", host=f"127.0.0.1:{console.port}")[0] == 200


def test_posts_from_other_pages_are_refused(console):
    for origin in (None, "", "http://evil.example", f"http://localhost:{console.port + 1}", "null"):
        status, _, _ = console.request("POST", "/api/customer", {}, origin=origin)
        assert status == 403, origin
    assert console.state()["customer"] is None   # nada llegó a la API


def test_healthz_answers_for_docker_with_any_host(console):
    status, headers, body = console.request("GET", "/healthz", host="127.0.0.1:9")
    assert (status, body) == (200, b"ok")


def test_bodies_are_limited_and_must_be_json(console):
    assert console.request("POST", "/api/scenario", raw_body=b"x" * 2000)[0] == 413
    assert console.request("POST", "/api/scenario", raw_body=b"{no")[0] == 400
    assert console.post("/api/scenario", {"id": 7})[0] == 400
    assert console.post("/api/scenario", {})[0] == 400
    assert console.post("/api/scenario", {"id": "../../etc/passwd"})[0] == 404
    assert console.post("/api/scenario", {"id": "nope"})[0] == 404
    assert console.post("/api/nope")[0] == 404
    assert console.get("/api/nope")[0] == 404


def test_the_console_has_no_endpoint_to_choose_a_target(console):
    status, headers, body = console.request("GET", "/api/state")
    assert "target" not in json.loads(body)["catalog"][0]
    assert console.post("/api/scenario", {"id": "bruteforce", "url": "http://example.com", "target": "x@y.z"})[0] == 200
    hosts = {request[3] for request in console.api.requests}
    assert all(re.fullmatch(r"(192\.0\.2|203\.0\.113|198\.51\.100)\.\d+", ip) for ip in hosts)
    assert console.config.target_email == "ana@tienda-demo.test"


def test_only_one_attack_runs_at_a_time(console):
    assert console.demo._busy.acquire(blocking=False)
    try:
        status, body = console.post("/api/scenario", {"id": "bruteforce"})
    finally:
        console.demo._busy.release()
    assert status == 409 and "en marcha" in body["error"]
    assert console.post("/api/scenario", {"id": "bruteforce"})[0] == 200


def test_several_clients_polling_while_an_attack_runs_do_not_block_it(console):
    results: list[int] = []

    def poll():
        for _ in range(10):
            results.append(console.request("GET", "/api/state")[0])

    thread = threading.Thread(target=poll)
    thread.start()
    assert console.post("/api/scenario", {"id": "stolen-session"})[0] == 200
    thread.join()
    assert results == [200] * 10


def test_an_unexpected_error_in_the_console_does_not_leave_it_without_an_answer(console, monkeypatch):
    monkeypatch.setattr(console.demo, "renew", lambda: 1 / 0)
    status, body = console.post("/api/renew")
    assert status == 500 and "inesperado" in body["error"] and "ZeroDivision" not in json.dumps(body)


# -- la API no responde ---------------------------------------------------------------------------------------------------------------------------

def test_when_the_api_is_down_the_page_is_told_and_actions_explain_it(console):
    console.api.available = False
    state = console.state()
    assert state["api_ready"] is False and state["customer"] is None
    status, body = console.post("/api/customer")
    assert status == 503 and "API" in body["error"]
    status, body = console.post("/api/scenario", {"id": "bruteforce"})
    assert status == 503
    console.api.available = True
    assert console.state()["api_ready"] is True
    assert console.post("/api/customer")[0] == 200


# -- el recorrido del cliente ------------------------------------------------------------------------------------------------------------------------

def test_the_steps_have_an_order(console):
    for path in ("/api/profile", "/api/renew", "/api/logout", "/api/login"):
        status, body = console.post(path)
        assert status == 409 and "crear la cuenta de cliente" in body["error"], path


def test_create_account_gives_a_session_and_cannot_be_repeated(console):
    assert console.post("/api/customer")[0] == 200
    customer = console.state()["customer"]
    assert customer["session"] == "active" and customer["email"].endswith("@tienda-demo.test") and customer["profile"] is None
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", customer["access_expires_at"])
    status, body = console.post("/api/customer")
    assert status == 409 and "reiniciar" in body["error"]
    assert "Cuenta de cliente creada" in console.state()["events"][-1]["text"]


def test_profile_with_and_without_a_key(console):
    console.customer_ready()
    assert console.post("/api/profile", {})[0] == 200
    profile = console.state()["customer"]["profile"]
    assert profile["role"] == "USER" and profile["role_label"] == "cliente" and profile["name"] == "Cliente de práctica"
    status, body = console.post("/api/profile", {"anonymous": True})
    assert status == 200 and body == {"refused": True, "status": 401}
    assert "rechazó, como corresponde" in console.state()["events"][-1]["text"]


def test_renewing_swaps_the_renewal_key_and_the_old_one_stops_working(console):
    console.customer_ready()
    old = console.demo._customer.refresh
    assert console.post("/api/renew")[0] == 200
    new = console.demo._customer.refresh
    assert new != old
    reply = console.demo.api.request("POST", "/api/auth/refresh", body={"refreshToken": old})
    assert reply.status == 401                      # la anterior ya no sirve
    assert console.post("/api/renew")[0] == 409     # (y al probarla la API cerró la sesión: el cliente tiene que volver a entrar)
    assert console.state()["customer"]["session"] == "closed"


def test_logout_and_login_again(console):
    console.customer_ready()
    assert console.post("/api/logout")[0] == 200
    customer = console.state()["customer"]
    assert customer["session"] == "closed" and customer["access_expires_at"] is None
    assert console.post("/api/logout")[0] == 409
    assert console.post("/api/profile", {})[0] == 409
    assert console.post("/api/renew")[0] == 409
    assert console.post("/api/login")[0] == 200
    assert console.state()["customer"]["session"] == "active"
    assert console.post("/api/login")[0] == 409
    assert console.post("/api/profile", {})[0] == 200


def test_an_expired_access_key_is_explained(console):
    console.customer_ready()
    console.demo._customer.access = "x.y.z"   # una llave que la API no reconoce (por ejemplo, vencida)
    status, body = console.post("/api/profile", {})
    assert status == 409 and "venció" in body["error"] and "15 minutos" in body["error"]


def test_the_administration_lists_accounts_without_passwords(console):
    console.customer_ready()
    assert console.post("/api/accounts")[0] == 200
    listing = console.state()["admin_list"]
    assert listing["total"] == 5 and listing["shown"] == 5        # administración, los 3 clientes de práctica y el cliente nuevo
    assert {u["role_label"] for u in listing["users"]} == {"administración", "cliente"}
    assert "password" not in json.dumps(listing)
    assert "sin contraseñas" in console.state()["events"][-1]["text"]


def test_the_list_is_cut_to_a_dozen_but_the_total_is_reported(console):
    for _ in range(14):
        console.api._add_user(f"extra{_}@tienda-demo.test", "Aa1-xxxxxxxx", "Extra", "USER")
    console.post("/api/accounts")
    listing = console.state()["admin_list"]
    assert listing["total"] == 18 and listing["shown"] == len(listing["users"]) == server.LISTED_USERS    # 4 de la carga inicial + 14


def test_a_password_in_the_listing_is_flagged_as_a_problem(make_console):
    console = make_console(leak_passwords=True)
    console.post("/api/accounts")
    last = console.state()["events"][-1]
    assert last["ok"] is False and "incluyó contraseñas" in last["text"]


def test_the_administration_session_is_reused_and_renewed_when_it_stops_working(console):
    console.post("/api/accounts")
    console.post("/api/accounts")
    logins = [r for r in console.api.requests if r[1] == "/api/auth/login" and r[3] == "192.0.2.20"]
    assert len(logins) == 1                                     # la llave de acceso se guarda
    console.demo.admin._token = "x.y.z"                          # una llave inválida: entra de nuevo y repite una sola vez
    assert console.post("/api/accounts")[0] == 200
    assert len([r for r in console.api.requests if r[1] == "/api/auth/login" and r[3] == "192.0.2.20"]) == 2


def test_each_step_uses_the_customers_address_and_the_admin_uses_its_own(console):
    console.customer_ready()
    console.post("/api/profile", {})
    console.post("/api/renew")
    console.post("/api/accounts")
    by_ip: dict[str, set[str]] = {}
    for method, path, status, ip in console.api.requests:
        by_ip.setdefault(ip, set()).add(path)
    assert by_ip["192.0.2.10"] == {"/api/auth/register", "/api/users/me", "/api/auth/refresh"}
    assert by_ip["192.0.2.20"] == {"/api/auth/login", "/api/admin/users"}


def test_a_session_closed_by_the_api_is_noticed_when_renewing(console):
    console.customer_ready()
    for token in console.api.tokens.values():
        token["revoked"] = True                   # la API cerró la sesión por su cuenta
    status, body = console.post("/api/renew")
    assert status == 409 and "ya no está abierta" in body["error"]
    assert console.state()["customer"]["session"] == "closed"


def test_too_many_requests_are_explained_in_plain_words(console):
    console.api.limited = lambda ip: 5
    status, body = console.post("/api/customer")
    assert status == 429 and "5 cada 10 segundos" in body["error"]


# -- lo que ve la página ---------------------------------------------------------------------------------------------------------------------------------

def test_the_initial_state(console):
    state = console.state()
    assert state["api_ready"] is True and state["customer"] is None and state["admin_list"] is None and state["results"] == {}
    assert state["events"] == [] and state["log"] == []
    assert state["limits"] == {"requests": 5, "seconds": 10, "access_minutes": 15, "refresh_days": 7}
    assert [item["id"] for item in state["catalog"]] == [s.id for s in scenarios.SCENARIO_LIST]
    assert state["target_email"] == "ana@tienda-demo.test" and state["admin_email"] == "admin@tienda-demo.test"


def test_results_are_kept_so_a_reloaded_page_shows_them(console):
    console.attack("bad-input")
    state = console.state()
    assert state["results"]["bad-input"]["held"] is True and state["results"]["bad-input"]["ran_at"]
    assert "«Mandar datos mal armados o enormes»" in state["events"][-1]["text"]


def test_the_server_log_reaches_the_page_clean_and_in_order(console):
    console.customer_ready()
    console.post("/api/profile", {})
    lines = console.state()["log"]
    texts = [line["text"] for line in lines]
    assert any(re.fullmatch(r"User registered: [0-9a-f-]{36}", t) for t in texts)
    assert any(re.fullmatch(r"GET /api/users/me 200 — \d+ms", t) for t in texts)
    assert all("\x1b" not in t for t in texts) and all(line["level"] in ("info", "warn", "error") for line in lines)
    assert lines == sorted(lines, key=lambda line: line["t"] or "")        # cronológico


def test_throttled_requests_show_up_in_the_log_as_alerts(console):
    console.attack("bruteforce")
    alerts = [line for line in console.state()["log"] if line["level"] == "warn"]
    assert len(alerts) == 3 and all("Pedido frenado por exceso de intentos" in line["text"] for line in alerts)


def test_the_log_never_carries_emails_passwords_or_keys(console):
    console.customer_ready()
    console.attack("stolen-session")
    console.attack("forged-token")
    text = json.dumps(console.state()["log"])
    assert "@tienda-demo.test" not in text and "eyJ" not in text
    assert console.demo._customer.password not in text


def test_nothing_secret_ever_reaches_the_page(console, state_dir):
    console.customer_ready()
    console.post("/api/profile", {})
    console.post("/api/accounts")
    for scenario in scenarios.SCENARIO_LIST:
        console.attack(scenario.id)
    everything = json.dumps(console.state())
    admin_password = (state_dir / "admin_password").read_text().strip()
    secrets_seen = [admin_password, console.demo._customer.password, console.api.secret, console.api.refresh_secret,
                    console.demo._customer.access, console.demo._customer.refresh]
    for secret in secrets_seen:
        assert secret not in everything
    assert "eyJ" not in everything                      # ninguna llave (JWT) viaja a la página
    assert not re.search(r"(?i)password\"\s*:\s*\"(?!\s*\")", everything)


# -- reinicio ---------------------------------------------------------------------------------------------------------------------------------------------

def test_reset_starts_the_walkthrough_again_and_hides_the_old_log(console):
    console.customer_ready()
    console.post("/api/accounts")
    console.attack("bruteforce")
    assert console.state()["log"]
    assert console.post("/api/reset")[0] == 200
    state = console.state()
    assert state["customer"] is None and state["admin_list"] is None and state["results"] == {} and state["log"] == []
    assert [e["text"][:20] for e in state["events"]] == ["Recorrido reiniciado"]
    assert console.post("/api/customer")[0] == 200                    # se puede volver a empezar
    assert any("User registered" in line["text"] for line in console.state()["log"])


def test_the_log_is_read_from_the_start_again_if_the_api_trimmed_it(console):
    console.attack("bad-input")
    console.post("/api/reset")
    log = console.api.log_path
    log.write_text("2026-11-12 10:00:00 [\x1b[32minfo\x1b[39m]: User registered: x\n", encoding="utf-8")   # la API recortó el archivo
    assert [line["text"] for line in console.state()["log"]] == ["User registered: x"]
