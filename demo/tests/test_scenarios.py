"""Los ataques: qué pedidos hacen, qué veredicto dan con una API como la real y, sobre todo, que el veredicto sale de lo que la API contesta.

Para eso cada ataque se corre también contra una API de mentira más débil (sin freno, sin detección de robo, sin control de roles...) y
tiene que informar que no la frenó. Si el resultado estuviera escrito de antemano, esas pruebas fallarían.
"""
from __future__ import annotations

import ipaddress

import pytest

from console import scenarios
from console.server import Refused

DEFENDED = [s.id for s in scenarios.SCENARIO_LIST if s.group == scenarios.DEFENDED]
LIMITS = [s.id for s in scenarios.SCENARIO_LIST if s.group == scenarios.LIMIT]

CUSTOMER_NET = ipaddress.ip_network("192.0.2.0/24")
ATTACKER_NET = ipaddress.ip_network("203.0.113.0/24")
SPREAD_NET = ipaddress.ip_network("198.51.100.0/24")


def statuses(result):
    return [a["status"] for a in result["attempts"]]


# -- catálogo -------------------------------------------------------------------------------------------------------------------

def test_catalog_has_six_defended_attacks_and_two_documented_limits():
    assert len(DEFENDED) == 6 and LIMITS == ["spoof-ip", "logout-token"]
    assert [item["id"] for item in scenarios.CATALOG] == [s.id for s in scenarios.SCENARIO_LIST]
    assert len({s.id for s in scenarios.SCENARIO_LIST}) == len(scenarios.SCENARIO_LIST)
    for scenario in scenarios.SCENARIO_LIST:
        assert scenario.title and scenario.what and scenario.group in (scenarios.DEFENDED, scenarios.LIMIT)
        assert scenario.expected_held == (scenario.group == scenarios.DEFENDED)


# -- contra una API como la real ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("scenario_id", DEFENDED)
def test_every_defended_attack_is_stopped(console, scenario_id):
    result = console.attack(scenario_id)
    assert result["held"] is True, result
    assert result["id"] == scenario_id and result["attempts"] and result["headline"] and result["lesson"]
    assert all(a["ok"] for a in result["attempts"]), result["attempts"]


@pytest.mark.parametrize("scenario_id", LIMITS)
def test_the_documented_limits_are_reproduced_and_reported_as_open(console, scenario_id):
    result = console.attack(scenario_id)
    assert result["held"] is False, result
    assert result["limit"] and "README" in result["limit"]
    assert not all(a["ok"] for a in result["attempts"])


def test_bruteforce_is_throttled_after_the_fifth_attempt(console):
    result = console.attack("bruteforce")
    assert statuses(result) == [401] * 5 + [429] * 3
    assert "intento 6" in result["headline"]
    assert "Podría volver a intentar en" in result["attempts"][-1]["note"]
    assert {a["who"] for a in result["attempts"]} == {"Atacante"}
    attackers = {ip for method, path, status, ip in console.api.requests if path == "/api/auth/login"}
    assert len(attackers) == 1 and ipaddress.ip_address(attackers.pop()) in ATTACKER_NET


def test_stolen_session_is_detected_and_the_whole_session_is_closed(console):
    result = console.attack("stolen-session")
    assert statuses(result) == [201, 200, 401, 401, 200]
    assert [a["who"] for a in result["attempts"]] == ["Titular", "Titular", "Atacante", "Titular", "Titular"]
    log = console.api.log_path.read_text(encoding="utf-8")
    assert "Refresh token reuse detected" in log
    # el servidor lo registró como alerta y la página lo ve en el registro de la API
    warnings = [line for line in console.state()["log"] if line["level"] == "warn"]
    assert any("reuse detected" in line["text"] for line in warnings)


def test_forged_keys_are_all_rejected_with_401(console):
    result = console.attack("forged-token")
    assert statuses(result) == [401] * 5
    assert all(u["role"] == "USER" for u in console.api.users.values() if u["email"].startswith("prueba-"))


def test_a_customer_cannot_become_administrator(console):
    result = console.attack("privilege-escalation")
    assert statuses(result) == [403, 403, 200, 200]
    assert [a["who"] for a in result["attempts"]] == ["Cliente", "Cliente", "Cliente", "Administración"]
    customers = [u for u in console.api.users.values() if u["email"].startswith("prueba-")]
    assert customers and all(u["role"] == "USER" for u in customers)
    assert "en ninguna aparece la contraseña" in result["attempts"][-1]["note"]


def test_role_changes_apply_immediately_and_the_employee_ends_as_a_customer(console):
    result = console.attack("revoked-role")
    assert statuses(result) == [403, 200, 200, 200, 403]
    employees = [u for u in console.api.users.values() if u["name"] == "Empleado de práctica"]
    assert len(employees) == 1 and employees[0]["role"] == "USER"


def test_bad_input_gets_precise_errors(console):
    result = console.attack("bad-input")
    assert statuses(result) == [400, 400, 413, 415]


def test_spoofing_the_address_gets_around_the_throttle(console):
    result = console.attack("spoof-ip")
    assert statuses(result) == [401] * len(scenarios.GUESSES)
    addresses = [ip for method, path, status, ip in console.api.requests if path == "/api/auth/login"]
    assert len(set(addresses)) == len(scenarios.GUESSES)
    assert all(ipaddress.ip_address(ip) in SPREAD_NET for ip in addresses)
    flagged = [a for a in result["attempts"] if not a["ok"]]
    assert [a["status"] for a in flagged] == [401, 401, 401]   # los tres que debieron frenarse
    assert "no frenó" in result["lesson"] or "no actuó" in result["headline"]


def test_logout_cuts_the_renewal_but_not_the_access_key(console):
    result = console.attack("logout-token")
    assert statuses(result) == [204, 401, 200]
    assert result["attempts"][-1]["ok"] is False and "15 minutos" in result["attempts"][-1]["note"]


# -- las direcciones de práctica ---------------------------------------------------------------------------------------------------------------

def test_each_character_calls_from_its_own_address_so_attacks_never_consume_the_customers_allowance(console):
    console.customer_ready()
    console.attack("bruteforce")
    console.attack("stolen-session")
    console.attack("spoof-ip")
    console.post("/api/accounts")
    seen = {ip for method, path, status, ip in console.api.requests}
    assert {"192.0.2.10", "192.0.2.20"} <= seen                       # el cliente del recorrido y la administración
    nets = [CUSTOMER_NET, ATTACKER_NET, SPREAD_NET]
    assert all(any(ipaddress.ip_address(ip) in net for net in nets) for ip in seen), seen   # solo bloques reservados para documentación
    customer_requests = [r for r in console.api.requests if r[3] == "192.0.2.10"]
    assert customer_requests and all(status != 429 for method, path, status, ip in customer_requests)
    # el cliente puede seguir usando la API aunque el atacante haya sido frenado
    assert console.post("/api/profile", {})[0] == 200


def test_running_the_same_attack_twice_in_a_row_gives_the_same_verdict(console):
    first, second = console.attack("bruteforce"), console.attack("bruteforce")
    assert statuses(first) == statuses(second) == [401] * 5 + [429] * 3


# -- el veredicto sale de lo que contesta la API ------------------------------------------------------------------------------------------------

def test_without_a_throttle_bruteforce_is_reported_as_not_stopped(make_console):
    result = make_console(rate_limit=False).attack("bruteforce")
    assert statuses(result) == [401] * 8
    assert result["held"] is False and "no frenó" in result["headline"]
    assert [a["ok"] for a in result["attempts"]] == [True] * 5 + [False] * 3


def test_a_platform_that_sets_the_address_makes_the_spoofing_attack_fail(make_console):
    result = make_console(trust_real_ip=False).attack("spoof-ip")   # todos los pedidos comparten una sola dirección
    assert 429 in statuses(result) and result["held"] is True
    assert "frenó" in result["headline"]


def test_without_reuse_detection_the_stolen_session_is_not_reported_as_handled(make_console):
    result = make_console(reuse_detection=False).attack("stolen-session")
    assert statuses(result) == [201, 200, 401, 200, 200]
    assert result["held"] is False and "no detecta el robo" in result["headline"]


def test_an_api_that_accepts_forged_keys_is_reported_as_broken(make_console):
    result = make_console(verify_signature=False, rbac_from_db=False).attack("forged-token")
    assert statuses(result) == [401, 200, 200, 200, 200]
    assert result["held"] is False and "aceptó una llave falsa" in result["headline"]
    assert "¡La API le dio acceso" in result["attempts"][1]["note"]


def test_without_role_checks_the_customer_gets_in(make_console):
    result = make_console(check_roles=False).attack("privilege-escalation")
    assert statuses(result)[:2] == [200, 200]
    assert result["held"] is False and "dejó pasar" in result["headline"]


def test_a_listing_that_includes_passwords_is_reported(make_console):
    result = make_console(leak_passwords=True).attack("privilege-escalation")
    assert result["held"] is False
    assert result["attempts"][-1]["ok"] is False and "contraseñas" in result["attempts"][-1]["note"]


def test_roles_read_from_the_token_do_not_apply_immediately(make_console):
    console = make_console(rbac_from_db=False)
    result = console.attack("revoked-role")
    assert statuses(result) == [403, 200, 403, 200, 403]   # el ascenso no surtió efecto con la llave anterior
    assert result["held"] is False
    assert [u["role"] for u in console.api.users.values() if u["name"] == "Empleado de práctica"] == ["USER"]


def test_without_input_validation_bad_input_is_reported(make_console):
    result = make_console(validate_input=False).attack("bad-input")
    assert result["held"] is False and statuses(result) != [400, 400, 413, 415]


def test_if_the_project_fixes_the_logout_limit_the_console_reports_it_as_covered(make_console):
    result = make_console(revoke_access_on_logout=True).attack("logout-token")
    assert statuses(result) == [204, 401, 401]
    assert result["held"] is True and result["limit"] == ""


# -- fallas ------------------------------------------------------------------------------------------------------------------------------------------

def test_a_server_error_stops_the_attack_with_a_clear_message(console):
    console.api.broken_paths.add("/api/auth/login")
    status, body = console.post("/api/scenario", {"id": "bruteforce"})
    assert status == 502 and "500" in body["error"] and "registro" in body["error"]
    last = console.state()["events"][-1]
    assert last["ok"] is False and "no pudo completarse" in last["text"]
    assert "bruteforce" not in console.state()["results"]


def test_an_attack_that_needs_the_administration_says_so_when_it_cannot_log_in(make_console, state_dir):
    console = make_console()
    console.api.users[console.config.admin_email]["password"] = "otra"   # la API ya no acepta la contraseña de práctica
    status, body = console.post("/api/scenario", {"id": "privilege-escalation"})
    assert status == 502 and "administración" in body["error"] and "401" in body["error"]


def test_the_rate_limit_stops_the_preparation_of_a_test_account_with_a_clear_message(console):
    console.api.limited = lambda ip: 7   # la API limita cualquier pedido de /api/auth/*
    status, body = console.post("/api/scenario", {"id": "forged-token"})
    assert status == 502 and "limitando" in body["error"]


def test_scenario_errors_are_plain_exceptions_with_a_message():
    assert str(scenarios.ScenarioError("x")) == "x"
    assert issubclass(Refused, Exception)
