"""La prueba de humo (smoke.py) corrida contra la consola y una API de mentira: comprueba el guion de la prueba y que detecta cambios."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import smoke
from console import scenarios


def run_smoke(console, **kwargs):
    lines: list[str] = []
    runner = smoke.Smoke(smoke.Client(console.port), wait=3, poll=0.05, out=lines.append, log_wait=kwargs.get("log_wait", 1.0))
    return runner, lines


def test_the_expectations_cover_every_attack_and_match_the_catalog():
    assert set(smoke.EXPECTED) == {s.id for s in scenarios.SCENARIO_LIST}
    for scenario in scenarios.SCENARIO_LIST:
        assert smoke.EXPECTED[scenario.id][0] is scenario.expected_held
    assert set(smoke.ALERTS) <= set(smoke.EXPECTED)


def test_the_whole_walkthrough_passes_against_an_api_that_behaves_like_the_real_one(console):
    runner, lines = run_smoke(console)
    runner.run()
    assert runner.step_number == smoke.TOTAL_STEPS == len(lines)
    assert lines[0].startswith("[ok]  1/17") and lines[-1].startswith("[ok] 17/17")
    assert runner.alerts_seen == set(smoke.ALERTS)
    assert console.state()["customer"] is None          # al terminar deja la demo en cero


def test_main_returns_zero_and_prints_a_summary(console, capsys):
    assert smoke.main(["--port", str(console.port), "--wait", "3"]) == 0
    assert "Todo salió como se esperaba (17 pasos" in capsys.readouterr().out


@pytest.mark.parametrize("flags, message", [
    ({"rate_limit": False}, "bruteforce"),
    ({"reuse_detection": False}, "stolen-session"),
    ({"validate_input": False}, "bad-input"),
    ({"check_roles": False}, "privilege-escalation"),
    ({"revoke_access_on_logout": True}, "logout-token"),   # si el proyecto corrige un límite, la prueba avisa
])
def test_a_change_in_the_api_behaviour_is_reported_with_the_attack_that_shows_it(make_console, flags, message, capsys):
    console = make_console(**flags)
    assert smoke.main(["--port", str(console.port), "--wait", "3"]) == 1
    err = capsys.readouterr().err
    assert "[FALLÓ]" in err and message in err
    if message == "logout-token":
        assert "actualizar la demo y el README" in err


def test_a_demo_that_is_not_running_gets_a_clear_message(capsys):
    from conftest import free_port

    assert smoke.main(["--port", str(free_port())]) == 1
    assert "¿Está encendida la demo?" in capsys.readouterr().err


def test_an_api_that_never_gets_ready_times_out_with_a_pointer_to_the_logs(console):
    console.api.available = False
    runner, _ = run_smoke(console)
    runner.wait = 0.2
    with pytest.raises(smoke.Failure, match="docker compose logs api"):
        runner.run()


class Limited(smoke.Client):
    """Una consola cuyo `path` contesta 429 las primeras `times` veces, como cuando la API frena al cliente del recorrido."""

    def __init__(self, port, path, times):
        super().__init__(port)
        self.path, self.times = path, times

    def call(self, method, path, body=None, timeout=90.0):
        if method == "POST" and path == self.path and self.times:
            self.times -= 1
            return 429, {"error": "La API limita los ingresos (5 cada 10 segundos desde una misma dirección). Esperar unos segundos y probar de nuevo."}
        return super().call(method, path, body, timeout)


def test_a_request_the_api_limited_is_repeated_after_waiting(console):
    lines: list[str] = []
    runner = smoke.Smoke(Limited(console.port, "/api/renew", 2), wait=3, poll=0.05, out=lines.append, log_wait=1, rate_wait=0.01)
    runner.run()
    waits = [line for line in lines if "se espera" in line]
    assert len(waits) == 2 and all("/api/renew" in line for line in waits)
    assert runner.step_number == smoke.TOTAL_STEPS


def test_a_request_that_stays_limited_fails_after_the_retries_and_says_so(console):
    runner = smoke.Smoke(Limited(console.port, "/api/renew", 99), wait=3, poll=0.05, out=lambda *_: None, log_wait=1, rate_wait=0.01)
    with pytest.raises(smoke.Failure, match="429"):
        runner.run()
    assert runner.client.times == 99 - (smoke.RATE_RETRIES + 1)          # se intentó una vez más que reintentos


def test_the_wait_between_retries_covers_the_window_of_the_api():
    from console import explain

    assert smoke.RATE_WINDOW_SECONDS == explain.RATE_LIMIT_SECONDS
    assert smoke.Smoke(smoke.Client(1)).rate_wait > smoke.RATE_WINDOW_SECONDS


def test_an_alert_that_never_reaches_the_log_is_reported_right_after_its_attack(console):
    console.api.log_path = Path(os.devnull)             # la API sigue funcionando, pero su registro no llega a la consola
    runner, lines = run_smoke(console, log_wait=0.3)
    with pytest.raises(smoke.Failure, match="Pedido frenado por exceso de intentos") as failure:
        runner.run()
    assert "bruteforce" in str(failure.value)
    assert runner.step_number == 7                      # falló en el 8º paso (el primer ataque): no siguió con los demás


def test_keys_or_emails_in_the_log_are_reported(console):
    original = console.api.log

    def noisy(level, message):
        original(level, message + " dueño: ana@tienda-demo.test")

    console.api.log = noisy                              # una API que escribe correos en su registro
    runner, _ = run_smoke(console)
    with pytest.raises(smoke.Failure, match="llaves ni correos"):
        runner.run()
