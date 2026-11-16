"""Prueba de humo de la demo de Auth API Security: recorre toda la demo a través de la consola, como lo haría alguien con el navegador.

Se corre con la demo encendida (`docker compose up --build`, dentro de la carpeta demo) y desde cualquier carpeta:

    python demo/tests/smoke.py                  # la consola en el puerto 4200
    python demo/tests/smoke.py --port 4300      # si se cambió DEMO_CONSOLE_PORT

Usa solo la biblioteca estándar de Python (3.8 o más nueva): no hace falta instalar nada. Habla únicamente con la consola de la demo
(127.0.0.1); nunca con otra dirección.

Qué comprueba, en este orden (usa la API verdadera, no una de mentira):
  1. la consola y la API responden;  2. la demo parte de cero;  3. se crea la cuenta de un cliente;  4. el perfil se pide con y sin llave;
  5. la sesión se renueva;  6. se cierra la sesión y se vuelve a entrar;  7. la administración ve las cuentas, sin contraseñas;
  8-13. los seis ataques que la API frena (contraseñas a los golpes, sesión robada, llaves falsas, cliente que quiere ser administrador,
        cambio de rol en pleno uso, datos mal armados), con la secuencia exacta de respuestas de cada uno;
  14-15. los dos límites que el README documenta (cambiar de dirección para esquivar el freno; llave de acceso que sobrevive al cierre
        de sesión);  16. el registro de la API mostró las alertas (los pedidos frenados, justo después de las contraseñas a los golpes; la
        sesión robada, justo después de ese ataque) y no lleva llaves ni correos;  17. la demo vuelve a cero.

Si la API cambia de comportamiento (por ejemplo, si se corrige uno de los límites), esta prueba lo dice: hay que actualizar la demo y el
README, no ignorar el aviso.

AVISO: crea cuentas de práctica en la base de la demo (viven hasta que se apague) y, al empezar y al terminar, reinicia el recorrido.

Termina con código 0 si todo salió como se esperaba y con 1 si algo falló (y dice qué).
"""
from __future__ import annotations

import argparse
import http.client
import json
import re
import socket
import sys
import time
from typing import Any, Optional

# Lo que la API del proyecto debe contestar en cada ataque, tal como lo documenta el README.
EXPECTED: dict[str, tuple[bool, list[int]]] = {
    "bruteforce": (True, [401] * 5 + [429] * 3),
    "stolen-session": (True, [201, 200, 401, 401, 200]),
    "forged-token": (True, [401] * 5),
    "privilege-escalation": (True, [403, 403, 200, 200]),
    "revoked-role": (True, [403, 200, 200, 200, 403]),
    "bad-input": (True, [400, 400, 413, 415]),
    "spoof-ip": (False, [401] * 8),
    "logout-token": (False, [204, 401, 200]),
}
TOTAL_STEPS = 17
# El freno de la API (5 pedidos cada 10 segundos por dirección) también alcanza a esta prueba si se corre dos veces seguidas: el cliente del
# recorrido llama siempre desde la misma dirección. Cuando la consola avisa que la API frenó un pedido (429), se espera a que se libere y se repite.
RATE_WINDOW_SECONDS = 10
RATE_RETRIES = 2
# La alerta que la API debe dejar en su registro apenas termina cada uno de estos ataques (el panel de la consola muestra solo las últimas
# 40 líneas, por eso se mira en el momento y no al final).
ALERTS = {
    "bruteforce": "Pedido frenado por exceso de intentos",
    "stolen-session": "Refresh token reuse detected",
}
SECRET_LOOKING = re.compile(r"eyJ[A-Za-z0-9_-]{5,}|@tienda-demo\.test")      # una llave (JWT) o un correo: el registro lleva ids, nunca esto


class Failure(Exception):
    """Algo no salió como se esperaba. El mensaje dice qué, para quien está mirando la pantalla."""


class ConsoleDown(Failure):
    pass


class Client:
    """Hace los mismos pedidos que la página de la consola (con su Host y su Origin) y devuelve (estado, cuerpo)."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.base = f"http://localhost:{port}"
        self.headers = {"Host": f"localhost:{port}", "Origin": self.base}

    def call(self, method: str, path: str, body: Optional[dict] = None, timeout: float = 90.0) -> tuple[int, Any]:
        headers = dict(self.headers)
        payload = None
        if method == "POST":
            payload = json.dumps(body or {}).encode()
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            connection.request(method, path, payload, headers)
            response = connection.getresponse()
            raw = response.read()
        except socket.timeout:
            raise ConsoleDown(
                f"La consola ({self.base}) no contestó a tiempo. Puede estar ocupada: esperar un momento y repetir la prueba."
            ) from None
        except (OSError, http.client.HTTPException) as exc:
            raise ConsoleDown(
                f"No se pudo hablar con la consola en {self.base} ({exc.__class__.__name__}). "
                "¿Está encendida la demo? Se enciende con:  cd demo  y después  docker compose up --build"
            ) from None
        finally:
            connection.close()
        try:
            return response.status, json.loads(raw)
        except ValueError:
            return response.status, raw


def _short(value: Any, limit: int = 300) -> str:
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[:limit] + "…"


class Smoke:
    def __init__(self, client: Client, wait: float = 120.0, poll: float = 2.0, out=print, log_wait: float = 15.0, rate_wait: float = RATE_WINDOW_SECONDS + 1.0) -> None:
        self.client, self.wait, self.poll, self.out, self.log_wait, self.rate_wait = client, wait, poll, out, log_wait, rate_wait
        self.step_number = 0
        self.alerts_seen: set[str] = set()
        self.started = time.monotonic()

    # -- ayudas ------------------------------------------------------------------------------------------------------------
    def ok(self, text: str) -> None:
        self.step_number += 1
        self.out(f"[ok] {self.step_number:>2}/{TOTAL_STEPS}  {text}")

    def expect(self, condition: bool, what: str, got: Any = None) -> None:
        if not condition:
            detail = f"\n         Se obtuvo: {_short(got)}" if got is not None else ""
            raise Failure(f"{what}{detail}")

    def post(self, path: str, body: Optional[dict] = None, expected: int = 200) -> Any:
        for attempt in range(RATE_RETRIES + 1):
            status, payload = self.client.call("POST", path, body)
            if status != 429 or attempt == RATE_RETRIES:
                break
            self.out(f"      la API frenó un pedido por exceso de intentos ({path}): se espera {self.rate_wait:g} s y se repite")
            time.sleep(self.rate_wait)
        self.expect(status == expected, f"POST {path} debía responder {expected}", f"{status} {_short(payload)}")
        return payload

    def state(self) -> dict:
        status, payload = self.client.call("GET", "/api/state")
        self.expect(status == 200 and isinstance(payload, dict), "GET /api/state debía responder 200", f"{status} {_short(payload)}")
        return payload

    def attack(self, scenario_id: str) -> dict:
        result = self.post("/api/scenario", {"id": scenario_id})
        self.expect(isinstance(result, dict) and "attempts" in result, f"El ataque {scenario_id} debía devolver su resultado", result)
        return result

    # -- el recorrido -------------------------------------------------------------------------------------------------------
    def wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.wait
        while True:
            status, _ = self.client.call("GET", "/healthz")
            self.expect(status == 200, "La consola debía responder en /healthz", status)
            if self.state().get("api_ready"):
                return
            if time.monotonic() > deadline:
                raise Failure(f"La API no estuvo lista en {int(self.wait)} segundos. Ver:  docker compose logs api")
            time.sleep(self.poll)

    def run(self) -> None:
        self.wait_until_ready()
        self.ok("la consola y la API responden")

        self.post("/api/reset")
        state = self.state()
        self.expect(state["customer"] is None and state["results"] == {} and state["admin_list"] is None, "La demo debía partir de cero", state)
        self.ok("la demo parte de cero")

        self.post("/api/customer")
        customer = self.state()["customer"]
        self.expect(bool(customer) and customer["session"] == "active", "Debía quedar una sesión abierta", customer)
        self.ok(f"cuenta de cliente creada ({customer['email']}) y sesión abierta")

        self.post("/api/profile", {})
        profile = self.state()["customer"]["profile"]
        self.expect(bool(profile) and profile["role"] == "USER", "El perfil debía mostrar el rol de cliente", profile)
        refused = self.post("/api/profile", {"anonymous": True})
        self.expect(refused == {"refused": True, "status": 401}, "Sin llave, la API debía rechazar el pedido (401)", refused)
        self.ok("perfil con llave (rol: cliente) y sin llave (rechazado, 401)")

        before = self.state()["customer"]["access_expires_at"]
        self.post("/api/renew")
        after = self.state()["customer"]
        self.expect(after["session"] == "active" and after["access_expires_at"] is not None, "La sesión debía seguir abierta tras renovar", after)
        self.expect(before is None or after["access_expires_at"] >= before, "La llave de acceso nueva no podía vencer antes que la anterior", (before, after))
        self.ok("sesión renovada")

        self.post("/api/logout")
        self.expect(self.state()["customer"]["session"] == "closed", "Al cerrar sesión la consola debía mostrarla cerrada")
        self.post("/api/login")
        self.expect(self.state()["customer"]["session"] == "active", "Al entrar de nuevo la sesión debía quedar abierta")
        self.ok("sesión cerrada y abierta de nuevo con la contraseña")

        self.post("/api/accounts")
        listing = self.state()["admin_list"]
        self.expect(bool(listing) and listing["total"] >= 5, "La administración debía ver al menos 5 cuentas (administración, 3 clientes de práctica y el cliente nuevo)", listing)
        self.expect("password" not in json.dumps(listing).lower(), "El listado no debía incluir contraseñas", listing)
        self.ok(f"la administración ve {listing['total']} cuentas, sin contraseñas")

        for scenario_id in ("bruteforce", "stolen-session", "forged-token", "privilege-escalation", "revoked-role", "bad-input"):
            self._check_attack(scenario_id)
        for scenario_id in ("spoof-ip", "logout-token"):
            self._check_attack(scenario_id)

        self.expect(self.alerts_seen == set(ALERTS), "El registro de la API debía mostrar las alertas de los ataques que la API frena", sorted(self.alerts_seen))
        self.expect(not SECRET_LOOKING.search(json.dumps(self.state()["log"])), "El registro no debía llevar llaves ni correos")
        self.ok("el registro de la API mostró los pedidos frenados y la alerta de robo de sesión, sin llaves ni correos")

        self.post("/api/reset")
        state = self.state()
        self.expect(state["customer"] is None and state["results"] == {} and state["log"] == [], "Al reiniciar, la demo debía volver a cero", state)
        self.ok("la demo vuelve a cero")

    def _check_attack(self, scenario_id: str) -> None:
        held, statuses = EXPECTED[scenario_id]
        result = self.attack(scenario_id)
        got = [a["status"] for a in result["attempts"]]
        self.expect(
            got == statuses,
            f"Las respuestas del ataque «{scenario_id}» no son las documentadas. Si la API cambió a propósito, actualizar la demo y el README.\n"
            f"         Esperado: {statuses}",
            got,
        )
        self.expect(result["held"] is held, f"El veredicto de «{scenario_id}» debía ser {'«la API lo frenó»' if held else '«límite conocido»'}", result["headline"])
        if scenario_id in ALERTS:
            self.wait_for_alert(scenario_id)
        self.ok(f"{scenario_id}: {result['headline']}")

    def wait_for_alert(self, scenario_id: str) -> None:
        """La API escribe su registro y la consola lo copia: puede tardar un instante en aparecer."""
        wanted = ALERTS[scenario_id]
        deadline = time.monotonic() + self.log_wait
        while True:
            warnings = [line["text"] for line in self.state()["log"] if line["level"] == "warn"]
            if any(wanted in text for text in warnings):
                self.alerts_seen.add(scenario_id)
                return
            if time.monotonic() > deadline:
                raise Failure(
                    f"Tras el ataque «{scenario_id}», el registro de la API debía mostrar «{wanted}» y no apareció en {self.log_wait:g} segundos. "
                    "Ver:  docker compose logs api"
                )
            time.sleep(min(self.poll, 0.5))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Prueba de humo de la demo de Auth API Security (consola encendida).")
    parser.add_argument("--port", type=int, default=4200, help="puerto de la consola (por defecto 4200)")
    parser.add_argument("--wait", type=float, default=120.0, help="segundos máximos de espera a que la API esté lista")
    args = parser.parse_args(argv)
    smoke = Smoke(Client(args.port), wait=args.wait)
    try:
        smoke.run()
    except Failure as exc:
        print(f"\n[FALLÓ] paso {smoke.step_number + 1}/{TOTAL_STEPS}: {exc}", file=sys.stderr)
        return 1
    print(f"\nTodo salió como se esperaba ({TOTAL_STEPS} pasos, {time.monotonic() - smoke.started:.1f} s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
