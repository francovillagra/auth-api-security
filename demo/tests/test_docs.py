"""Que lo que dice la demo coincida con lo que hace la API (su código) y con lo que dice su propio README.

La demo afirma cosas ante un cliente: «5 intentos cada 10 segundos», «la llave de acceso dura 15 minutos», «el registro dice tal cosa». Si el
código de la API cambia y la demo no, esas frases pasan a ser falsas. Estas pruebas lo detectan antes de que lo vea alguien.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import fake_api
import smoke
from common import API_UID, CONSOLE_UID
from console import api as apimod
from console import explain, scenarios, serverlog

DEMO = Path(__file__).resolve().parent.parent
REPO = DEMO.parent
README = (DEMO / "README.md").read_text(encoding="utf-8")


def source(*parts: str) -> str:
    return REPO.joinpath(*parts).read_text(encoding="utf-8")


def demo_sources(*suffixes: str) -> list[Path]:
    """Los archivos de la demo (sin pruebas ni copias) con esas extensiones."""
    return [
        path for path in sorted(DEMO.rglob("*"))
        if path.is_file() and path.suffix in suffixes and not {"tests", "__pycache__", "node_modules"} & set(path.relative_to(DEMO).parts)
    ]


# -- los números que la demo le dice al cliente ------------------------------------------------------------------------------

def test_the_rate_limit_the_console_explains_is_the_one_in_the_proxy():
    proxy = source("proxy.ts")
    assert int(re.search(r"const RATE_LIMIT = (\d+);", proxy).group(1)) == explain.RATE_LIMIT_REQUESTS
    assert int(re.search(r"const RATE_WINDOW_MS = ([\d_]+);", proxy).group(1).replace("_", "")) == explain.RATE_LIMIT_SECONDS * 1000
    assert f"slidingWindow(RATE_LIMIT, '{explain.RATE_LIMIT_SECONDS} s')" in proxy
    assert "const RATE_LIMITED_PREFIXES = ['/api/auth'];" in proxy       # el freno vale para /api/auth/* y para nada más


def test_the_life_of_the_keys_the_console_explains_is_the_one_in_the_api():
    auth = source("lib", "auth.ts")
    assert f"expiresIn: '{explain.ACCESS_TOKEN_MINUTES}m'" in auth
    assert f"expiresIn: '{explain.REFRESH_TOKEN_DAYS}d'" in auth
    assert re.search(rf"REFRESH_TOKEN_TTL_MS = {explain.REFRESH_TOKEN_DAYS} \* DAY_MS", source("lib", "refresh-tokens.ts"))


def test_the_fake_api_used_by_the_tests_has_the_same_limits_as_the_real_one():
    assert fake_api.RATE_LIMIT == explain.RATE_LIMIT_REQUESTS and fake_api.RATE_WINDOW == explain.RATE_LIMIT_SECONDS
    assert re.search(r"MAX_JSON_BYTES = (\d+) \* 1024;", source("lib", "http.ts")).group(1) == str(fake_api.MAX_JSON_BYTES // 1024)
    assert f"const ISSUER = '{fake_api.ISSUER}';" in source("lib", "auth.ts")


def test_the_attacks_are_sized_against_the_limits_they_try_to_pass():
    assert len(scenarios.GUESSES) > explain.RATE_LIMIT_REQUESTS                    # si no, el freno nunca tendría ocasión de actuar
    max_kb = int(re.search(r"MAX_JSON_BYTES = (\d+) \* 1024;", source("lib", "http.ts")).group(1))
    assert scenarios.OVERSIZE_BYTES > max_kb * 1024
    assert f"el máximo es {max_kb} KB" in (DEMO / "console" / "scenarios.py").read_text(encoding="utf-8")


# -- a qué le habla la consola ---------------------------------------------------------------------------------------------------

USED_ROUTES = [
    ("POST", "/api/auth/register"), ("POST", "/api/auth/login"), ("POST", "/api/auth/refresh"), ("POST", "/api/auth/logout"),
    ("GET", "/api/users/me"), ("GET", "/api/admin/users"), ("PATCH", "/api/admin/users/[id]/role"),
]


@pytest.mark.parametrize("method, path", USED_ROUTES)
def test_every_endpoint_the_demo_uses_exists_in_the_api_with_that_method(method, path):
    route = REPO / "app" / (path.removeprefix("/") + "/route.ts")
    assert route.is_file(), route
    assert re.search(rf"^export (const|async function) {method}\b", route.read_text(encoding="utf-8"), re.M)


def test_the_console_only_calls_endpoints_that_are_on_that_list():
    found: set[str] = set()
    for path in (DEMO / "console").glob("*.py"):
        for literal in re.findall(r"/api/(?:auth|users|admin)[^\"'\s)]*", path.read_text(encoding="utf-8")):
            found.add(re.sub(r"\{[^}]+\}", "[id]", literal))
    assert found == {path for _, path in USED_ROUTES}


def test_the_client_address_is_declared_with_the_header_the_proxy_reads():
    proxy = source("proxy.ts")
    assert "req.headers.get('x-real-ip')" in proxy
    assert '"x-real-ip"' in (DEMO / "console" / "api.py").read_text(encoding="utf-8")


# -- el registro que la consola muestra -------------------------------------------------------------------------------------------

def test_the_log_formats_the_console_reads_are_the_ones_the_api_writes():
    assert "timestamp({ format: 'YYYY-MM-DD HH:mm:ss' })" in source("lib", "logger.ts")
    assert "`${timestamp} [${level}]: ${stack || message}`" in source("lib", "logger.ts")
    assert "console.warn(`[proxy] 429 rate limited: ${ip} → ${pathname}`);" in source("proxy.ts")
    assert "`${method} ${nextUrl.pathname} ${res.status} — ${Date.now() - start}ms`" in source("lib", "request-logger.ts")
    # y el lector entiende un ejemplo de cada uno
    entries = serverlog.parse([
        "2026-11-12 16:05:11 [\x1b[32minfo\x1b[39m]: POST /api/auth/login 200 — 85ms",
        "[proxy] 429 rate limited: 203.0.113.5 → /api/auth/login",
        "2026-11-12 16:05:12 [\x1b[33mwarn\x1b[39m]: Refresh token reuse detected: user u1, session s1 revoked",
    ])
    assert [e["level"] for e in entries] == ["info", "warn", "warn"]


def test_the_alerts_the_demo_points_to_exist_in_the_api():
    refresh_tokens = source("lib", "refresh-tokens.ts")
    assert "Refresh token reuse detected: user ${stored.userId}, session ${stored.familyId} revoked" in refresh_tokens
    for alert in smoke.ALERTS.values():
        assert alert in refresh_tokens or alert in (DEMO / "console" / "serverlog.py").read_text(encoding="utf-8")


def test_the_api_log_identifies_people_by_id_and_the_page_says_so():
    for path in ("app/api/auth/login/route.ts", "app/api/auth/register/route.ts", "app/api/auth/refresh/route.ts", "app/api/admin/users/route.ts"):
        assert not re.search(r"log\.\w+\(`[^`]*\$\{[^}]*email", source(*path.split("/")), re.I), path


# -- las limitaciones que la Parte 3 reproduce figuran en el README del proyecto ----------------------------------------------------

@pytest.mark.parametrize("phrase", [
    "**El access token no se revoca.**",
    "**El rate limit es por IP, no por cuenta.**",
    "**La IP del cliente se asume confiable solo en Vercel.**",
])
def test_the_limits_shown_in_part_3_are_documented_in_the_project_readme(phrase):
    text = source("README.md")
    assert "## Limitaciones conocidas" in text and phrase in text.split("## Limitaciones conocidas", 1)[1]


def test_the_limit_group_and_the_defended_group_match_what_the_smoke_test_expects():
    for scenario in scenarios.SCENARIO_LIST:
        assert (scenario.group == scenarios.LIMIT) is (not smoke.EXPECTED[scenario.id][0]), scenario.id


# -- el README de la demo -------------------------------------------------------------------------------------------------------------

def readme_row(title: str) -> str:
    return next(line for line in README.splitlines() if line.startswith(f"| {title} |"))


@pytest.mark.parametrize("scenario", scenarios.SCENARIO_LIST, ids=lambda s: s.id)
def test_the_readme_lists_each_attack_with_statuses_the_api_really_answers(scenario):
    mentioned = {int(code) for code in re.findall(r"`(\d{3})`", readme_row(scenario.title))}
    assert mentioned and mentioned <= set(smoke.EXPECTED[scenario.id][1]), (mentioned, smoke.EXPECTED[scenario.id][1])


def test_the_readme_puts_each_attack_in_the_part_of_the_page_where_it_appears():
    part2, part3 = README.split("### Parte 2.", 1)[1].split("### Parte 3.", 1)
    for scenario in scenarios.SCENARIO_LIST:
        assert f"| {scenario.title} |" in (part3 if scenario.group == scenarios.LIMIT else part2), scenario.id


def test_the_readme_gives_the_address_the_commands_and_the_numbers_the_demo_really_uses():
    from console.server import Config

    assert f"http://localhost:{Config.public_port}" in README and f"127.0.0.1:{Config.public_port}->8080/tcp" in README
    assert "DEMO_CONSOLE_PORT" in README and "docker compose up --build" in README and "docker compose down -v" in README
    assert "Consola de la demo lista" in (DEMO / "console" / "server.py").read_text(encoding="utf-8")
    assert f"{smoke.TOTAL_STEPS} pasos" in README and "python demo/tests/smoke.py" in README
    assert f"imprimir `{CONSOLE_UID}`" in README and f"`{API_UID}`" in README


def test_the_buttons_and_panels_the_readme_names_exist_on_the_page():
    page = (DEMO / "console" / "static" / "app.js").read_text(encoding="utf-8") + (DEMO / "console" / "static" / "index.html").read_text(encoding="utf-8")
    for name in (
        "Crear la cuenta de práctica", "Pedir mi perfil", "Probar sin llave", "Renovar la sesión", "Cerrar sesión", "Entrar de nuevo",
        "Ver las cuentas como administración", "Probar este ataque", "Reiniciar el recorrido", "Lo que va pasando", "Lo que registra la API",
        "Sistema listo", "Esperando que la API termine de arrancar", "Parte 1.", "Parte 2.", "Parte 3.", "Límite conocido", "La API lo frenó",
    ):
        assert name in README or name.startswith("Parte"), f"el README ya no nombra «{name}»"
        assert name in page or name in (DEMO / "console" / "scenarios.py").read_text(encoding="utf-8"), f"la página no tiene «{name}»"


def test_every_file_in_the_readme_layout_exists():
    tree = README.split("## Cómo está armado", 1)[1].split("```")[1]
    names = set()
    for line in tree.splitlines():
        entry = line.split("#", 1)[0]
        entry = re.sub(r"[│├└─]+", " ", entry)
        for token in entry.split(" / "):
            token = token.strip()
            if token and token != "demo/":
                names.add(token.rstrip("/"))
    assert {"docker-compose.yml", "api.Dockerfile", "smoke.py", "fake_api.py", "scenarios.py", "serverlog.py"} <= names
    existing = {path.name for path in DEMO.rglob("*")}
    missing = sorted(name for name in names if name not in existing and "*" not in name)
    assert missing == [], f"el README nombra archivos que no existen: {missing}"


# -- español neutro en lo que lee el público ------------------------------------------------------------------------------------------------

VOSEO = re.compile(r"\b(vos|sos|podés|tenés|querés|sabés|hacé|mirá|usá|elegí|pulsá|abrí|esperá|probá|revisá|fijate|acordate|decime|contame|ponete|andá)\b", re.I)
TUTEO = re.compile(r"\b(tú|tienes|puedes|quieres|sabes|haz|eres)\b", re.I)


@pytest.mark.parametrize("path", demo_sources(".py", ".mjs", ".js", ".html", ".css", ".md", ".yml", ".Dockerfile"), ids=lambda p: str(p.relative_to(DEMO)))
def test_the_text_the_public_reads_is_neutral_spanish(path):
    text = path.read_text(encoding="utf-8")
    assert not VOSEO.search(text), VOSEO.search(text).group(0)
    assert not TUTEO.search(text), TUTEO.search(text).group(0)


def test_the_project_readme_points_to_the_demo_and_says_its_tests_run_apart():
    text = source("README.md")
    assert "[`demo/`](demo/README.md)" in text and "http://localhost:4200" in text and "python demo/tests/smoke.py" in text
    assert "docker compose up --build" in text and "no corren en la integración continua" in text
    assert "demo/" in text.split("## Arquitectura", 1)[1].split("### Flujo de una request", 1)[0]


def test_the_page_and_the_readme_name_the_demo_the_same_way():
    page = (DEMO / "console" / "static" / "index.html").read_text(encoding="utf-8")
    assert "<title>Demo de Auth API Security</title>" in page
    assert README.startswith("# Demo local de Auth API Security")
