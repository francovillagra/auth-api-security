"""El compose y las imágenes: las garantías de seguridad de la demo no dependen de que alguien se acuerde de ellas; se verifican acá."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from common import API_UID, CONSOLE_UID, DB_HOST, DB_NAME, DB_USER, SECRET_FILES  # noqa: E402

DEMO_DIR = Path(__file__).resolve().parent.parent
REPO = DEMO_DIR.parent
OURS = ("init", "setup", "api", "console")   # lo que se construye con los Dockerfile de la demo (postgres es la imagen oficial)


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load((DEMO_DIR / "docker-compose.yml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def services(compose) -> dict:
    return compose["services"]


def network_names(service: dict) -> set[str]:
    networks = service.get("networks", [])
    return set(networks) if isinstance(networks, (list, dict)) else set()


def environment(service: dict) -> dict:
    env = service.get("environment", {})
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    return {key: str(value) for key, value in env.items()}


def stages(dockerfile: str) -> list[str]:
    """El texto de cada etapa de un Dockerfile (lo que hay entre un FROM y el siguiente)."""
    return [part for part in re.split(r"(?m)^(?=FROM )", dockerfile) if part.startswith("FROM ")]


# -- red y puertos -----------------------------------------------------------------------------------------------------------

def test_only_the_console_publishes_a_port_and_only_on_this_computer(services):
    published = {name: svc["ports"] for name, svc in services.items() if svc.get("ports")}
    assert list(published) == ["console"]
    (mapping,) = published["console"]
    assert str(mapping).startswith("127.0.0.1:"), mapping   # nunca 0.0.0.0: nadie de la red local entra
    assert str(mapping).endswith(":8080")
    assert not any("expose" in svc for svc in services.values())


def test_the_lab_network_has_no_way_out(compose, services):
    assert compose["networks"]["lab"]["internal"] is True
    assert not compose["networks"]["edge"].get("internal")
    for name in ("postgres", "setup", "api"):
        assert network_names(services[name]) == {"lab"}, name   # base, preparación y API: solo la red sin salida
    assert network_names(services["console"]) == {"lab", "edge"}   # la consola necesita 'edge' únicamente para publicar su puerto
    assert services["init"]["network_mode"] == "none" and "networks" not in services["init"]


def test_nothing_is_privileged_or_shares_the_host(services):
    for name, svc in services.items():
        assert not svc.get("privileged"), name
        assert svc.get("network_mode") in (None, "none"), name
        assert svc.get("pid") is None and svc.get("ipc") is None and not svc.get("devices"), name
        for volume in svc.get("volumes", []):
            assert "docker.sock" not in str(volume) and not str(volume).startswith(("/", ".", "~")), (name, volume)   # solo volúmenes con nombre
        assert not svc.get("cap_add") or name == "init", name


def test_the_console_reaches_the_api_by_the_name_and_port_the_api_listens_on(services):
    assert environment(services["console"])["DEMO_API_URL"] == "http://api:3000"
    assert environment(services["api"])["PORT"] == "3000"
    assert "127.0.0.1:3000/" in " ".join(services["api"]["healthcheck"]["test"])
    from console.server import Config

    assert Config.api_url == "http://api:3000" and Config.public_port == 4200
    assert services["console"]["ports"] == ["127.0.0.1:${DEMO_CONSOLE_PORT:-4200}:8080"]
    assert environment(services["console"])["DEMO_CONSOLE_PUBLIC_PORT"] == "${DEMO_CONSOLE_PORT:-4200}"


# -- secretos ----------------------------------------------------------------------------------------------------------------

def test_no_credential_is_written_in_the_compose_file(services):
    sensitive = re.compile(r"PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|DATABASE_URL|JWT", re.I)
    for name, svc in services.items():
        for key, value in environment(svc).items():
            if sensitive.search(key):
                assert key.endswith("_FILE") and value.startswith("/run/demo/"), (name, key)   # solo se indica el archivo donde está
    assert environment(services["postgres"])["POSTGRES_PASSWORD_FILE"] == "/run/demo/postgres_password"
    assert environment(services["api"]).keys() == {"HOME", "PORT"}   # los secretos de la API los lee launch.mjs del volumen
    assert environment(services["setup"]).keys() == {"HOME"}


def test_the_secret_files_are_the_ones_the_scripts_read():
    env_mjs = (DEMO_DIR / "env.mjs").read_text(encoding="utf-8")
    for name in ("postgres_password", "jwt_secret", "jwt_refresh_secret"):
        assert f"readState('{name}')" in env_mjs
    assert "readState('admin_password')" in (DEMO_DIR / "setup.mjs").read_text(encoding="utf-8")
    assert set(SECRET_FILES) == {"postgres_password", "jwt_secret", "jwt_refresh_secret", "admin_password"}


def test_the_database_names_match_between_compose_and_scripts(services):
    env = environment(services["postgres"])
    assert env["POSTGRES_USER"] == DB_USER and env["POSTGRES_DB"] == DB_NAME
    assert f"-U {DB_USER} -d {DB_NAME}" in " ".join(services["postgres"]["healthcheck"]["test"])
    assert DB_HOST in services                                   # el nombre del servicio es la dirección que usa la API
    env_mjs = (DEMO_DIR / "env.mjs").read_text(encoding="utf-8")
    assert f"?? '{DB_USER}'" in env_mjs and f"?? '{DB_NAME}'" in env_mjs and f"?? '{DB_HOST}'" in env_mjs


def test_the_whole_demo_folder_has_no_hardcoded_secrets():
    pattern = re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]")
    skipped = {"tests", "__pycache__", "node_modules"}
    checked = 0
    for path in DEMO_DIR.rglob("*"):
        if path.is_file() and not skipped & set(path.relative_to(DEMO_DIR).parts) and path.suffix in {".py", ".yml", ".js", ".mjs", ".html", ".md", ".txt"}:
            assert not pattern.search(path.read_text(encoding="utf-8")), path
            checked += 1
    assert checked >= 15


def test_the_images_carry_no_fixed_secret(services):
    api = (DEMO_DIR / "api.Dockerfile").read_text(encoding="utf-8")
    assert not re.search(r"(?mi)^\s*(ENV|ARG)\b[^\n]*(SECRET|PASSWORD|TOKEN|DATABASE_URL|API_KEY)", api)   # nada fijo en ninguna capa
    final = stages(api)[-1]
    assert not re.search(r"(?i)JWT_|DATABASE_URL|SECRET|PASSWORD", final)
    assert "randomBytes" in stages(api)[0]                       # los valores del build salen al azar y solo viven en ese paso


# -- volúmenes -----------------------------------------------------------------------------------------------------------------

def test_volumes_are_read_only_where_they_can_be(services):
    state, shared = "demo_state:/run/demo", "demo_shared:/run/shared"
    for name in ("postgres", "setup", "api", "console"):
        assert f"{state}:ro" in services[name]["volumes"], name    # solo `init` escribe las credenciales y los datos de práctica
    assert shared in services["api"]["volumes"]                    # la API escribe su registro...
    assert f"{shared}:ro" in services["console"]["volumes"]        # ...y la consola solo lo lee
    assert set(services["init"]["volumes"]) == {state, shared}
    assert not [v for name in ("postgres", "setup") for v in services[name].get("volumes", []) if "shared" in v]


# -- endurecimiento ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", OURS)
def test_containers_drop_every_capability_and_cannot_gain_more(services, name):
    svc = services[name]
    assert svc["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in svc["security_opt"]


@pytest.mark.parametrize("name", OURS)
def test_our_containers_have_a_read_only_filesystem(services, name):
    assert services[name]["read_only"] is True


def test_the_only_writable_places_of_the_api_are_memory_and_its_log_folder(services):
    for name in ("setup", "api"):
        assert "/tmp" in services[name]["tmpfs"] and environment(services[name])["HOME"] == "/tmp", name
    assert "/app/.next/cache:uid=1000,gid=1000" in services["api"]["tmpfs"]
    assert f"uid={API_UID},gid={API_UID}" in "".join(services["api"]["tmpfs"])


def test_only_init_adds_capabilities_and_only_the_three_it_needs(services):
    added = {name: svc["cap_add"] for name, svc in services.items() if svc.get("cap_add")}
    assert added == {"init": ["CHOWN", "DAC_OVERRIDE", "FOWNER"]}
    assert services["init"]["user"] == "root"
    assert [name for name, svc in services.items() if svc.get("user") == "root"] == ["init"]


def test_the_database_lives_in_memory(services):
    assert services["postgres"]["tmpfs"] == ["/var/lib/postgresql/data"]
    assert not [v for v in services["postgres"]["volumes"] if "postgresql/data" in v]


# -- arranque ordenado ------------------------------------------------------------------------------------------------------------

def test_everything_waits_for_init_and_the_console_waits_for_the_api(services):
    for name in ("postgres", "setup", "api"):
        assert services[name]["depends_on"]["init"]["condition"] == "service_completed_successfully", name
    assert services["setup"]["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert services["api"]["depends_on"]["setup"]["condition"] == "service_completed_successfully"
    assert services["console"]["depends_on"] == {"api": {"condition": "service_healthy"}}
    for name in ("postgres", "api", "console"):
        assert "healthcheck" in services[name], name
    assert services["setup"]["command"] == ["node", "demo/setup.mjs"]


def test_the_api_is_built_from_the_unmodified_project_folder(services):
    for name in ("setup", "api"):
        assert services[name]["build"] == {"context": "..", "dockerfile": "demo/api.Dockerfile"}
        assert services[name]["image"] == "auth-api-demo-api"
    for name in ("init", "console"):
        assert services[name]["build"] == {"context": ".", "dockerfile": "tools.Dockerfile"}
        assert services[name]["image"] == "auth-api-demo-tools"
    api = (DEMO_DIR / "api.Dockerfile").read_text(encoding="utf-8")
    assert "npx next build" in api and "npm ci" in api and "npm install" not in api   # versiones exactas del package-lock.json
    assert 'CMD ["node", "demo/launch.mjs"]' in api


# -- imágenes --------------------------------------------------------------------------------------------------------------------------

def test_the_tools_image_runs_as_an_unprivileged_user_with_no_dependencies():
    dockerfile = (DEMO_DIR / "tools.Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^USER demo$", dockerfile, re.M) and re.search(r"^FROM python:3\.\d+-slim$", dockerfile, re.M)
    assert f"--uid {CONSOLE_UID}" in dockerfile
    assert "pip install" not in dockerfile and not (DEMO_DIR / "requirements.txt").exists()   # solo la biblioteca estándar


def test_the_api_image_runs_as_the_node_user_and_the_build_tools_stay_in_the_first_stage():
    first, final = stages((DEMO_DIR / "api.Dockerfile").read_text(encoding="utf-8"))
    assert re.search(r"^USER node$", final, re.M) and "USER" not in first
    assert API_UID == 1000                                       # uid del usuario `node` de la imagen de Node
    assert re.match(r"FROM node:\d+-bookworm-slim AS build", first) and re.match(r"FROM node:\d+-bookworm-slim\n", final)
    assert "npx next build" not in final and "npm ci" not in final
    assert "--chown=node:node" in final


def _copy_sources(dockerfile: str) -> list[str]:
    sources = []
    for line in re.findall(r"(?m)^COPY\s+(?!--from)(?:--\S+\s+)*(.+)$", dockerfile):
        parts = line.split()
        sources += parts[:-1]
    return sources


def _whitelist(path: Path) -> set[str]:
    return {line[1:].strip() for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("!")}


def test_every_file_the_tools_image_copies_exists_and_is_let_through_by_its_ignore_file():
    sources = _copy_sources((DEMO_DIR / "tools.Dockerfile").read_text(encoding="utf-8"))
    allowed = _whitelist(DEMO_DIR / ".dockerignore")
    assert sources
    for source in sources:
        assert (DEMO_DIR / source).exists(), source
        assert source in allowed, source


def test_every_file_the_api_image_copies_exists_and_is_let_through_by_its_ignore_file():
    dockerfile = (DEMO_DIR / "api.Dockerfile").read_text(encoding="utf-8")
    ignore = DEMO_DIR / "api.Dockerfile.dockerignore"
    assert ignore.read_text(encoding="utf-8").splitlines()[2] == "**"           # lista blanca: todo lo demás se ignora
    allowed = _whitelist(ignore)
    sources = _copy_sources(dockerfile)
    assert sources
    for source in sources:
        assert (REPO / source).exists(), source
        assert source.rstrip("/") in allowed or source.removeprefix("./") in allowed, source
    for forbidden in (".env", ".git", "node_modules", ".next", "tests", "assets"):
        assert forbidden not in allowed


def test_line_endings_stay_unix_so_the_containers_work_when_cloned_on_windows():
    assert "* text eol=lf" in (DEMO_DIR / ".gitattributes").read_text(encoding="utf-8")
