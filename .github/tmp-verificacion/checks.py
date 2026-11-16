"""Comprobaciones de la demo en Docker para la verificación temporal (rama tmp/verificacion-docker-auth-api).

Se corre dentro de demo/, con la demo ya encendida:

    python3 ../.github/tmp-verificacion/checks.py estado
    python3 ../.github/tmp-verificacion/checks.py seguridad

Imprime una línea por comprobación (OK / FALLA), deja un resumen en el panel del job y termina con código 1 si alguna falla.
Son las comprobaciones de la «Prueba de aceptación en Docker Desktop» de demo/README.md, pasos 2 y 5, más los ajustes de seguridad
que el docker-compose.yml declara, leídos del contenedor en ejecución (docker inspect).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

PROJECT = "auth-api-demo"


def run(args, timeout=90):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


class Report:
    def __init__(self, title: str):
        self.title = title
        self.lines: list[str] = []
        self.failed = 0

    def check(self, ok: bool, text: str) -> None:
        line = f"{'OK   ' if ok else 'FALLA'} {text}"
        self.lines.append(line)
        print(line, flush=True)
        if not ok:
            self.failed += 1

    def finish(self) -> int:
        total = len(self.lines)
        summary = f"{self.title}: {total - self.failed} de {total} comprobaciones en orden"
        print(summary)
        path = os.environ.get("GITHUB_STEP_SUMMARY")
        if path:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(f"### {self.title}\n\n```\n" + "\n".join(self.lines) + "\n```\n\n")
        if self.failed:
            failing = [line for line in self.lines if line.startswith("FALLA")]
            print(f"::error title={self.title}::{escape(summary + chr(10) + chr(10).join(failing))}")
            return 1
        print(f"::notice title={self.title}::{escape(summary + chr(10) + chr(10).join(self.lines))}")
        return 0


def compose_ps() -> dict[str, dict]:
    raw = run(["docker", "compose", "ps", "-a", "--format", "json"]).stdout.strip()
    try:
        data = json.loads(raw)
        rows = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:  # versiones de Compose que escriben un objeto por línea
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    return {row["Service"]: row for row in rows}


def inspect(service: str) -> dict:
    ids = run(["docker", "compose", "ps", "-a", "-q", service]).stdout.split()
    if not ids:
        return {}
    return json.loads(run(["docker", "inspect", ids[0]]).stdout)[0]


def estado() -> int:
    rep = Report("Estado de los servicios")
    rows = compose_ps()
    for service in ("init", "setup"):
        row = rows.get(service) or {}
        rep.check(
            row.get("State") == "exited" and row.get("ExitCode") == 0,
            f"{service} terminó con código 0 (estado={row.get('State')}, código={row.get('ExitCode')})",
        )
    for service in ("postgres", "api", "console"):
        row = rows.get(service) or {}
        rep.check(
            row.get("State") == "running" and row.get("Health") == "healthy",
            f"{service} figura healthy (estado={row.get('State')}, salud={row.get('Health')})",
        )
    return rep.finish()


def seguridad() -> int:
    rep = Report("Comprobaciones de seguridad")
    rows = compose_ps()

    # 1) La API no tiene salida a internet: el pedido a un sitio público debe terminar con un error de red (no con una página).
    probe = (
        "require('http').get('http://example.com', {timeout: 5000}, (r) => { console.log(r.statusCode); process.exit(0); })"
        ".on('error', (e) => { console.error(e.code); process.exit(1); })"
    )
    out = run(["docker", "compose", "exec", "-T", "api", "node", "-e", probe])
    last = (out.stdout + out.stderr).strip().splitlines()[-1:] or [""]
    rep.check(
        out.returncode == 1 and re.fullmatch(r"E[A-Z_]+", last[0]) is not None,
        f"la API no sale a internet: el pedido a example.com terminó con error de red (código {out.returncode}, detalle «{last[0]}»)",
    )

    # 2) Solo la consola publica un puerto, y solo en 127.0.0.1:4200.
    published = {}
    for service, row in rows.items():
        pubs = {
            f"{p.get('URL')}:{p['PublishedPort']}->{p.get('TargetPort')}/{p.get('Protocol')}"
            for p in (row.get("Publishers") or [])
            if p.get("PublishedPort")
        }
        published[service] = sorted(pubs)
    only_console = published.get("console") == ["127.0.0.1:4200->8080/tcp"] and all(
        not ports for service, ports in published.items() if service != "console"
    )
    rep.check(only_console, f"solo la consola publica un puerto, solo en 127.0.0.1: {json.dumps(published)}")

    # 3) Los contenedores propios corren sin root.
    for service, uid in (("console", "10002"), ("api", "1000")):
        res = run(["docker", "compose", "exec", "-T", service, "id", "-u"])
        rep.check(res.stdout.strip() == uid, f"{service} corre con el usuario {uid} (devolvió «{res.stdout.strip() or res.stderr.strip()}»)")

    # 4) Ajustes de seguridad que declara el docker-compose.yml, leídos del contenedor real.
    for service in ("api", "setup", "console", "init"):
        host = inspect(service).get("HostConfig", {})
        drop = [c.upper().removeprefix("CAP_") for c in (host.get("CapDrop") or [])]
        options = host.get("SecurityOpt") or []
        rep.check(host.get("ReadonlyRootfs") is True, f"{service}: sistema de archivos de solo lectura")
        rep.check("ALL" in drop, f"{service}: descarta todas las capacidades de Linux (CapDrop={host.get('CapDrop')})")
        rep.check(any("no-new-privileges" in o for o in options), f"{service}: no-new-privileges (SecurityOpt={options})")
    init_host = inspect("init").get("HostConfig", {})
    added = sorted(c.upper().removeprefix("CAP_") for c in (init_host.get("CapAdd") or []))
    rep.check(added == ["CHOWN", "DAC_OVERRIDE", "FOWNER"], f"init: solo agrega CHOWN, DAC_OVERRIDE y FOWNER (CapAdd={init_host.get('CapAdd')})")
    rep.check(init_host.get("NetworkMode") == "none", f"init: sin red (NetworkMode={init_host.get('NetworkMode')})")

    # 5) Redes: «lab» es interna; la API y la base solo están ahí; la consola está en «lab» y en «edge».
    names = run(["docker", "network", "ls", "--filter", f"label=com.docker.compose.project={PROJECT}", "--format", "{{.Name}}"]).stdout.split()
    lab = next((n for n in names if n.endswith("_lab")), None)
    edge = next((n for n in names if n.endswith("_edge")), None)
    lab_info = json.loads(run(["docker", "network", "inspect", lab]).stdout)[0] if lab else {}
    edge_info = json.loads(run(["docker", "network", "inspect", edge]).stdout)[0] if edge else {}
    rep.check(lab_info.get("Internal") is True, f"la red lab es internal (sin salida): {lab}")
    rep.check(edge_info.get("Internal") is False, f"la red edge no es internal (solo para publicar la consola): {edge}")
    for service, expected in (("api", [lab]), ("postgres", [lab]), ("console", sorted([lab, edge]))):
        got = sorted((inspect(service).get("NetworkSettings", {}).get("Networks") or {}).keys())
        rep.check(got == expected, f"{service} está en las redes {got}")
    return rep.finish()


if __name__ == "__main__":
    commands = {"estado": estado, "seguridad": seguridad}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit("uso: checks.py estado|seguridad")
    sys.exit(commands[sys.argv[1]]())
