"""Lee el registro que escribe la API (la copia que deja launch.mjs en la carpeta compartida) y lo deja listo para mostrar.

El registro es el de verdad: líneas de Winston («2026-11-12 16:05:11 [info]: POST /api/auth/login 401 — 85ms») y los avisos del proxy
cuando frena a alguien. La API identifica a las personas por id, nunca por correo, y no escribe contraseñas ni llaves; igual se limita
el largo de cada línea. Las líneas que no tienen esa forma (el saludo de arranque de Next, restos de errores) no se muestran.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

MAX_READ_BYTES = 64 * 1024
MAX_LINES = 40
MAX_LINE_CHARS = 300

ANSI = re.compile(r"\x1b\[[0-9;]*m")
WINSTON = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) \[(\w+)\]: (.*)$")
RATE_LIMITED = re.compile(r"^\[proxy\] 429 rate limited: (\S+) → (\S+)$")
LEVELS = {"info", "warn", "error"}


def parse(lines: list[str]) -> list[dict]:
    """Convierte líneas de texto en {t, level, text}. `t` es la hora en UTC (ISO) o None si la línea no la trae."""
    entries: list[dict] = []
    last_time: Optional[str] = None
    for line in lines:
        text = ANSI.sub("", line).rstrip()
        match = WINSTON.match(text)
        if match:
            date, clock, level, message = match.groups()
            last_time = f"{date}T{clock}Z"
            if level in LEVELS:   # el nivel debug no se muestra
                entries.append({"t": last_time, "level": level, "text": message[:MAX_LINE_CHARS]})
            continue
        limited = RATE_LIMITED.match(text)
        if limited:
            ip, path = limited.groups()
            entries.append({"t": last_time, "level": "warn", "text": f"Pedido frenado por exceso de intentos: {ip} → {path}"[:MAX_LINE_CHARS]})
    return entries


def tail(path: Path, floor: int = 0) -> tuple[list[dict], int]:
    """Las últimas líneas del registro desde el byte `floor` (lo que ya había cuando se reinició el recorrido).

    Devuelve (líneas, tamaño actual del archivo). Si el archivo se achicó (la API lo recorta al llegar a su tope), se lee desde el principio.
    """
    try:
        with path.open("rb") as handle:
            size = handle.seek(0, 2)
            start = floor if floor <= size else 0
            read_from = max(start, size - MAX_READ_BYTES)
            handle.seek(read_from)
            data = handle.read()
    except OSError:
        return [], 0
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if read_from > start and lines:   # se empezó a leer en el medio de una línea: esa se descarta
        lines = lines[1:]
    return parse(lines)[-MAX_LINES:], size
