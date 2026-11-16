"""Prepara lo que la demo necesita antes de arrancar: credenciales, datos de práctica y la carpeta compartida.

Nada de esto vive en el repositorio: cada computadora lo genera la primera vez que arranca la demo y lo guarda en un volumen de Docker.
Si ya existe, no se toca (salvo el registro de la API, que empieza limpio en cada encendido). `docker compose down -v` borra los
volúmenes y la próxima vez se genera todo de nuevo.

Qué se genera:
  - la contraseña de la base de práctica;
  - los dos secretos con que la API firma sus pases (JWT_SECRET y JWT_REFRESH_SECRET). La API se niega a arrancar con secretos cortos,
    de ejemplo o repetidos; los de acá cumplen esas mismas reglas (ver `is_valid_jwt_secret`);
  - la contraseña de la cuenta de administración de práctica (la usa la consola cuando hace de administrador);
  - `seed.json`: quién se carga en la base (la cuenta de administración y tres clientes de práctica).

No imprime ninguna credencial.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
from pathlib import Path

from common import (
    ADMIN_EMAIL, ADMIN_NAME, ADMIN_PASSWORD_FILE, API_UID, DEFAULT_SHARED_DIR, DEFAULT_STATE_DIR, SAMPLE_CUSTOMERS, SEED_FILE,
    SERVER_LOG,
)

STATE_DIR = Path(os.environ.get("DEMO_STATE_DIR", DEFAULT_STATE_DIR))
SHARED_DIR = Path(os.environ.get("DEMO_SHARED_DIR", DEFAULT_SHARED_DIR))
OWNER_UID = int(os.environ.get("DEMO_API_UID", str(API_UID)))   # quién escribe en la carpeta compartida (el usuario de la API)

# Las mismas comprobaciones que hace la API al arrancar (lib/secrets.ts): largo mínimo, que no parezca un valor de ejemplo y que tenga
# variedad de caracteres. Un valor al azar casi nunca las incumple, pero si pasara la API no arrancaría: por eso se verifican acá también.
MIN_SECRET_LENGTH = 32
PLACEHOLDER = re.compile(r"change[-_ ]?(this|me)|reemplazar|replace[-_ ]?me|your[-_ ]?secret|placeholder|example|secreto-seguro|openssl", re.IGNORECASE)
MIN_DISTINCT_CHARS = 10


def is_valid_jwt_secret(value: str) -> bool:
    return len(value) >= MIN_SECRET_LENGTH and not PLACEHOLDER.search(value) and len(set(value)) >= MIN_DISTINCT_CHARS


# -- archivos -------------------------------------------------------------------------------------------------------------

def _chown(path: Path) -> None:
    if os.geteuid() == 0:   # solo root puede cambiar el dueño (en las pruebas, que no corren como root, no hace falta)
        os.chown(path, OWNER_UID, OWNER_UID)


def write_atomic(path: Path, data: bytes, *, mode: int) -> None:
    """Escribe en un archivo temporal y lo mueve al lugar final: quien lee nunca ve un archivo a medias."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# -- credenciales ---------------------------------------------------------------------------------------------------------

def new_jwt_secret(avoid: str = "") -> str:
    while True:
        value = secrets.token_urlsafe(48)
        if is_valid_jwt_secret(value) and value != avoid:
            return value


def new_password() -> str:
    """Para la cuenta de administración. Los hashes bcrypt de la API aceptan hasta 72 bytes: 24 caracteres sobran."""
    return secrets.token_urlsafe(18)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def write_secret_if_missing(name: str, make) -> bool:
    path = STATE_DIR / name
    if read_text(path):
        return False
    # 0644: las leen la base, la API y la consola, cada una con su propio usuario, y el volumen no sale de la demo.
    write_atomic(path, (make() + "\n").encode("utf-8"), mode=0o644)
    return True


def ensure_secrets() -> bool:
    created = [
        write_secret_if_missing("postgres_password", lambda: secrets.token_hex(24)),
        write_secret_if_missing("jwt_secret", new_jwt_secret),
    ]
    # El segundo secreto tiene que ser distinto del primero (la API lo exige).
    created.append(write_secret_if_missing("jwt_refresh_secret", lambda: new_jwt_secret(avoid=read_text(STATE_DIR / "jwt_secret"))))
    created.append(write_secret_if_missing(ADMIN_PASSWORD_FILE, new_password))
    return any(created)


def write_seed() -> None:
    """Quién se carga en la base. No lleva contraseñas: las de los clientes de práctica se generan al cargarlos y se descartan."""
    seed = {
        "admin": {"email": ADMIN_EMAIL, "name": ADMIN_NAME},
        "customers": [{"email": email, "name": name} for name, email in SAMPLE_CUSTOMERS],
    }
    write_atomic(STATE_DIR / SEED_FILE, (json.dumps(seed, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), mode=0o644)


# -- carpeta compartida ---------------------------------------------------------------------------------------------------

def reset_shared() -> None:
    """La API escribe su registro acá y la consola lo lee. Cada encendido empieza limpio."""
    SHARED_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SHARED_DIR, 0o755)
    _chown(SHARED_DIR)
    (SHARED_DIR / SERVER_LOG).unlink(missing_ok=True)


def main() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o755)
    created = ensure_secrets()
    write_seed()
    reset_shared()
    print("Credenciales de la demo: " + ("generadas." if created else "ya existían, se conservan."), flush=True)
    print("Datos de práctica (administración y tres clientes): definidos.", flush=True)
    print("Registro de la API: limpio.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
