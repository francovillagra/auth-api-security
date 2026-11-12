"""Traduce lo que contesta la API a palabras de cliente. Sin lógica de negocio: solo textos."""
from __future__ import annotations

# Lo que la API limita, tal como figura en su código (proxy.ts y lib/auth.ts). Hay una prueba que lo compara con esos archivos: si la
# API cambia, la demo no puede seguir diciendo otra cosa.
RATE_LIMIT_REQUESTS = 5
RATE_LIMIT_SECONDS = 10
ACCESS_TOKEN_MINUTES = 15
REFRESH_TOKEN_DAYS = 7

STATUS_LABELS = {
    200: "Aceptado",
    201: "Aceptado",
    204: "Aceptado",
    400: "Datos inválidos",
    401: "Sin identificación válida",
    403: "Sin permiso",
    404: "No existe",
    409: "Ya existe",
    413: "Demasiado grande",
    415: "Formato no admitido",
    429: "Frenado por exceso de pedidos",
}

ROLE_LABELS = {"USER": "cliente", "ADMIN": "administración"}


def status_label(status: int) -> str:
    if status in STATUS_LABELS:
        return STATUS_LABELS[status]
    return "Error de la API" if status >= 500 else "Respuesta inesperada"


def role_label(role: object) -> str:
    return ROLE_LABELS.get(str(role), str(role))


def plural(count: int, one: str, many: str) -> str:
    return one if count == 1 else many
