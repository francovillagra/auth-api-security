"""Los ataques de la demo.

Cada ataque es una secuencia de pedidos reales a la API de práctica. El veredicto («la API lo frenó» o «no lo frenó») se calcula de las
respuestas que la API dio de verdad: nada está guionado. Por eso hay pruebas que arman una API de mentira más débil (sin freno, sin
detección de robo, sin control de roles) y comprueban que la consola lo reporta como corresponde.

Seis ataques muestran protecciones que funcionan. Dos muestran límites que el README del proyecto ya documenta («Limitaciones conocidas»):
una revisión de seguridad también dice lo que falta y cómo cerrarlo, y reproducirlo acá evita que alguien lo dé por resuelto.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from common import ADMIN_EMAIL, MAIL_DOMAIN

try:  # importado como paquete (las pruebas)
    from . import api as apimod
    from . import explain
except ImportError:  # corriendo como script dentro del contenedor
    import api as apimod
    import explain

DEFENDED = "defended"   # protecciones que funcionan
LIMIT = "limit"         # límites conocidos y documentados

# Contraseñas comunes que prueba el ataque. Nadie conoce la de la cuenta atacada, así que ninguna acierta.
GUESSES = ("123456", "password", "qwerty", "admin123", "letmein", "tienda2024", "Passw0rd!", "ana1990")
ISSUER = "auth-api-security"
OVERSIZE_BYTES = 20 * 1024


class ScenarioError(Exception):
    """La prueba no pudo completarse (la API falló o no se pudo preparar la cuenta). El mensaje se le muestra a quien usa la consola."""


@dataclass
class Attempt:
    who: str          # quién hace el pedido
    what: str         # qué hace, en palabras de cliente
    status: int       # lo que contestó la API
    ok: bool          # ¿es lo que debería contestar una API segura?
    note: str = ""

    def to_json(self) -> dict:
        return {
            "who": self.who, "what": self.what, "status": self.status, "label": explain.status_label(self.status),
            "ok": self.ok, "note": self.note,
        }


@dataclass
class Outcome:
    held: bool          # la protección funcionó
    headline: str
    attempts: list[Attempt]
    lesson: str
    watch: str = ""     # qué mirar en el registro de la API
    limit: str = ""     # límites de lo que se acaba de ver

    def to_json(self) -> dict:
        return {
            "held": self.held, "headline": self.headline, "attempts": [a.to_json() for a in self.attempts],
            "lesson": self.lesson, "watch": self.watch, "limit": self.limit,
        }


@dataclass
class Account:
    email: str
    password: str
    user_id: str
    access: str
    refresh: str


class Lab:
    """Lo que un ataque necesita: la API, las direcciones de práctica, la cuenta de administración y la cuenta que se ataca."""

    def __init__(self, api: apimod.Api, origins: apimod.Origins, admin: apimod.AdminSession, target_email: str) -> None:
        self.api, self.origins, self.admin, self.target_email = api, origins, admin, target_email

    def call(self, method: str, path: str, **kwargs: Any) -> apimod.Reply:
        reply = self.api.request(method, path, **kwargs)
        self._check(reply)
        return reply

    def admin_call(self, method: str, path: str, body: Any = None) -> apimod.Reply:
        try:
            reply = self.admin.request(method, path, body=body)
        except apimod.AdminUnavailable as exc:
            raise ScenarioError(str(exc)) from None
        self._check(reply)
        return reply

    @staticmethod
    def _check(reply: apimod.Reply) -> None:
        if reply.status >= 500:
            raise ScenarioError(f"La API respondió un error ({reply.status}) y la prueba no se pudo completar. El detalle está en su registro.")

    def register(self, ip: str, *, name: str = "Cliente de práctica") -> Account:
        """Una cuenta descartable para la prueba (la API la crea y la deja con una sesión abierta)."""
        email = f"prueba-{secrets.token_hex(4)}@{MAIL_DOMAIN}"
        password = "Aa1-" + secrets.token_urlsafe(12)
        reply = self.call("POST", "/api/auth/register", body={"email": email, "password": password, "name": name}, ip=ip)
        user, access, refresh = reply.get("user"), reply.get("accessToken"), reply.get("refreshToken")
        if reply.status == 429:
            raise ScenarioError("La API está limitando los pedidos. Esperar unos segundos y repetir la prueba.")
        if reply.status != 201 or not (isinstance(user, dict) and isinstance(user.get("id"), str) and isinstance(access, str) and isinstance(refresh, str)):
            raise ScenarioError(f"No se pudo preparar una cuenta de práctica para la prueba (la API respondió {reply.status}).")
        return Account(email, password, user["id"], access, refresh)


# -- 1. contraseñas a los golpes ----------------------------------------------------------------------------------------------

def _guess_note(reply: apimod.Reply, number: int) -> str:
    if reply.status == 429:
        wait = reply.retry_after
        return "La API ni mira la contraseña: ya se pasó el máximo de intentos." + (f" Podría volver a intentar en {wait} s." if wait else "")
    if reply.status == 200:
        return "Entró: la contraseña era correcta."
    return ""


def bruteforce(lab: Lab) -> Outcome:
    ip = lab.origins.attacker()
    attempts: list[Attempt] = []
    blocked_at: Optional[int] = None
    guessed = False
    for number, password in enumerate(GUESSES, start=1):
        reply = lab.call("POST", "/api/auth/login", body={"email": lab.target_email, "password": password}, ip=ip)
        if reply.status == 429 and blocked_at is None:
            blocked_at = number
        guessed = guessed or reply.status == 200
        # Lo esperable: los primeros intentos se rechazan por clave incorrecta y, pasado el máximo, la API frena.
        expected = reply.status == 429 or (reply.status == 401 and number <= explain.RATE_LIMIT_REQUESTS)
        attempts.append(Attempt("Atacante", f"Prueba la contraseña «{password}»", reply.status, expected, _guess_note(reply, number)))
    held = blocked_at is not None and not guessed
    return Outcome(
        held=held,
        headline=(
            f"La API frenó al atacante a partir del intento {blocked_at}."
            if held else f"La API no frenó al atacante: probó {len(GUESSES)} contraseñas sin que nada lo detuviera."
        ),
        attempts=attempts,
        lesson=(
            f"Cada intento de ingreso cuenta. Pasados {explain.RATE_LIMIT_REQUESTS} en {explain.RATE_LIMIT_SECONDS} segundos desde la misma "
            "dirección, la API deja de procesarlos y responde «demasiados pedidos». Un programa que prueba miles de contraseñas por minuto "
            f"queda reducido a {explain.RATE_LIMIT_REQUESTS} cada {explain.RATE_LIMIT_SECONDS} segundos."
        ),
        watch="En el registro de la API, los pedidos frenados quedan marcados como alerta.",
        limit="El freno cuenta por dirección de internet, no por cuenta: quien controla muchas conexiones lo esquiva (ver la parte 3).",
    )


# -- 2. robo de sesión ----------------------------------------------------------------------------------------------------------

def stolen_session(lab: Lab) -> Outcome:
    owner_ip, thief_ip = lab.origins.visitor(), lab.origins.attacker()
    owner = lab.register(owner_ip, name="Titular de la cuenta")
    attempts = [Attempt("Titular", "Crea su cuenta y entra a la tienda (la API le da su llave de renovación)", 201, True)]

    # El atacante se queda con una copia de la llave de renovación (por ejemplo, de un celular infectado).
    copied = owner.refresh

    renew = lab.call("POST", "/api/auth/refresh", body={"refreshToken": owner.refresh}, ip=owner_ip)
    renewed = renew.get("refreshToken")
    if renew.status != 200 or not isinstance(renewed, str):
        raise ScenarioError(f"No se pudo preparar la prueba: la API no renovó la sesión del titular (respondió {renew.status}).")
    attempts.append(Attempt("Titular", "Renueva su sesión con normalidad (la llave anterior se cambia por una nueva)", renew.status, True))

    stolen = lab.call("POST", "/api/auth/refresh", body={"refreshToken": copied}, ip=thief_ip)
    attempts.append(Attempt(
        "Atacante", "Usa la copia de la llave que se llevó", stolen.status, stolen.status == 401,
        "Esa llave ya se había usado: la API sospecha que alguien la copió." if stolen.status == 401 else "",
    ))

    after = lab.call("POST", "/api/auth/refresh", body={"refreshToken": renewed}, ip=owner_ip)
    attempts.append(Attempt(
        "Titular", "Intenta renovar con su llave nueva", after.status, after.status == 401,
        "La sesión entera quedó cerrada, también para el titular: no hay forma de saber quién es quién, así que se corta todo."
        if after.status == 401 else "La sesión siguió abierta.",
    ))

    again = lab.call("POST", "/api/auth/login", body={"email": owner.email, "password": owner.password}, ip=owner_ip)
    attempts.append(Attempt(
        "Titular", "Vuelve a entrar con su contraseña", again.status, again.status == 200,
        "Sesión nueva: el atacante no tiene ninguna llave que sirva." if again.status == 200 else "",
    ))

    held = stolen.status == 401 and after.status == 401
    if held:
        headline = "La API detectó la copia y cerró la sesión completa: el atacante quedó afuera."
    elif stolen.status != 401:
        headline = "La API aceptó la llave robada."
    else:
        headline = "La API rechazó la copia, pero dejó abierta la sesión: no detecta el robo."
    return Outcome(
        held=held, headline=headline, attempts=attempts,
        lesson=(
            f"Las llaves de renovación (duran {explain.REFRESH_TOKEN_DAYS} días) se usan una sola vez: cada renovación entrega una nueva y "
            "anula la anterior. Si alguien presenta una que ya se usó, la API entiende que hay una copia circulando y cierra la sesión "
            "completa. El titular tiene que volver a entrar, pero el atacante no se queda con nada."
        ),
        watch="Buscar en el registro de la API la alerta «Refresh token reuse detected».",
        limit="La llave de acceso ya emitida (15 minutos) sigue valiendo hasta que venza: ver la parte 3.",
    )


# -- 3. llaves falsas -------------------------------------------------------------------------------------------------------------

def forged_token(lab: Lab) -> Outcome:
    victim = lab.register(lab.origins.visitor())   # su llave verdadera sirve para el último intento
    ip = lab.origins.attacker()
    now = int(time.time())
    admin_claims = {
        "userId": victim.user_id, "email": ADMIN_EMAIL, "role": "ADMIN", "sub": victim.user_id, "iss": ISSUER,
        "aud": f"{ISSUER}:access", "iat": now, "exp": now + 900,
    }
    tries: list[tuple[str, Optional[str]]] = [
        ("Se presenta sin ninguna llave", None),
        ("Llave sin firma: declara el algoritmo «none» y dice ser administrador", apimod.forge(admin_claims, None, "none")),
        ("Llave firmada con una clave adivinada («secret»)", apimod.forge(admin_claims, "secret")),
        ("Llave firmada con otra clave adivinada («auth-api-security»)", apimod.forge(admin_claims, ISSUER)),
        ("Llave verdadera de un cliente, con el rol editado a «ADMIN»", apimod.tamper(victim.access, role="ADMIN")),
    ]
    attempts = []
    for what, token in tries:
        reply = lab.call("GET", "/api/admin/users", token=token, ip=ip)
        attempts.append(Attempt(
            "Atacante", what, reply.status, reply.status == 401,
            "¡La API le dio acceso a la lista de cuentas!" if reply.status == 200 else "",
        ))
    held = all(a.status == 401 for a in attempts)
    return Outcome(
        held=held,
        headline=(
            "La API rechazó las cinco llaves: ninguna llevaba su firma."
            if held else "La API aceptó una llave falsa: cualquiera podría hacerse pasar por administrador."
        ),
        attempts=attempts,
        lesson=(
            "Cada llave que entrega la API lleva una firma hecha con un secreto que solo ella conoce. Quien no lo tiene no puede fabricar una "
            "llave nueva, ni editar los datos de una verdadera sin romper la firma. La API además fija el único algoritmo que acepta, así que "
            "tampoco sirve declarar que la llave «no necesita firma»."
        ),
        watch="Estos pedidos fallan antes de tocar la base de datos.",
        limit="La seguridad de las llaves depende de que el secreto sea largo y se mantenga en reserva (la API se niega a arrancar con uno corto o de ejemplo).",
    )


# -- 4. un cliente quiere ser administrador ---------------------------------------------------------------------------------------

def privilege_escalation(lab: Lab) -> Outcome:
    customer = lab.register(lab.origins.visitor())
    ip = lab.origins.attacker()
    attempts = []

    listing = lab.call("GET", "/api/admin/users", token=customer.access, ip=ip)
    attempts.append(Attempt(
        "Cliente", "Pide el listado de todas las cuentas", listing.status, listing.status == 403,
        "La API sabe quién es, pero su rol no alcanza." if listing.status == 403 else "",
    ))

    promote = lab.call("PATCH", f"/api/admin/users/{customer.user_id}/role", body={"role": "ADMIN"}, token=customer.access, ip=ip)
    attempts.append(Attempt(
        "Cliente", "Se da a sí mismo el rol de administración", promote.status, promote.status == 403,
        "No puede ascenderse solo." if promote.status == 403 else "",
    ))

    profile = lab.call("GET", "/api/users/me", token=customer.access, ip=ip)
    user = profile.get("user")
    still_customer = profile.status == 200 and isinstance(user, dict) and user.get("role") == "USER"
    attempts.append(Attempt(
        "Cliente", "Mira su perfil para ver si cambió algo", profile.status, still_customer,
        "Sigue siendo cliente: los intentos no cambiaron nada." if still_customer else "Su rol cambió.",
    ))

    admin_list = lab.admin_call("GET", "/api/admin/users")
    users = admin_list.get("users")
    users = users if isinstance(users, list) else []
    leaked = any(isinstance(u, dict) and "password" in u for u in users)
    admin_ok = admin_list.status == 200 and not leaked
    attempts.append(Attempt(
        "Administración", "Pide el mismo listado", admin_list.status, admin_ok,
        f"Ve {len(users)} cuentas, y en ninguna aparece la contraseña." if admin_ok else ("Aparecen contraseñas en el listado." if leaked else ""),
    ))

    held = all(a.ok for a in attempts)
    return Outcome(
        held=held,
        headline=(
            "La API le cerró la puerta al cliente y se la abrió a la administración."
            if held else "La API dejó pasar a alguien sin el rol de administración."
        ),
        attempts=attempts,
        lesson=(
            "Tener una cuenta no alcanza para ver todo. La API distingue entre «no se sabe quién llama» (401) y «se sabe quién es, pero no tiene "
            "permiso» (403), y solo la administración llega al listado. Aun con una llave válida, un cliente no puede cambiarse el rol a sí mismo."
        ),
        watch="Los pedidos rechazados también quedan en el registro, con el estado 403.",
    )


# -- 5. el rol se respeta al instante -----------------------------------------------------------------------------------------------

def revoked_role(lab: Lab) -> Outcome:
    employee = lab.register(lab.origins.visitor(), name="Empleado de práctica")
    ip = lab.origins.attacker()
    attempts = []

    before = lab.call("GET", "/api/admin/users", token=employee.access, ip=ip)
    attempts.append(Attempt("Empleado", "Pide el listado de cuentas (todavía es cliente)", before.status, before.status == 403))

    promote = lab.admin_call("PATCH", f"/api/admin/users/{employee.user_id}/role", body={"role": "ADMIN"})
    if promote.status != 200:
        raise ScenarioError(f"No se pudo preparar la prueba: la administración no logró cambiar el rol (respondió {promote.status}).")
    attempts.append(Attempt("Administración", "Le da el cargo de administración", promote.status, True))

    try:
        during = lab.call("GET", "/api/admin/users", token=employee.access, ip=ip)
        attempts.append(Attempt(
            "Empleado", "Pide el listado con la misma llave de antes", during.status, during.status == 200,
            "Funciona al instante: la API consulta el rol actual en cada pedido." if during.status == 200 else "",
        ))
    finally:
        demote = lab.admin_call("PATCH", f"/api/admin/users/{employee.user_id}/role", body={"role": "USER"})   # siempre vuelve a cliente
    attempts.append(Attempt("Administración", "Le quita el cargo", demote.status, demote.status == 200))

    after = lab.call("GET", "/api/admin/users", token=employee.access, ip=ip)
    attempts.append(Attempt(
        "Empleado", "Pide el listado otra vez, con la misma llave", after.status, after.status == 403,
        "Pierde el acceso en el mismo momento, sin esperar a que venza su llave." if after.status == 403 else "Siguió teniendo acceso.",
    ))

    held = before.status == 403 and during.status == 200 and demote.status == 200 and after.status == 403
    return Outcome(
        held=held,
        headline=(
            "Dar o quitar el cargo surte efecto en el mismo instante."
            if held else "El cambio de rol no se aplicó al instante: la persona conservó (o no recibió) el acceso con su llave anterior."
        ),
        attempts=attempts,
        lesson=(
            "La llave lleva escrito un rol, pero la API no se fía de él: en cada pedido lee el rol actual de la base de datos. Si una persona "
            "deja la empresa o cambia de puesto, quitarle el rol corta su acceso ya, sin esperar a que venza su sesión."
        ),
        watch="Cada cambio de rol queda registrado con quién lo hizo y de qué rol a cuál.",
    )


# -- 6. datos mal armados ------------------------------------------------------------------------------------------------------------

def bad_input(lab: Lab) -> Outcome:
    ip = lab.origins.attacker()
    oversize = b'{"email":"ana@' + MAIL_DOMAIN.encode() + b'","password":"' + b"A" * OVERSIZE_BYTES + b'"}'
    tries: list[tuple[str, dict, int, str]] = [
        ("Un correo con forma de ataque a la base de datos: «' OR 1=1 --»", {"body": {"email": "' OR 1=1 --", "password": "x"}}, 400,
         "No es un correo válido: el pedido se corta antes de llegar a la base de datos."),
        ("Un texto roto que no es JSON", {"raw": b'{"email": "ana@'}, 400, "La API no entiende el pedido y lo rechaza."),
        (f"Un envío de {OVERSIZE_BYTES // 1024} KB (el máximo es 8 KB)", {"raw": oversize}, 413,
         "Se rechaza por el tamaño declarado, sin leer el contenido."),
        ("Un formato que la API no espera (texto plano en vez de JSON)", {"raw": b"email=ana&password=x", "content_type": "text/plain"}, 415,
         "Solo se aceptan pedidos en JSON."),
    ]
    attempts = []
    for what, kwargs, expected, note in tries:
        reply = lab.call("POST", "/api/auth/login", ip=ip, **kwargs)
        attempts.append(Attempt("Atacante", what, reply.status, reply.status == expected, note if reply.status == expected else ""))
    held = all(a.ok for a in attempts)
    return Outcome(
        held=held,
        headline=(
            "La API rechazó los cuatro pedidos con un error claro, sin procesarlos."
            if held else "La API procesó algún pedido que debió rechazar."
        ),
        attempts=attempts,
        lesson=(
            "Todo lo que llega se valida antes de usarse: la forma del correo, que el texto sea JSON, el tamaño del envío y el formato. "
            "Los pedidos inválidos reciben un error preciso y no consumen recursos de la base de datos."
        ),
        watch="La base de datos solo se consulta con pedidos que ya pasaron la validación.",
    )


# -- 7. (límite) esquivar el freno cambiando de dirección ------------------------------------------------------------------------------

def spoof_ip(lab: Lab) -> Outcome:
    attempts: list[Attempt] = []
    guessed = False
    for number, password in enumerate(GUESSES, start=1):
        reply = lab.call("POST", "/api/auth/login", body={"email": lab.target_email, "password": password}, ip=lab.origins.spread())
        guessed = guessed or reply.status == 200
        expected = reply.status == 429 or (reply.status == 401 and number <= explain.RATE_LIMIT_REQUESTS)
        note = ""
        if reply.status == 401 and number > explain.RATE_LIMIT_REQUESTS:
            note = "Debió frenarse: la API cree que viene de otra dirección."
        elif reply.status == 200:
            note = "Entró: la contraseña era correcta."
        attempts.append(Attempt("Atacante", f"Prueba «{password}», declarando una dirección distinta", reply.status, expected, note))
    held = any(a.status == 429 for a in attempts) and not guessed
    return Outcome(
        held=held,
        headline=(
            "La API frenó al atacante aunque cambiara de dirección."
            if held else f"El freno no actuó: {len(GUESSES)} intentos seguidos contra la misma cuenta, ninguno frenado."
        ),
        attempts=attempts,
        lesson=(
            "El freno cuenta los intentos por la dirección de internet que declara quien llama. En Vercel esa dirección la fija la plataforma "
            "y no se puede falsificar; si el servicio queda accesible directamente, quien llega puede inventarla. Además el límite es por "
            "dirección y no por cuenta: con muchas conexiones se puede atacar una sola cuenta sin pasar el tope."
            if not held else "El freno sigue actuando aunque cada intento declare una dirección distinta."
        ),
        watch="En el registro no aparece ninguna alerta: para la API, cada intento viene de alguien nuevo.",
        limit=(
            "Cómo se corrige: publicar la API solo detrás de la plataforma o de un proxy que fije la dirección, y sumar un contador de "
            "intentos fallidos por cuenta. Está en «Limitaciones conocidas» del README."
            if not held else ""
        ),
    )


# -- 8. (límite) la llave de acceso sobrevive al cierre de sesión ------------------------------------------------------------------------

def logout_token(lab: Lab) -> Outcome:
    client_ip, thief_ip = lab.origins.visitor(), lab.origins.attacker()
    client = lab.register(client_ip)
    attempts = []

    out = lab.call("POST", "/api/auth/logout", body={"refreshToken": client.refresh}, ip=client_ip)
    attempts.append(Attempt("Cliente", "Cierra sesión", out.status, out.status == 204))

    renew = lab.call("POST", "/api/auth/refresh", body={"refreshToken": client.refresh}, ip=thief_ip)
    attempts.append(Attempt(
        "Atacante", "Intenta renovar la sesión con la llave de renovación que había copiado", renew.status, renew.status == 401,
        "La renovación quedó cortada." if renew.status == 401 else "",
    ))

    use = lab.call("GET", "/api/users/me", token=client.access, ip=thief_ip)
    attempts.append(Attempt(
        "Atacante", "Usa la llave de acceso que había copiado", use.status, use.status == 401,
        "Siguió funcionando: la llave de acceso no se anula al cerrar sesión, solo vence a los 15 minutos." if use.status == 200 else "",
    ))
    held = use.status == 401
    return Outcome(
        held=held,
        headline=(
            "Cerrar sesión cortó también la llave de acceso."
            if held else "Cerrar sesión cortó la renovación, pero la llave de acceso ya emitida siguió funcionando."
        ),
        attempts=attempts,
        lesson=(
            f"La llave de acceso dura {explain.ACCESS_TOKEN_MINUTES} minutos y la API no la consulta en la base en cada pedido; por eso, "
            "hasta que venza, sigue valiendo. Es una decisión de diseño documentada: anularla al instante exige consultar la base en cada "
            "pedido o llevar una lista de llaves revocadas."
            if not held else "La API consulta si la llave fue anulada en cada pedido."
        ),
        watch="La ventana de riesgo es corta (15 minutos) y el atacante no puede renovar la sesión.",
        limit=(
            "Cómo se reduce: acortar la vida de la llave de acceso o sumar la lista de llaves revocadas. Está en «Limitaciones conocidas» del README."
            if not held else ""
        ),
    )


# -- catálogo -----------------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    id: str
    group: str
    title: str
    what: str
    expected_held: bool    # lo que debe dar con la API del proyecto tal como está (lo comprueba la prueba de humo)
    run: Callable[[Lab], Outcome]


SCENARIO_LIST: tuple[Scenario, ...] = (
    Scenario(
        "bruteforce", DEFENDED, "Adivinar una contraseña a los golpes",
        "Un programa prueba contraseñas comunes, una tras otra, contra la cuenta de Ana. Es el ataque más común contra cualquier pantalla de ingreso.",
        True, bruteforce,
    ),
    Scenario(
        "stolen-session", DEFENDED, "Robar una sesión y usarla después",
        "Alguien copia la llave de renovación de un cliente (por ejemplo, desde un celular infectado) y la usa después de que el dueño ya renovó su sesión.",
        True, stolen_session,
    ),
    Scenario(
        "forged-token", DEFENDED, "Fabricar una llave de administrador",
        "El atacante no tiene cuenta. Arma llaves falsas que dicen «soy administrador»: sin firma, con una clave adivinada o editando una llave verdadera.",
        True, forged_token,
    ),
    Scenario(
        "privilege-escalation", DEFENDED, "Un cliente intenta entrar al panel de administración",
        "Un cliente con una cuenta legítima prueba ver el listado de todas las cuentas y darse a sí mismo el rol de administración.",
        True, privilege_escalation,
    ),
    Scenario(
        "revoked-role", DEFENDED, "Cambiar el rol de una persona en pleno uso",
        "A un empleado se le da y se le quita el cargo de administración mientras su sesión sigue abierta, para ver si la API respeta el cambio al instante.",
        True, revoked_role,
    ),
    Scenario(
        "bad-input", DEFENDED, "Mandar datos mal armados o enormes",
        "Un correo con forma de ataque a la base de datos, un texto roto, un envío de 20 KB y un formato que la API no espera.",
        True, bad_input,
    ),
    Scenario(
        "spoof-ip", LIMIT, "Cambiar de dirección para esquivar el freno",
        "El mismo ataque de contraseñas, pero cada intento declara una dirección de internet distinta, como haría quien controla muchas conexiones.",
        False, spoof_ip,
    ),
    Scenario(
        "logout-token", LIMIT, "Seguir usando la llave de acceso después de cerrar sesión",
        "Un cliente cierra sesión y alguien que había copiado su llave de acceso la usa un momento después.",
        False, logout_token,
    ),
)

SCENARIOS: dict[str, Scenario] = {scenario.id: scenario for scenario in SCENARIO_LIST}
CATALOG: list[dict] = [{"id": s.id, "group": s.group, "title": s.title, "what": s.what} for s in SCENARIO_LIST]
