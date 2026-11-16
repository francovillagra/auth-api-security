"""Nombres y archivos que comparten `init.py`, la consola y las pruebas. Solo constantes: nada que ejecutar."""

# La tienda ficticia cuya "zona de clientes" protege la API en la demo. `.test` está reservado para pruebas (RFC 6761): no existe en internet,
# así que ningún correo de la demo puede llegar a una persona real (además, la API no envía correos).
SHOP = "Tienda Demo"
MAIL_DOMAIN = "tienda-demo.test"

ADMIN_EMAIL = f"admin@{MAIL_DOMAIN}"
ADMIN_NAME = "Administración (práctica)"
# Datos de práctica que se cargan en la base: no son personas. Nadie conoce sus contraseñas (se generan al azar y se descartan).
SAMPLE_CUSTOMERS = (
    ("Ana Demo", f"ana@{MAIL_DOMAIN}"),
    ("Luis Demo", f"luis@{MAIL_DOMAIN}"),
    ("Marta Demo", f"marta@{MAIL_DOMAIN}"),
)
# De estas cuentas, la consola usa la primera como "víctima" del ataque de contraseñas: existe y nadie conoce su clave.
TARGET_EMAIL = SAMPLE_CUSTOMERS[0][1]

DEFAULT_STATE_DIR = "/run/demo"      # credenciales y datos de práctica (solo lectura para todos menos `init`)
DEFAULT_SHARED_DIR = "/run/shared"   # lo que escribe la API y lee la consola (su registro)

SEED_FILE = "seed.json"              # quién y qué se carga en la base (lo escribe init.py; lo leen setup.mjs y la consola)
SERVER_LOG = "api.log"               # el registro de la API (lo escribe launch.mjs; lo lee la consola)
ADMIN_PASSWORD_FILE = "admin_password"
SECRET_FILES = ("postgres_password", "jwt_secret", "jwt_refresh_secret", ADMIN_PASSWORD_FILE)

DB_USER = "authapi"
DB_NAME = "authapi"
DB_HOST = "postgres"

# Usuarios sin privilegios con los que corren los servicios (ver docker-compose.yml y los Dockerfile).
API_UID = 1000       # el usuario `node` de la imagen de Node
CONSOLE_UID = 10002
