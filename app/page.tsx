const REPO_URL = "https://github.com/francovillagra/auth-api-security";

const endpoints = [
  { method: "POST", path: "/api/auth/register", access: "Público", does: "Crea la cuenta y abre una sesión (access y refresh token)." },
  { method: "POST", path: "/api/auth/login", access: "Público", does: "Inicia sesión. Mismo mensaje y mismo tiempo si el email no existe." },
  { method: "POST", path: "/api/auth/refresh", access: "Refresh token", does: "Canjea el refresh token por un par nuevo. Cada refresh token sirve una sola vez." },
  { method: "POST", path: "/api/auth/logout", access: "Refresh token", does: "Cierra la sesión; con everywhere: true, todas las del usuario." },
  { method: "GET", path: "/api/users/me", access: "Access token", does: "Perfil del usuario autenticado." },
  { method: "GET", path: "/api/admin/users", access: "ADMIN", does: "Lista los usuarios (sin contraseñas)." },
  { method: "PATCH", path: "/api/admin/users/:id/role", access: "ADMIN", does: "Cambia el rol de un usuario." },
];

const guarantees = [
  "Access token de 15 minutos, refresh token de 7 días y sesiones de 30 días como máximo.",
  "Refresh tokens rotativos: cada uno se canjea una vez y reutilizar uno ya canjeado cierra la sesión entera.",
  "Contraseñas con bcrypt; el login no revela si un email existe (ni por el mensaje ni por el tiempo).",
  "Los roles se leen de la base en cada pedido: un admin degradado pierde el acceso al instante.",
  "Rate limiting de 5 pedidos cada 10 segundos por IP sobre /api/auth/*.",
  "Cuerpos JSON de hasta 8 KB, validados con Zod; headers de seguridad y respuestas sin caché.",
];

const example = `BASE=https://TU-DOMINIO   # la URL de este sitio

# 1. Crear la cuenta (devuelve accessToken y refreshToken)
curl -s -X POST $BASE/api/auth/register \\
  -H 'Content-Type: application/json' \\
  -d '{"email":"vos@ejemplo.com","password":"UnaClave123"}'

# 2. Ver tu perfil con el access token
curl -s $BASE/api/users/me -H "Authorization: Bearer $ACCESS"

# 3. Renovar: el refresh token viejo deja de servir
curl -s -X POST $BASE/api/auth/refresh \\
  -H 'Content-Type: application/json' \\
  -d "{\\"refreshToken\\":\\"$REFRESH\\"}"

# 4. Cerrar la sesión
curl -s -X POST $BASE/api/auth/logout \\
  -H 'Content-Type: application/json' \\
  -d "{\\"refreshToken\\":\\"$REFRESH\\"}"`;

export default function Home() {
  return (
    <main className="mx-auto w-full max-w-3xl px-4 py-12 sm:px-6 sm:py-16">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">Auth API Security</h1>
        <p className="mt-3 text-lg leading-8 text-muted">
          API REST de autenticación y autorización construida con Next.js, TypeScript y Prisma. Es una API: no tiene pantalla de
          login. Todo se usa con <code className="font-mono text-base">curl</code> o desde tu propio frontend.
        </p>
        <p className="mt-4">
          <a className="font-medium text-accent underline underline-offset-4" href={REPO_URL}>
            Código, tests y documentación en GitHub
          </a>
        </p>
      </header>

      <section className="mt-12" aria-labelledby="endpoints">
        <h2 id="endpoints" className="text-xl font-semibold">
          Endpoints
        </h2>
        {/* En pantallas chicas la tabla de cuatro columnas no entra: se muestra como lista. */}
        <ul className="mt-4 divide-y divide-border rounded-lg border border-border sm:hidden">
          {endpoints.map((endpoint) => (
            <li key={`${endpoint.method} ${endpoint.path}`} className="px-3 py-3">
              <p className="break-all font-mono text-sm">
                <span className="font-semibold">{endpoint.method}</span> {endpoint.path}
              </p>
              <p className="mt-1 text-sm">
                <span className="text-muted">Acceso:</span> {endpoint.access}
              </p>
              <p className="mt-1 text-sm text-muted">{endpoint.does}</p>
            </li>
          ))}
        </ul>
        <div className="mt-4 hidden overflow-x-auto rounded-lg border border-border sm:block">
          <table className="w-full border-collapse text-left text-sm">
            <thead className="bg-surface">
              <tr>
                <th scope="col" className="px-3 py-2 font-semibold">Método</th>
                <th scope="col" className="px-3 py-2 font-semibold">Ruta</th>
                <th scope="col" className="px-3 py-2 font-semibold">Acceso</th>
                <th scope="col" className="px-3 py-2 font-semibold">Qué hace</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((endpoint) => (
                <tr key={`${endpoint.method} ${endpoint.path}`} className="border-t border-border align-top">
                  <td className="px-3 py-2 font-mono">{endpoint.method}</td>
                  <td className="px-3 py-2 font-mono">{endpoint.path}</td>
                  <td className="px-3 py-2">{endpoint.access}</td>
                  <td className="px-3 py-2 text-muted">{endpoint.does}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-12" aria-labelledby="probar">
        <h2 id="probar" className="text-xl font-semibold">
          Probala en cuatro pasos
        </h2>
        <pre className="mt-4 overflow-x-auto rounded-lg border border-border bg-surface p-4 text-sm leading-6">
          <code className="font-mono">{example}</code>
        </pre>
      </section>

      <section className="mt-12" aria-labelledby="garantias">
        <h2 id="garantias" className="text-xl font-semibold">
          Qué garantiza
        </h2>
        <ul className="mt-4 list-disc space-y-2 pl-5 leading-7">
          {guarantees.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        <p className="mt-4 text-muted">
          Lo que todavía no hace (verificación de email, reset de contraseña, 2FA, límite de intentos por cuenta) está listado
          en la sección «Limitaciones conocidas» del{" "}
          <a className="text-accent underline underline-offset-4" href={`${REPO_URL}#limitaciones-conocidas`}>
            README
          </a>
          .
        </p>
      </section>
    </main>
  );
}
