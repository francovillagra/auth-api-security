import type { NextConfig } from 'next';

// Security headers equivalent to Helmet defaults
const securityHeaders = [
  { key: 'X-DNS-Prefetch-Control',     value: 'off' },
  { key: 'X-Frame-Options',            value: 'DENY' },
  { key: 'X-Content-Type-Options',     value: 'nosniff' },
  // Disable legacy XSS auditor — CSP covers this in modern browsers
  { key: 'X-XSS-Protection',           value: '0' },
  { key: 'Referrer-Policy',            value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy',         value: 'camera=(), microphone=(), geolocation=()' },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
    ].join('; '),
  },
];

// La API devuelve solo JSON: no necesita cargar nada. Y las respuestas con tokens
// nunca deben quedar en cachés (RFC 6749 §5.1).
const apiHeaders = [
  { key: 'Cache-Control', value: 'no-store' },
  {
    key: 'Content-Security-Policy',
    value: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  },
];

// CORS se resuelve en proxy.ts (lista explícita de orígenes en CORS_ORIGIN).
const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
      {
        // Va después de la regla general: para la misma clave gana la última.
        source: '/api/(.*)',
        headers: apiHeaders,
      },
    ];
  },
};

export default nextConfig;
