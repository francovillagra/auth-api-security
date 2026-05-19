import type { NextConfig } from 'next';

const CORS_ORIGIN = process.env.CORS_ORIGIN ?? '*';

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

const corsHeaders = [
  { key: 'Access-Control-Allow-Origin',  value: CORS_ORIGIN },
  { key: 'Access-Control-Allow-Methods', value: 'GET, POST, PUT, DELETE, OPTIONS' },
  { key: 'Access-Control-Allow-Headers', value: 'Content-Type, Authorization' },
  { key: 'Access-Control-Max-Age',       value: '86400' },
];

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
      {
        source: '/api/(.*)',
        headers: corsHeaders,
      },
    ];
  },
};

export default nextConfig;
