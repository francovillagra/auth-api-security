import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Auth API Security",
  description:
    "API REST de autenticación y autorización: JWT, refresh tokens rotativos y revocables, roles, rate limiting y headers de seguridad.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
