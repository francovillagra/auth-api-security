import { z } from 'zod';

/** bcrypt solo usa los primeros 72 bytes: más que eso se descartaría en silencio. */
const MAX_PASSWORD_BYTES = 72;

const email = z
  .string()
  .trim()
  .toLowerCase()
  .max(254, 'Email too long')
  .email('Invalid email format');

/** Registration payload: email, strong password, and optional display name. */
export const registerSchema = z.object({
  email,
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .refine((value) => Buffer.byteLength(value, 'utf8') <= MAX_PASSWORD_BYTES, `Password must be at most ${MAX_PASSWORD_BYTES} bytes`)
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  name: z.string().trim().min(2, 'Name must be at least 2 characters').max(100, 'Name too long').optional(),
});

export type RegisterInput = z.infer<typeof registerSchema>;

/** Login payload: email and password (no strength rules — just presence and a sane size). */
export const loginSchema = z.object({
  email,
  password: z.string().min(1, 'Password is required').max(256, 'Password too long'),
});

export type LoginInput = z.infer<typeof loginSchema>;

/** Refresh token rotation payload. */
export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required').max(2048, 'Refresh token too long'),
});

export type RefreshTokenInput = z.infer<typeof refreshTokenSchema>;
