import { z } from 'zod';

const email = z.email().max(254).trim().toLowerCase();

export const registerBody = z.strictObject({
  email,
  // Length beats complexity rules (NIST 800-63B). The max stops huge inputs from burning CPU in argon2.
  password: z.string().min(12, 'Password must be at least 12 characters').max(128),
});

export const loginBody = z.strictObject({
  email,
  password: z.string().min(1).max(128),
});

export type RegisterBody = z.infer<typeof registerBody>;
export type LoginBody = z.infer<typeof loginBody>;
