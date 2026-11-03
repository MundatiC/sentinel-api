import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

// Random, URL-safe secret with `bytes` bytes of entropy (32 bytes = 256 bits).
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

// SHA-256 is the right tool for hashing HIGH-ENTROPY random tokens (refresh tokens, API keys).
// It would be the wrong tool for passwords (humans pick guessable ones) - those use argon2.
export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

// Compare two hex hashes in constant time so response timing cannot leak how many
// leading characters matched.
export function safeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}
