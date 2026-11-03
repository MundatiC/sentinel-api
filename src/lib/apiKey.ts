import { randomBytes } from 'node:crypto';
import { randomToken, sha256 } from './crypto.js';

// Key format: snt_<8 hex chars prefix>_<random secret>
//   - the prefix is public: it lets us find the right row and lets admins recognise a key
//   - the secret is 256 bits of randomness and is never stored, only its SHA-256 hash
const KEY_PREFIX = 'snt_';
const PREFIX_LENGTH = 8;

export const API_KEY_SCOPES = ['events:write', 'scans:write'] as const;
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];

export function generateApiKey() {
  const prefix = randomBytes(PREFIX_LENGTH / 2).toString('hex');
  const raw = `${KEY_PREFIX}${prefix}_${randomToken(32)}`;
  return { raw, prefix, hash: sha256(raw) };
}

// Returns the prefix if the string has the right shape, otherwise null.
// (Checking the shape first avoids a database query for obvious garbage.)
export function parseApiKey(raw: string): { prefix: string } | null {
  const match = /^snt_([0-9a-f]{8})_[A-Za-z0-9_-]{43}$/.exec(raw);
  return match ? { prefix: match[1]! } : null;
}
