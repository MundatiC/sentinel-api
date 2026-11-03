import argon2 from 'argon2';

// argon2id: memory-hard, so attackers cannot cheaply crack hashes on GPUs.
// The library's defaults (64 MiB, 3 passes) are stronger than OWASP's minimum.
export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, { type: argon2.argon2id });
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false; // malformed hash: treat as "does not match", never crash
  }
}

// When a login uses an unknown email we still verify against this hash. Otherwise
// "unknown email" would answer instantly while "wrong password" takes ~50 ms, and an
// attacker could use that timing difference to discover which emails have accounts.
let dummyHash: Promise<string> | undefined;
export function getDummyHash(): Promise<string> {
  dummyHash ??= hashPassword('not-a-real-password-just-for-timing');
  return dummyHash;
}
