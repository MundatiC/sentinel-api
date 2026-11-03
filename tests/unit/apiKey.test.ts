import { describe, expect, it } from 'vitest';
import { generateApiKey, parseApiKey } from '../../src/lib/apiKey.js';
import { sha256 } from '../../src/lib/crypto.js';

describe('API key helpers', () => {
  it('generates a well-formed key whose hash matches', () => {
    const { raw, prefix, hash } = generateApiKey();
    expect(raw).toMatch(/^snt_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$/);
    expect(parseApiKey(raw)).toEqual({ prefix });
    expect(hash).toBe(sha256(raw));
  });

  it('generates unique keys', () => {
    expect(generateApiKey().raw).not.toBe(generateApiKey().raw);
  });

  it.each([
    '',
    'snt_',
    'snt_12345678_short',
    'xxx_12345678_' + 'a'.repeat(43),
    'snt_ZZZZZZZZ_' + 'a'.repeat(43),
  ])('rejects malformed key %j', (bad) => {
    expect(parseApiKey(bad)).toBeNull();
  });
});
