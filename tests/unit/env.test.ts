import { describe, expect, it } from 'vitest';
import { parseEnv } from '../../src/config/env.js';

const base = {
  DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
  JWT_ACCESS_SECRET: 'x'.repeat(32),
};

describe('parseEnv', () => {
  it('applies defaults', () => {
    const env = parseEnv(base);
    expect(env.PORT).toBe(4000);
    expect(env.NODE_ENV).toBe('development');
    expect(env.CORS_ORIGINS).toEqual(['http://localhost:3000']);
  });

  it('splits and trims CORS origins', () => {
    const env = parseEnv({ ...base, CORS_ORIGINS: ' https://a.com , https://b.com ' });
    expect(env.CORS_ORIGINS).toEqual(['https://a.com', 'https://b.com']);
  });

  it('rejects a wildcard CORS origin', () => {
    expect(() => parseEnv({ ...base, CORS_ORIGINS: '*' })).toThrow(/CORS_ORIGINS/);
  });

  it('fails fast when a required variable is missing', () => {
    expect(() => parseEnv({})).toThrow(/DATABASE_URL/);
  });

  it('rejects a short JWT secret', () => {
    expect(() => parseEnv({ ...base, JWT_ACCESS_SECRET: 'too-short' })).toThrow(
      /JWT_ACCESS_SECRET/,
    );
  });

  it('keeps registration disabled by default', () => {
    expect(parseEnv(base).ALLOW_REGISTRATION).toBe(false);
  });

  it('uses secure cookies in production only by default', () => {
    expect(parseEnv({ ...base, NODE_ENV: 'production' }).cookieSecure).toBe(true);
    expect(parseEnv({ ...base, NODE_ENV: 'development' }).cookieSecure).toBe(false);
  });

  it('requires a long PROXY_SHARED_SECRET when one is given, and allows none', () => {
    expect(parseEnv(base).PROXY_SHARED_SECRET).toBeUndefined();
    expect(() => parseEnv({ ...base, PROXY_SHARED_SECRET: 'short' })).toThrow(
      /PROXY_SHARED_SECRET/,
    );
    expect(parseEnv({ ...base, PROXY_SHARED_SECRET: 'z'.repeat(32) }).PROXY_SHARED_SECRET).toBe(
      'z'.repeat(32),
    );
  });

  it('rejects an out-of-range port', () => {
    expect(() => parseEnv({ ...base, PORT: '99999' })).toThrow(/PORT/);
  });
});
