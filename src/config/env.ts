import { z } from 'zod';

// All configuration comes from environment variables and is validated ONCE at startup.
// If anything is missing or malformed the process exits with a clear message instead of
// failing later in a confusing way (fail fast).
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  CORS_ORIGINS: z
    .string()
    .default('http://localhost:3000')
    .transform((value) =>
      value
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean),
    )
    .refine((origins) => !origins.includes('*'), {
      message: 'CORS_ORIGINS must list explicit origins; "*" is not allowed with credentials',
    }),
  TRUST_PROXY: z.coerce.number().int().min(0).default(0),
  // Shared with the dashboard's proxy (see src/middleware/verifiedProxyIp.ts). Unset = feature off.
  PROXY_SHARED_SECRET: z
    .string()
    .min(32, 'PROXY_SHARED_SECRET must be at least 32 characters')
    .optional(),
  DATABASE_URL: z.string().min(1),

  // Signing key for access tokens. 32+ characters is enforced so nobody ships "secret".
  // Generate one with: openssl rand -base64 48
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
  ACCESS_TOKEN_TTL_MINUTES: z.coerce.number().int().min(1).max(60).default(15),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(7),

  // Self-registration is OFF unless explicitly enabled. New users are always VIEWERs.
  ALLOW_REGISTRATION: z
    .enum(['true', 'false'])
    .default('false')
    .transform((value) => value === 'true'),

  // Swagger UI + openapi.json. On by default except in production, where it must be switched on explicitly.
  ENABLE_DOCS: z.enum(['true', 'false']).optional(),

  // Cookies get the Secure flag (HTTPS only) in production unless overridden.
  COOKIE_SECURE: z.enum(['true', 'false']).optional(),

  // Rate limits (requests per window). Configurable so tests and load tests can change them.
  GLOBAL_RATE_LIMIT: z.coerce.number().int().min(1).default(300),
  LOGIN_RATE_LIMIT: z.coerce.number().int().min(1).default(10), // per IP+email
  ACCOUNT_LOGIN_RATE_LIMIT: z.coerce.number().int().min(1).default(30), // failures per email, all IPs
  INGEST_RATE_LIMIT: z.coerce.number().int().min(1).default(600), // per API key, per minute
  RATE_LIMIT_WINDOW_MINUTES: z.coerce.number().int().min(1).default(15),
});

export type Env = z.infer<typeof envSchema> & { cookieSecure: boolean; docsEnabled: boolean };

// Takes the source as an argument (instead of reading process.env directly) so tests
// can call it with any object.
export function parseEnv(source: NodeJS.ProcessEnv): Env {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    const problems = result.error.issues
      .map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${problems}`);
  }
  const data = result.data;
  const cookieSecure = data.COOKIE_SECURE
    ? data.COOKIE_SECURE === 'true'
    : data.NODE_ENV === 'production';
  const docsEnabled = data.ENABLE_DOCS
    ? data.ENABLE_DOCS === 'true'
    : data.NODE_ENV !== 'production';
  return { ...data, cookieSecure, docsEnabled };
}
