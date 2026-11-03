import { z, type ZodType } from 'zod';
import { API_KEY_SCOPES } from './apiKey.js';
import { loginBody, registerBody } from '../modules/auth/auth.schemas.js';
import { createApiKeyBody } from '../modules/apiKeys/apiKeys.routes.js';
import { updateAlertBody, listAlertsQuery } from '../modules/alerts/alerts.schemas.js';
import { listEventsQuery, statsQuery } from '../modules/events/events.schemas.js';
import { listAuditQuery } from '../modules/audit/audit.routes.js';
import {
  addNoteBody,
  createIncidentBody,
  linkAlertBody,
  listIncidentsQuery,
  updateIncidentBody,
} from '../modules/incidents/incidents.schemas.js';
import { ingestEventsBody, ingestScanBody } from '../modules/ingest/ingest.schemas.js';
import { createRuleBody, updateRuleBody } from '../modules/rules/rules.routes.js';
import { updateUserBody } from '../modules/users/users.routes.js';
import { paginationQuery } from './pagination.js';

// The OpenAPI document is GENERATED from the same zod schemas that validate requests, so the
// documented request shapes cannot drift away from what the API really accepts.
// (Response bodies are described in prose; request schemas are the part clients get wrong.)

type AuthKind = 'public' | 'bearer' | 'apiKey' | 'refreshCookie';
type MinRole = 'VIEWER' | 'ANALYST' | 'ADMIN';

interface Operation {
  method: 'get' | 'post' | 'patch' | 'delete';
  path: string; // OpenAPI style: /events/{id}
  summary: string;
  tag: string;
  auth: AuthKind;
  role?: MinRole; // minimum role for bearer routes
  scope?: string; // required scope for API key routes
  body?: ZodType;
  query?: ZodType;
  success?: number;
  returns?: string;
  rateLimited?: boolean;
}

const op = (o: Operation) => o;

export const operations: Operation[] = [
  op({
    method: 'get',
    path: '/health',
    summary: 'Liveness probe',
    tag: 'Health',
    auth: 'public',
    returns: '{ status, uptimeSeconds }',
  }),
  op({
    method: 'get',
    path: '/ready',
    summary: 'Readiness probe (checks the database)',
    tag: 'Health',
    auth: 'public',
    returns: '{ status }; 503 if the database is down',
  }),

  op({
    method: 'post',
    path: '/auth/register',
    summary: 'Self-register a VIEWER (only when ALLOW_REGISTRATION=true)',
    tag: 'Auth',
    auth: 'public',
    body: registerBody,
    success: 201,
    returns: '{ user }',
  }),
  op({
    method: 'post',
    path: '/auth/login',
    summary: 'Log in; sets the refresh cookie',
    tag: 'Auth',
    auth: 'public',
    body: loginBody,
    rateLimited: true,
    returns: '{ accessToken, user }',
  }),
  op({
    method: 'post',
    path: '/auth/refresh',
    summary: 'Rotate the refresh token and get a new access token',
    tag: 'Auth',
    auth: 'refreshCookie',
    returns: '{ accessToken, user }',
  }),
  op({
    method: 'post',
    path: '/auth/logout',
    summary: 'Revoke the session and clear the cookie',
    tag: 'Auth',
    auth: 'public',
    success: 204,
  }),
  op({
    method: 'get',
    path: '/auth/me',
    summary: 'Current user',
    tag: 'Auth',
    auth: 'bearer',
    role: 'VIEWER',
    returns: '{ user }',
  }),

  op({
    method: 'get',
    path: '/users',
    summary: 'List users',
    tag: 'Users',
    auth: 'bearer',
    role: 'ADMIN',
    query: paginationQuery,
    returns: '{ data: User[], pagination }',
  }),
  op({
    method: 'patch',
    path: '/users/{id}',
    summary: 'Change a user role or active status',
    tag: 'Users',
    auth: 'bearer',
    role: 'ADMIN',
    body: updateUserBody,
    returns: '{ user }',
  }),

  op({
    method: 'get',
    path: '/api-keys',
    summary: 'List API keys (never includes secrets)',
    tag: 'API keys',
    auth: 'bearer',
    role: 'ADMIN',
    returns: '{ data: ApiKey[] }',
  }),
  op({
    method: 'post',
    path: '/api-keys',
    summary: 'Create an API key. The raw key is returned ONCE.',
    tag: 'API keys',
    auth: 'bearer',
    role: 'ADMIN',
    body: createApiKeyBody,
    success: 201,
    returns: '{ apiKey, key }',
  }),
  op({
    method: 'delete',
    path: '/api-keys/{id}',
    summary: 'Revoke an API key',
    tag: 'API keys',
    auth: 'bearer',
    role: 'ADMIN',
    success: 204,
  }),

  op({
    method: 'post',
    path: '/ingest/events',
    summary: 'Ingest a batch of 1-500 security events',
    tag: 'Ingest',
    auth: 'apiKey',
    scope: 'events:write',
    body: ingestEventsBody,
    success: 201,
    rateLimited: true,
    returns: '{ accepted }',
  }),
  op({
    method: 'post',
    path: '/ingest/scans',
    summary: 'Ingest a scan with its findings',
    tag: 'Ingest',
    auth: 'apiKey',
    scope: 'scans:write',
    body: ingestScanBody,
    success: 201,
    rateLimited: true,
    returns: '{ id, summary, criticalEvents }',
  }),

  op({
    method: 'get',
    path: '/events',
    summary: 'Search events (filters + server-side pagination)',
    tag: 'Events',
    auth: 'bearer',
    role: 'VIEWER',
    query: listEventsQuery,
    returns: '{ data: Event[], pagination }',
  }),
  op({
    method: 'get',
    path: '/events/stats',
    summary: 'Event counts per time bucket and severity',
    tag: 'Events',
    auth: 'bearer',
    role: 'VIEWER',
    query: statsQuery,
    returns: '{ from, to, bucket, data: [{ bucket, INFO..CRITICAL, total }] }',
  }),
  op({
    method: 'get',
    path: '/events/{id}',
    summary: 'One event',
    tag: 'Events',
    auth: 'bearer',
    role: 'VIEWER',
    returns: '{ event }',
  }),

  op({
    method: 'get',
    path: '/alert-rules',
    summary: 'List alert rules',
    tag: 'Alert rules',
    auth: 'bearer',
    role: 'VIEWER',
    returns: '{ data: AlertRule[] }',
  }),
  op({
    method: 'post',
    path: '/alert-rules',
    summary: 'Create an alert rule',
    tag: 'Alert rules',
    auth: 'bearer',
    role: 'ADMIN',
    body: createRuleBody,
    success: 201,
    returns: '{ rule }',
  }),
  op({
    method: 'patch',
    path: '/alert-rules/{id}',
    summary: 'Update an alert rule',
    tag: 'Alert rules',
    auth: 'bearer',
    role: 'ADMIN',
    body: updateRuleBody,
    returns: '{ rule }',
  }),
  op({
    method: 'delete',
    path: '/alert-rules/{id}',
    summary: 'Delete a rule that has no alerts (otherwise disable it)',
    tag: 'Alert rules',
    auth: 'bearer',
    role: 'ADMIN',
    success: 204,
  }),

  op({
    method: 'get',
    path: '/alerts',
    summary: 'List alerts',
    tag: 'Alerts',
    auth: 'bearer',
    role: 'VIEWER',
    query: listAlertsQuery,
    returns: '{ data: Alert[], pagination }',
  }),
  op({
    method: 'get',
    path: '/alerts/stream',
    summary: 'Live alert feed (Server-Sent Events: alert.created, alert.updated)',
    tag: 'Alerts',
    auth: 'bearer',
    role: 'VIEWER',
    returns: 'text/event-stream; closes when the access token expires',
  }),
  op({
    method: 'get',
    path: '/alerts/{id}',
    summary: 'Alert with its triggering events',
    tag: 'Alerts',
    auth: 'bearer',
    role: 'VIEWER',
    returns: '{ alert }',
  }),
  op({
    method: 'patch',
    path: '/alerts/{id}',
    summary: 'Acknowledge, resolve or assign an alert',
    tag: 'Alerts',
    auth: 'bearer',
    role: 'ANALYST',
    body: updateAlertBody,
    returns: '{ alert }',
  }),

  op({
    method: 'get',
    path: '/incidents',
    summary: 'List incidents',
    tag: 'Incidents',
    auth: 'bearer',
    role: 'VIEWER',
    query: listIncidentsQuery,
    returns: '{ data: Incident[], pagination }',
  }),
  op({
    method: 'post',
    path: '/incidents',
    summary: 'Open an incident (optionally linking alerts)',
    tag: 'Incidents',
    auth: 'bearer',
    role: 'ANALYST',
    body: createIncidentBody,
    success: 201,
    returns: '{ incident }',
  }),
  op({
    method: 'get',
    path: '/incidents/{id}',
    summary: 'Incident with timeline and alerts',
    tag: 'Incidents',
    auth: 'bearer',
    role: 'VIEWER',
    returns: '{ incident }',
  }),
  op({
    method: 'patch',
    path: '/incidents/{id}',
    summary: 'Update an incident (status changes are added to the timeline)',
    tag: 'Incidents',
    auth: 'bearer',
    role: 'ANALYST',
    body: updateIncidentBody,
    returns: '{ incident }',
  }),
  op({
    method: 'post',
    path: '/incidents/{id}/timeline',
    summary: 'Add a note to the timeline',
    tag: 'Incidents',
    auth: 'bearer',
    role: 'ANALYST',
    body: addNoteBody,
    success: 201,
    returns: '{ entry }',
  }),
  op({
    method: 'post',
    path: '/incidents/{id}/alerts',
    summary: 'Link an alert to the incident',
    tag: 'Incidents',
    auth: 'bearer',
    role: 'ANALYST',
    body: linkAlertBody,
    success: 201,
    returns: '{ incident }',
  }),

  op({
    method: 'get',
    path: '/scans',
    summary: 'List scans',
    tag: 'Scans',
    auth: 'bearer',
    role: 'VIEWER',
    query: paginationQuery,
    returns: '{ data: Scan[], pagination }',
  }),
  op({
    method: 'get',
    path: '/scans/{id}',
    summary: 'Scan with findings',
    tag: 'Scans',
    auth: 'bearer',
    role: 'VIEWER',
    returns: '{ scan }',
  }),
  op({
    method: 'get',
    path: '/export/incidents/{id}',
    summary: 'Incident export for the scanner post-mortem generator',
    tag: 'Export',
    auth: 'apiKey',
    scope: 'incidents:read',
    returns: '{ incident }',
  }),

  op({
    method: 'get',
    path: '/audit-logs',
    summary: 'Audit log',
    tag: 'Audit',
    auth: 'bearer',
    role: 'ADMIN',
    query: listAuditQuery,
    returns: '{ data: AuditEntry[], pagination }',
  }),
];

// zod -> JSON Schema. io:'input' describes what a CLIENT sends (before defaults/transforms).
function toJsonSchema(schema: ZodType): Record<string, unknown> {
  const json = z.toJSONSchema(schema, { io: 'input', unrepresentable: 'any' }) as Record<
    string,
    unknown
  >;
  delete json.$schema; // OpenAPI 3.1 already declares the JSON Schema dialect
  return json;
}

function queryParameters(schema: ZodType) {
  const json = toJsonSchema(schema) as {
    properties?: Record<string, unknown>;
    required?: string[];
  };
  return Object.entries(json.properties ?? {}).map(([name, propSchema]) => ({
    name,
    in: 'query',
    required: json.required?.includes(name) ?? false,
    schema: propSchema,
  }));
}

const errorResponse = (description: string) => ({
  description,
  content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
});

export function createOpenApiDocument() {
  const paths: Record<string, Record<string, unknown>> = {};

  for (const o of operations) {
    const pathParams = [...o.path.matchAll(/\{(\w+)\}/g)].map((m) => ({
      name: m[1],
      in: 'path',
      required: true,
      schema: { type: 'string', format: 'uuid' },
    }));
    const responses: Record<string, unknown> = {
      [String(o.success ?? 200)]: {
        description: o.returns ?? 'Success',
        ...(o.success === 204
          ? {}
          : { content: { 'application/json': { schema: { type: 'object' } } } }),
      },
    };
    if (o.body || o.query || pathParams.length)
      responses['400'] = errorResponse('Validation error (VALIDATION_ERROR)');
    if (o.auth !== 'public') responses['401'] = errorResponse('Missing or invalid credentials');
    if ((o.role && o.role !== 'VIEWER') || o.scope)
      responses['403'] = errorResponse('Not allowed (role or scope too low)');
    if (pathParams.length) responses['404'] = errorResponse('Not found');
    if (o.rateLimited) responses['429'] = errorResponse('Rate limited (RATE_LIMITED)');

    const security =
      o.auth === 'public'
        ? []
        : o.auth === 'bearer'
          ? [{ bearerAuth: [] }]
          : o.auth === 'apiKey'
            ? [{ apiKeyAuth: [] }]
            : [{ refreshCookie: [] }];

    const roleNote = o.role ? ` Requires role ${o.role} or higher.` : '';
    const scopeNote = o.scope ? ` Requires API key scope \`${o.scope}\`.` : '';

    (paths[o.path] ??= {})[o.method] = {
      summary: o.summary,
      description: `${o.summary}.${roleNote}${scopeNote}`.replace('..', '.'),
      tags: [o.tag],
      security,
      parameters: [...pathParams, ...(o.query ? queryParameters(o.query) : [])],
      ...(o.body
        ? {
            requestBody: {
              required: true,
              content: { 'application/json': { schema: toJsonSchema(o.body) } },
            },
          }
        : {}),
      responses,
    };
  }

  return {
    openapi: '3.1.0',
    info: {
      title: 'Sentinel API',
      version: '1.0.0',
      description:
        'Security event ingestion, alert rules and live alerts. Humans authenticate with a short-lived JWT ' +
        '(`Authorization: Bearer`); machines (the scanner) use an API key (`X-API-Key`). ' +
        'Roles are cumulative: ADMIN > ANALYST > VIEWER. All errors share one shape: `{ error: { code, message, details?, requestId } }`.',
    },
    servers: [{ url: '/api/v1' }],
    paths,
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        apiKeyAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'X-API-Key',
          description: `Scopes: ${API_KEY_SCOPES.join(', ')}`,
        },
        refreshCookie: { type: 'apiKey', in: 'cookie', name: 'sentinel_refresh' },
      },
      schemas: {
        Error: {
          type: 'object',
          required: ['error'],
          properties: {
            error: {
              type: 'object',
              required: ['code', 'message', 'requestId'],
              properties: {
                code: { type: 'string', example: 'VALIDATION_ERROR' },
                message: { type: 'string' },
                details: {},
                requestId: { type: 'string' },
              },
            },
          },
        },
      },
    },
  };
}
