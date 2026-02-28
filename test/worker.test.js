import test from 'node:test';
import assert from 'node:assert/strict';

import {
  authenticateSessionWithStytch,
  buildCorsHeaders,
  buildStytchAuthenticateRequest,
  resolveLoginContext,
} from '../src/lib.js';

const baseEnv = {
  ALLOWED_ORIGINS: 'http://localhost:5173,https://flows-alpha.sinhasumit.com',
  DEFAULT_RETURN_TO: 'https://flows-alpha.sinhasumit.com/auth/callback',
  STYTCH_PROJECT_ID: 'project-test-123',
  STYTCH_SECRET: 'secret-test-abc',
  STYTCH_API_BASE: 'https://test.stytch.com',
};

test('return_to validation allows origin in ALLOWED_ORIGINS', () => {
  const result = resolveLoginContext(
    'https://flowz-auth-gateway.sinhasmt16.workers.dev/login?return_to=http%3A%2F%2Flocalhost%3A5173%2Fauth%2Fcallback&app_origin=http%3A%2F%2Flocalhost%3A5173',
    baseEnv,
  );

  assert.equal(result.ok, true);
  assert.equal(result.returnTo, 'http://localhost:5173/auth/callback');
  assert.equal(result.appOrigin, 'http://localhost:5173');
});

test('return_to validation rejects disallowed origin', () => {
  const result = resolveLoginContext(
    'https://flowz-auth-gateway.sinhasmt16.workers.dev/login?return_to=https%3A%2F%2Fevil.example.com%2Fauth%2Fcallback',
    baseEnv,
  );

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.code, 'origin_not_allowed');
});

test('return_to validation allows DEFAULT_RETURN_TO origin even when ALLOWED_ORIGINS empty', () => {
  const result = resolveLoginContext(
    'https://flowz-auth-gateway.sinhasmt16.workers.dev/login?return_to=https%3A%2F%2Fflows-alpha.sinhasumit.com%2Fauth%2Fcallback',
    {
      ...baseEnv,
      ALLOWED_ORIGINS: '',
    },
  );

  assert.equal(result.ok, true);
  assert.equal(result.returnToOrigin, 'https://flows-alpha.sinhasumit.com');
});

test('CORS allows configured origin', () => {
  const headers = buildCorsHeaders('http://localhost:5173', baseEnv);
  assert.ok(headers);
  assert.equal(headers['access-control-allow-origin'], 'http://localhost:5173');
});

test('CORS denies origin not configured', () => {
  const headers = buildCorsHeaders('https://evil.example.com', baseEnv);
  assert.equal(headers, null);
});

test('authenticate request formation uses Stytch sessions/authenticate with basic auth', async () => {
  let capturedUrl = null;
  let capturedInit = null;

  const fetchMock = async (url, init) => {
    capturedUrl = url;
    capturedInit = init;
    return new Response(
      JSON.stringify({
        user_id: 'user-123',
        session_jwt: 'jwt-abc',
        session_token: 'session-xyz',
        expires_at: '2026-03-01T00:00:00Z',
      }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    );
  };

  const payload = await authenticateSessionWithStytch('session-token-input', baseEnv, fetchMock);

  assert.equal(capturedUrl, 'https://test.stytch.com/v1/sessions/authenticate');
  assert.equal(capturedInit.method, 'POST');
  assert.equal(capturedInit.headers['content-type'], 'application/json');
  assert.equal(
    capturedInit.headers.authorization,
    `Basic ${Buffer.from('project-test-123:secret-test-abc').toString('base64')}`,
  );
  assert.deepEqual(JSON.parse(capturedInit.body), { session_token: 'session-token-input' });

  assert.deepEqual(payload, {
    user_id: 'user-123',
    session_jwt: 'jwt-abc',
    session_token: 'session-xyz',
    expires_at: '2026-03-01T00:00:00Z',
  });
});

test('request helper composes expected URL and body', () => {
  const request = buildStytchAuthenticateRequest('token-1', baseEnv);
  assert.equal(request.url, 'https://test.stytch.com/v1/sessions/authenticate');
  assert.deepEqual(JSON.parse(request.init.body), { session_token: 'token-1' });
});
